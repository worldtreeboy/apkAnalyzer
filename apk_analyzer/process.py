"""Bounded subprocess execution and failure-result helpers."""

import io
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from .safety import is_link_or_reparse_stat, is_valid_package, terminal_safe


MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
_ORIGINAL_SUBPROCESS_RUN = subprocess.run
_PROCESS_STOP_WAIT_SECONDS = 1.0


class RuntimeCheckUnavailable(RuntimeError):
    """Raised when a runtime security check cannot obtain trustworthy data."""

    def __init__(self, message, partial_findings=None):
        super().__init__(message)
        self.partial_findings = list(partial_findings or [])


class CommandOutputLimitExceeded(RuntimeError):
    """Raised when a child writes more output than can be handled safely."""

    def __init__(self, max_output_bytes):
        super().__init__(
            f"command output exceeded {max_output_bytes}-byte safety limit"
        )
        self.max_output_bytes = max_output_bytes


def safe_which(command, path=None, which=shutil.which):
    """Resolve an executable without Windows' implicit current-directory search.

    CPython before 3.12 prepends the current directory while implementing
    ``shutil.which`` on Windows. Scanner tools are commonly launched from the
    directory containing an untrusted APK, so Windows lookup is implemented
    explicitly from absolute, non-CWD PATH entries.
    """
    command = os.fspath(command)
    if os.name != "nt":
        return which(command) if path is None else which(command, path=path)

    directory, _basename = os.path.split(command)
    if directory:
        candidate = os.path.abspath(command)
        return candidate if os.path.isabs(command) and os.path.isfile(candidate) else None

    search_path = os.environ.get("PATH", "") if path is None else path
    extensions = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")
    command_extension = os.path.splitext(command)[1]
    names = [command] if command_extension else [
        command + extension for extension in extensions if extension
    ]
    current = os.path.normcase(os.path.realpath(os.getcwd()))
    for raw_directory in str(search_path or "").split(";"):
        raw_directory = raw_directory.strip().strip('"')
        if not raw_directory or not os.path.isabs(raw_directory):
            continue
        resolved_directory = os.path.abspath(raw_directory)
        if os.path.normcase(os.path.realpath(resolved_directory)) == current:
            continue
        for name in names:
            candidate = os.path.join(resolved_directory, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def _system_taskkill_path():
    """Return the trusted Windows taskkill path, never a PATH lookup result."""
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if not root or not os.path.isabs(root):
        return None
    candidate = os.path.abspath(os.path.join(root, "System32", "taskkill.exe"))
    try:
        candidate_stat = os.lstat(candidate)
    except OSError:
        return None
    if is_link_or_reparse_stat(candidate_stat) or not os.path.isfile(candidate):
        return None
    return candidate


def _captured_size(capture, returned, max_output_bytes):
    """Measure one output stream before allocating its decoded representation."""
    if returned is not None:
        if isinstance(returned, bytes):
            return len(returned)
        text = str(returned)
        if len(text) > max_output_bytes:
            return max_output_bytes + 1
        return len(text.encode("utf-8", errors="replace"))
    capture.flush()
    capture.seek(0, 2)
    return capture.tell()


def _read_captured(capture, returned):
    """Decode output from a real capture or a legacy subprocess mock."""
    if returned is not None:
        if isinstance(returned, bytes):
            return returned.decode("utf-8", errors="replace")
        return str(returned)
    capture.seek(0)
    return capture.read().decode("utf-8", errors="replace")


def _popen_process_tree_kwargs():
    """Return platform flags that put a child in its own process tree."""
    if os.name == "nt":
        return {
            "creationflags": getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200
            )
        }
    return {"start_new_session": True}


def _windows_kill_process_tree(process):
    """Terminate a Windows process and its descendants without a shell."""
    # Windows has no stdlib equivalent of killpg. taskkill is an OS component
    # and /T resolves the child tree while the direct process is still alive.
    # Invoke the saved function so a test monkeypatch of subprocess.run cannot
    # accidentally disable production cleanup.
    taskkill = _system_taskkill_path()
    if not taskkill:
        try:
            process.kill()
        except OSError:
            pass
        return
    try:
        with open(os.devnull, "wb") as devnull:
            _ORIGINAL_SUBPROCESS_RUN(
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=devnull,
                stderr=devnull,
                timeout=5,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
    except (OSError, subprocess.SubprocessError, ValueError):
        # A minimal Windows installation may not expose taskkill, or the
        # direct process may have disappeared between wait and cleanup.
        try:
            process.kill()
        except OSError:
            pass


def _terminate_process_tree(process):
    """Force-stop a contained process tree and reap its direct process."""
    if os.name == "nt":
        _windows_kill_process_tree(process)
    else:
        try:
            # start_new_session=True makes the child's PID its process-group
            # ID. SIGKILL prevents a timed-out tool from ignoring cleanup.
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=_PROCESS_STOP_WAIT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=_PROCESS_STOP_WAIT_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _cleanup_completed_process_tree(process):
    """Stop background descendants left behind after their parent exits."""
    if os.name == "nt":
        # taskkill cannot reliably discover a tree after its root exits. A
        # timed-out process is cleaned while alive; successful tools are not
        # expected to daemonize on Windows, so there is nothing safe to target
        # here without a native Job Object dependency.
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def _drain_stream(stream, retained, state, lock, limit_event,
                  max_output_bytes):
    """Drain one pipe while retaining at most the shared byte limit."""
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            with lock:
                remaining = max_output_bytes - state["bytes"]
                if remaining > 0:
                    retained.extend(chunk[:remaining])
                state["bytes"] += len(chunk)
                if state["bytes"] > max_output_bytes:
                    limit_event.set()
    except (OSError, ValueError) as exc:
        with lock:
            state["errors"].append(exc)
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _run_contained_capture(args, timeout, stdin, max_output_bytes):
    """Run a real process with tree containment and bounded pipe capture."""
    command = list(args)
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL if stdin is None else stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        **_popen_process_tree_kwargs(),
    )
    stdout_bytes = bytearray()
    stderr_bytes = bytearray()
    state = {"bytes": 0, "errors": []}
    lock = threading.Lock()
    limit_event = threading.Event()
    readers = [
        threading.Thread(
            target=_drain_stream,
            args=(stream, retained, state, lock, limit_event,
                  max_output_bytes),
            daemon=True,
        )
        for stream, retained in (
            (process.stdout, stdout_bytes),
            (process.stderr, stderr_bytes),
        )
    ]
    started_readers = []
    try:
        for reader in readers:
            reader.start()
            started_readers.append(reader)
    except BaseException:
        _terminate_process_tree(process)
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        for reader in started_readers:
            reader.join(timeout=_PROCESS_STOP_WAIT_SECONDS)
        raise

    deadline = None if timeout is None else time.monotonic() + timeout
    timed_out = False
    try:
        while True:
            if limit_event.is_set():
                _terminate_process_tree(process)
                break
            remaining = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    _terminate_process_tree(process)
                    break
            try:
                process.wait(
                    timeout=(0.05 if remaining is None
                             else min(0.05, remaining))
                )
                # A tool can return while a child keeps the capture pipes
                # open. Stop such descendants before joining the readers.
                _cleanup_completed_process_tree(process)
                break
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        _terminate_process_tree(process)
        raise
    finally:
        for reader, stream in zip(
                readers, (process.stdout, process.stderr)):
            reader.join(timeout=_PROCESS_STOP_WAIT_SECONDS)
            if reader.is_alive():
                # This should only be reachable for a broken OS pipe after
                # forced termination. Closing our endpoint prevents a daemon
                # reader from retaining it indefinitely.
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
                reader.join(timeout=_PROCESS_STOP_WAIT_SECONDS)

    with lock:
        captured_stdout = bytes(stdout_bytes)
        captured_stderr = bytes(stderr_bytes)
        reader_errors = list(state["errors"])

    if timed_out:
        raise subprocess.TimeoutExpired(command, timeout)
    if limit_event.is_set():
        raise CommandOutputLimitExceeded(max_output_bytes)
    if reader_errors:
        raise OSError(f"could not capture command output: {reader_errors[0]}")
    return subprocess.CompletedProcess(
        command, process.returncode,
        captured_stdout.decode("utf-8", errors="replace"),
        captured_stderr.decode("utf-8", errors="replace"),
    )


def _run_legacy_capture(args, timeout, stdin, max_output_bytes, runner):
    """Preserve the historical subprocess.run injection seam for callers."""
    with tempfile.TemporaryFile(mode="w+b") as stdout_capture, \
            tempfile.TemporaryFile(mode="w+b") as stderr_capture:
        result = runner(
            args,
            stdin=subprocess.DEVNULL if stdin is None else stdin,
            stdout=stdout_capture,
            stderr=stderr_capture,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        returned_stdout = getattr(result, "stdout", None)
        returned_stderr = getattr(result, "stderr", None)
        stdout_size = _captured_size(
            stdout_capture, returned_stdout, max_output_bytes
        )
        stderr_size = _captured_size(
            stderr_capture, returned_stderr, max_output_bytes
        )
        if (stdout_size > max_output_bytes
                or stderr_size > max_output_bytes
                or stdout_size + stderr_size > max_output_bytes):
            raise CommandOutputLimitExceeded(max_output_bytes)
        stdout_text = _read_captured(stdout_capture, returned_stdout)
        stderr_text = _read_captured(stderr_capture, returned_stderr)

    return subprocess.CompletedProcess(
        getattr(result, "args", args), result.returncode,
        stdout_text, stderr_text,
    )


def run_command_capture(args, timeout=30, stdin=None,
                        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES):
    """Return a tree-contained, bounded ``CompletedProcess`` with decoded output.

    stdout and stderr are drained concurrently, but only a combined bounded
    prefix is retained. Exceeding the limit terminates the whole tool process
    tree before either stream is decoded into memory.

    ``TimeoutExpired``, process-launch errors, invalid limits, and
    :class:`CommandOutputLimitExceeded` are intentionally left to the caller.
    This makes the helper usable by tool integrations that need the actual
    exit status and separate stderr while :func:`run_command` retains its
    legacy string-sentinel interface.
    """
    if (not isinstance(max_output_bytes, int)
            or isinstance(max_output_bytes, bool)
            or max_output_bytes <= 0):
        raise ValueError("invalid command output safety limit")

    # Keep compatibility with existing integrations that monkeypatch the old
    # subprocess.run seam. Real executions use Popen so we retain the process
    # handle needed to terminate descendants safely.
    if subprocess.run is not _ORIGINAL_SUBPROCESS_RUN:
        return _run_legacy_capture(
            args, timeout, stdin, max_output_bytes, subprocess.run
        )
    return _run_contained_capture(
        args, timeout, stdin, max_output_bytes
    )


def run_command(args, timeout=30, stdin=None, sanitizer=terminal_safe,
                max_output_bytes=MAX_COMMAND_OUTPUT_BYTES):
    """Run an argument-list command and return output or an error sentinel."""
    try:
        result = run_command_capture(
            args, timeout=timeout, stdin=stdin,
            max_output_bytes=max_output_bytes,
        )
        stdout = sanitizer(result.stdout).strip()
        stderr = sanitizer(result.stderr).strip()
        if result.returncode != 0:
            detail = stderr or stdout or "no diagnostic output"
            return f"[ERROR {result.returncode}] {detail}"
        return stdout
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except CommandOutputLimitExceeded as exc:
        return f"[ERROR] {exc}"
    except (OSError, ValueError) as exc:
        return f"[ERROR] {exc}"


def is_error_output(out):
    """Return whether output is empty or a command failure sentinel."""
    return not out or out == "[TIMEOUT]" or out.startswith("[ERROR")


def command_failed(out):
    """Return whether output is one of :func:`run_command`'s sentinels."""
    return isinstance(out, str) and (
        out == "[TIMEOUT]" or out.startswith("[ERROR")
    )


def require_runtime_command(
        out, operation, require_output=False, partial_findings=None,
        failure_predicate=command_failed,
        unavailable_error=RuntimeCheckUnavailable):
    """Validate command output or raise an explicit inconclusive-check error."""
    if failure_predicate(out) or (require_output and not str(out or "").strip()):
        detail = str(out or "no output").strip()
        raise unavailable_error(
            f"{operation}: {detail}", partial_findings=partial_findings
        )
    return out


def parse_android_ps(output, package, max_lines=8192, max_pids=32):
    """Parse a bounded Android ``ps`` table for one app's process family.

    The return value distinguishes an empty, valid table from an unsupported
    output layout. Only the exact package process and ``package:secondary``
    names are accepted; substring matches could attribute another app's logs.
    """
    result = {"recognized": False, "pids": [], "truncated": False}
    if not is_valid_package(package) or not isinstance(output, str):
        return result

    lines = []
    for index, line in enumerate(io.StringIO(output)):
        if index >= max_lines:
            result["truncated"] = True
            break
        lines.append(line.rstrip("\r\n"))

    header_index = None
    pid_index = None
    name_index = None
    for index, line in enumerate(lines[:20]):
        columns = line.split()
        upper = [column.upper() for column in columns]
        if "PID" not in upper:
            continue
        candidates = [
            pos for pos, column in enumerate(upper)
            if column in ("NAME", "CMD", "COMMAND", "ARGS")
        ]
        if not candidates:
            continue
        header_index = index
        pid_index = upper.index("PID")
        name_index = candidates[-1]
        result["recognized"] = True
        break

    if header_index is None:
        return result

    seen = set()
    for line in lines[header_index + 1:]:
        fields = line.split()
        if max(pid_index, name_index) >= len(fields):
            continue
        pid = fields[pid_index]
        name = fields[name_index]
        if (not pid.isascii() or not pid.isdigit() or len(pid) > 10):
            continue
        number = int(pid)
        if number <= 0 or number > 0x7FFFFFFF:
            continue
        if name != package and not name.startswith(package + ":"):
            continue
        if pid in seen:
            continue
        seen.add(pid)
        if len(result["pids"]) >= max_pids:
            result["truncated"] = True
            break
        result["pids"].append(pid)
    return result
