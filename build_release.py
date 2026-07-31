#!/usr/bin/env python3
"""Build the runnable APK Analyzer release JAR with only JDK + stdlib tools."""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def find_javac():
    configured = os.environ.get("JAVAC", "").strip()
    if configured:
        return configured
    return shutil.which("javac")


def project_version():
    source = (ROOT / "apkAnalyzer.py").read_text(encoding="utf-8")
    match = re.search(r'^TOOL_VERSION\s*=\s*"([^"]+)"', source, re.MULTILINE)
    if not match:
        raise RuntimeError("Could not read TOOL_VERSION from apkAnalyzer.py")
    return match.group(1)


def add_file(archive, source, archive_name):
    info = zipfile.ZipInfo(archive_name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, Path(source).read_bytes())


def add_bytes(archive, data, archive_name):
    info = zipfile.ZipInfo(archive_name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def build(output):
    javac = find_javac()
    if not javac:
        raise RuntimeError("javac was not found; install JDK 8 or newer")

    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="apkanalyzer-jar-") as tmp:
        classes = Path(tmp, "classes")
        classes.mkdir()
        command = [
            javac,
            "--release", "8",
            "-encoding", "UTF-8",
            "-d", str(classes),
            str(ROOT / "launcher" / "ApkAnalyzerLauncher.java"),
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"javac failed:\n{result.stderr.strip()}")

        with zipfile.ZipFile(output, "w") as archive:
            add_bytes(
                archive,
                b"Manifest-Version: 1.0\r\nMain-Class: ApkAnalyzerLauncher\r\n\r\n",
                "META-INF/MANIFEST.MF",
            )
            add_file(archive, classes / "ApkAnalyzerLauncher.class", "ApkAnalyzerLauncher.class")
            add_file(archive, ROOT / "apkAnalyzer.py", "apkAnalyzer.py")
            add_file(
                archive,
                ROOT / "frida_scripts" / "universal_bypass.js",
                "frida_scripts/universal_bypass.js",
            )
            add_file(archive, ROOT / "LICENSE", "LICENSE")

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    checksum = output.with_name(output.name + ".sha256")
    checksum.write_text(f"{digest}  {output.name}\n", encoding="ascii")
    return output, checksum, digest


def main():
    version = project_version()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(ROOT / "dist" / f"apkAnalyzer-{version}.jar"),
        help="Output JAR path",
    )
    args = parser.parse_args()
    output, checksum, digest = build(args.output)
    print(f"Built {output}")
    print(f"SHA-256 {digest}")
    print(f"Checksum {checksum}")


if __name__ == "__main__":
    main()
