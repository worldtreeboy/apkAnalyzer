"""Terminal presentation helpers used by the interactive application."""

import os
import sys


class C:
    """ANSI color and style escape sequences."""

    RST = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"
    BG_MAG = "\033[45m"
    BG_CYAN = "\033[46m"


def configure_windows_streams():
    """Prevent Unicode UI output from crashing under restrictive locales."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def clear():
    """Clear an interactive terminal without polluting redirected output."""
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="", flush=True)


def banner():
    """Print the application banner."""
    value = f"""
{C.CYAN}{C.BOLD}
   ╔══════════════════════════════════════════════════════════╗
   ║   █████╗ ██████╗ ██╗  ██╗                                ║
   ║  ██╔══██╗██╔══██╗██║ ██╔╝                                ║
   ║  ███████║██████╔╝█████╔╝                                 ║
   ║  ██╔══██║██╔═══╝ ██╔═██╗                                 ║
   ║  ██║  ██║██║     ██║  ██╗                                ║
   ║  ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝                                ║
   ║                     {C.MAGENTA}A N A L Y Z E R{C.CYAN}                      ║
   ║              {C.DIM}{C.WHITE}Android Security Analysis Tool{C.RST}{C.CYAN}{C.BOLD}              ║
   ║           {C.DIM}{C.WHITE}github.com/worldtreeboy/apkAnalyzer{C.RST}{C.CYAN}{C.BOLD}            ║
   ╚══════════════════════════════════════════════════════════╝{C.RST}
"""
    print(value)


def section(title):
    """Print a section heading."""
    width = 56
    pad = width - len(title) - 4
    print(f"\n  {C.CYAN}╔{'═' * width}╗{C.RST}")
    print(
        f"  {C.CYAN}║  {C.BOLD}{C.WHITE}{title}{C.RST}{C.CYAN}"
        f"{' ' * pad}║{C.RST}"
    )
    print(f"  {C.CYAN}╚{'═' * width}╝{C.RST}")


def status_line(label, value, color=None):
    """Print a labeled status value."""
    color = color or C.WHITE
    print(
        f"  {C.DIM}│{C.RST} {C.YELLOW}{label:<20}{C.RST} "
        f"{color}{value}{C.RST}"
    )


def pass_fail(label, passed, detail=""):
    """Print a pass/fail result."""
    if passed:
        tag = f"{C.GREEN}[PASS]{C.RST}"
    else:
        tag = f"{C.RED}[FAIL]{C.RST}"
    extra = f" {C.DIM}— {detail}{C.RST}" if detail else ""
    print(f"  {tag} {label}{extra}")


def warn_line(label, detail=""):
    """Print a warning result."""
    extra = f" {C.DIM}— {detail}{C.RST}" if detail else ""
    print(f"  {C.YELLOW}[WARN]{C.RST} {label}{extra}")


def info_line(label, detail=""):
    """Print an informational result."""
    extra = f" {C.DIM}— {detail}{C.RST}" if detail else ""
    print(f"  {C.BLUE}[INFO]{C.RST} {label}{extra}")


def pause():
    """Wait for interactive acknowledgement, tolerating closed input."""
    try:
        input(f"\n  {C.DIM}Press Enter to continue...{C.RST}")
    except (EOFError, KeyboardInterrupt):
        print()
