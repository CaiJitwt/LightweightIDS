from __future__ import annotations

import sys
from collections.abc import Callable


HELP_TEXT = """Lightweight IDS launcher

Usage:
  python main.py                 Start the classic PySide6 desktop
  python main.py desktop [args]  Start the classic PySide6 desktop
  python main.py modern [args]   Start the modern browser frontend and local API
  python main.py demo [args]     Start the local HTTP alert demonstration
  python main.py cli [args]      Run the command-line interface

The modern_main.py and demo_http.py shortcuts remain available.
Use `python main.py <command> --help` for command-specific options.
"""


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        return _run_desktop([])

    command = arguments[0].lower()
    command_arguments = arguments[1:]
    runners: dict[str, Callable[[list[str]], int]] = {
        "desktop": _run_desktop,
        "modern": _run_modern,
        "web": _run_modern,
        "demo": _run_demo,
        "cli": _run_cli,
    }
    if command in runners:
        return runners[command](command_arguments)
    if command in {"-h", "--help"}:
        print(HELP_TEXT)
        return 0

    # Preserve the previous `python main.py --cli ...` invocation.
    if "--cli" in arguments:
        return _run_cli([argument for argument in arguments if argument != "--cli"])

    # Unknown leading options may be Qt arguments used by the classic desktop.
    return _run_desktop(arguments)


def _run_desktop(arguments: list[str]) -> int:
    from app.application import run

    return run([sys.argv[0], *arguments])


def _run_modern(arguments: list[str]) -> int:
    from modern_main import main as run_modern

    return run_modern(arguments)


def _run_demo(arguments: list[str]) -> int:
    from demo_http import main as run_demo

    return run_demo(arguments)


def _run_cli(arguments: list[str]) -> int:
    from app.cli import run_cli

    return run_cli(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
