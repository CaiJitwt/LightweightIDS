"""Start the local HTTP alert demonstration and open it in a browser."""

from __future__ import annotations

import sys

from demo_http_lab.main import main as lab_main


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--open-browser" not in arguments:
        arguments.insert(0, "--open-browser")
    return lab_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
