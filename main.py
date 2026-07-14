from __future__ import annotations

import sys


if __name__ == "__main__":
    if "--cli" in sys.argv:
        from app.cli import run_cli
        cli_args = [a for a in sys.argv[1:] if a != "--cli"]
        raise SystemExit(run_cli(cli_args))
    from app.application import run
    raise SystemExit(run(sys.argv))
