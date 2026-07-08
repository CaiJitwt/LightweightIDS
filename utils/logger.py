from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.constants import DEFAULT_LOG_PATH


def configure_logging(config: dict[str, Any] | None = None) -> None:
    config = config or {}
    logging_config = config.get("logging", {})
    level_name = str(logging_config.get("level", "INFO")).upper()
    log_file = Path(logging_config.get("file", DEFAULT_LOG_PATH))
    if not log_file.is_absolute():
        log_file = Path.cwd() / log_file
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=getattr(logging, level_name, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
