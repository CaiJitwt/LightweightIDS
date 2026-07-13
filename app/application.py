from __future__ import annotations

from pathlib import Path
import sys

from app.constants import APP_NAME, CONFIG_PATH, DEFAULT_DATABASE_PATH
from storage.database import Database
from utils.config_loader import load_config
from utils.logger import configure_logging, get_logger

logger = get_logger(__name__)


def run(argv: list[str]) -> int:
    config = load_config(CONFIG_PATH)
    configure_logging(config)

    database_path = Path(config.get("database", {}).get("path", DEFAULT_DATABASE_PATH))
    database = Database(database_path)
    database.initialize()
    logger.info("Database initialized at %s", database.path)

    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        print("PySide6 is missing. The current Python interpreter is:")
        print(f"  {sys.executable}")
        print()
        print("Start the app with the project environment, for example:")
        print(r"  D:\Miniconda\envs\Lightweight-IDS\python.exe main.py")
        print()
        print("To use the current interpreter, install the project dependencies first:")
        print("  python -m pip install -r requirements.txt")
        raise SystemExit(1) from exc

    from ui.main_window import MainWindow
    from ui.styles import GLOBAL_APP_STYLE

    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(GLOBAL_APP_STYLE)

    window = MainWindow(database=database, config=config)
    window.show()

    return app.exec()
