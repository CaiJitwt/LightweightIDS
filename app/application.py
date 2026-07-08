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
        print("缺少 PySide6，当前启动程序使用的 Python 解释器是：")
        print(f"  {sys.executable}")
        print()
        print("请使用已安装依赖的 conda 环境启动，例如：")
        print(r"  D:\Miniconda\envs\Lightweight-IDS\python.exe main.py")
        print()
        print("如果要用当前解释器启动，则需要先在当前解释器中安装依赖：")
        print("  python -m pip install -r requirements.txt")
        raise SystemExit(1) from exc

    from ui.main_window import MainWindow

    app = QApplication(argv)
    app.setApplicationName(APP_NAME)

    window = MainWindow(database=database, config=config)
    window.show()

    return app.exec()
