from __future__ import annotations

from pathlib import Path

APP_NAME = "Lightweight IDS"
APP_VERSION = "0.1.0"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "default_config.yaml"
RULES_CONFIG_PATH = PROJECT_ROOT / "config" / "rules.yaml"
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "lightweight_ids.db"
DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "lightweight_ids.log"

PAGE_TITLES = {
    "dashboard": "仪表盘",
    "packets": "流量监控",
    "alerts": "告警中心",
    "rules": "规则管理",
    "reports": "报告导出",
    "settings": "系统设置",
}
