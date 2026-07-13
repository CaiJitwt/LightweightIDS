from __future__ import annotations

from pathlib import Path

APP_NAME = "Lightweight IDS"
APP_VERSION = "0.1.0"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "default_config.yaml"
RULES_CONFIG_PATH = PROJECT_ROOT / "config" / "rules.yaml"
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "lightweight_ids.db"
DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "lightweight_ids.log"

PAGE_TITLES: dict[str, str] = {
    "dashboard": "Dashboard",
    "packets": "Traffic Monitor",
    "hosts": "Host Explorer",
    "alerts": "Alert Center",
    "investigations": "Investigations",
    "assets": "Assets",
    "rules": "Rule Management",
    "reports": "Reports",
    "settings": "Settings",
    "personalization": "Personalization",
}


def get_page_title(key: str) -> str:
    """Return the translated page title for *key* using the current locale."""
    from ui.i18n import tr
    return tr(f"nav.{key}")
