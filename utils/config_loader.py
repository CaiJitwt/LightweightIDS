from __future__ import annotations

from pathlib import Path
from typing import Any


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return {}

    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("缺少 PyYAML。请先运行：pip install -r requirements.txt") from exc

    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise ValueError(f"配置文件格式错误：{config_path}")
    return data
