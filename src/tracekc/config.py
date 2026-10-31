"""Configuration loading with dotted-key CLI overrides."""
from __future__ import annotations

from pathlib import Path
import os

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "config.yaml"


def load_env(path: Path | None = None) -> None:
    """Load a local .env without overwriting environment variables or executing shell code."""
    path = path or PROJECT_ROOT / ".env"
    if path.exists():
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.removeprefix("export ").partition("=")
            key = key.strip()
            if sep and key.replace("_", "").isalnum():
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                os.environ.setdefault(key, value)


def load_config(path: str | Path | None = None, overrides: list[str] | tuple = ()) -> dict:
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8-sig"))
    for item in overrides:
        key, sep, raw = item.partition("=")
        if not sep:
            raise ValueError(f"override must look like key.sub=value, got {item!r}")
        node = cfg
        parts = key.strip().split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = yaml.safe_load(raw)
    # relative paths in the config resolve against the project root (parent of configs/)
    cfg["_root"] = str(cfg_path.resolve().parent.parent)
    return cfg


def project_path(cfg: dict, rel: str | Path) -> Path:
    p = Path(rel)
    return p if p.is_absolute() else Path(cfg["_root"]) / p
