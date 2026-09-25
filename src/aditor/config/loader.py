"""Configuration loader for ADitor."""

import json
import os
from pathlib import Path
from typing import Optional

from .models import Config


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from a JSON file.

    Args:
        config_path: Path to the configuration file. If None, uses the
            ``AD_MCP_CONFIG`` environment variable.

    ``${VAR}`` / ``$VAR`` references are expanded from the environment first,
    which is how the bind password stays out of the file.

    Raises:
        FileNotFoundError: the file doesn't exist.
        ValueError: no path was given, or the config is invalid.
        json.JSONDecodeError: the file is not valid JSON.
    """
    config_path = config_path or os.getenv("AD_MCP_CONFIG")
    if not config_path:
        raise ValueError(
            "No configuration file specified. Either provide config_path or "
            "set AD_MCP_CONFIG environment variable.")

    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    raw = os.path.expandvars(config_file.read_text(encoding="utf-8"))
    try:
        return Config.from_dict(json.loads(raw))
    except TypeError as exc:  # a missing required field
        raise ValueError(f"invalid configuration: {exc}") from exc
