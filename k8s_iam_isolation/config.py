import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("k8s_isolation")


CONFIG_DIR = Path.home() / ".config" / "k8s_iam_isolation"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
DEFAULT_LOG_CONFIG = Path(__file__).parent / "custom_logging" / "config.json"
DEFAULTS = {
    "log_config": str(DEFAULT_LOG_CONFIG),
}


def get_config(config_path: Path = CONFIG_FILE):
    """Load configuration from config.yaml or return defaults."""
    if os.path.exists(config_path):
        with open(config_path) as file:
            config = yaml.safe_load(file) or {}
            DEFAULTS.update(config)  # Merge with defaults
    return DEFAULTS


def save_config(config: dict[str, Any]):
    """Save configuration on the specified path."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    config = validate_config(config)
    with open(CONFIG_FILE, "w") as file:
        yaml.dump(config, file)


def validate_config(config: dict) -> dict:
    """Validate and sanitize configuration."""
    required_keys = ["log_config"]

    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

    # Validate log config path exists
    log_config_path = Path(config["log_config"])
    if not log_config_path.exists():
        logger.warning(f"Log config file not found: {log_config_path}")
        config["log_config"] = str(DEFAULT_LOG_CONFIG)

    return config
