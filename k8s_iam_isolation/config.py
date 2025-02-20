import yaml
import os
from pathlib import Path
from typing import Any


CONFIG_DIR = Path.home() / ".config" / "k8s_iam_isolation"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
DEFAULTS = {
    "log_level": "INFO",
    "log_file": "/var/logs/k8s_iam_isolation/loaudit.log"
}

def get_config(config_path: Path = CONFIG_FILE):
    """Load configuration from config.yaml or return defaults."""
    if os.path.exists(config_path):
        with open(config_path, "r") as file:
            config = yaml.safe_load(file) or {}
            DEFAULTS.update(config)  # Merge with defaults
    return DEFAULTS

def save_config(config: dict[str, Any]):
    """Save configuration on the specified path."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, 'w') as file:
        yaml.dump(config, file)