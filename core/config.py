# core/config.py
"""Configuration settings for the Secure Code Analyzer."""
import json
from pathlib import Path
from typing import Dict, Any

class Config:
    """Configuration class for the Secure Code Analyzer."""
    
    DEFAULT_CONFIG = {
        'output_dir': 'output',
        'report_format': 'json',
        'severity_levels': ['low', 'medium', 'high', 'critical'],
        'exclude_dirs': ['node_modules', '.git', 'venv', '__pycache__'],
        'max_file_size': 1048576  # 1MB
    }
    
    def __init__(self, config_path: str = None):
        self.config = self.DEFAULT_CONFIG.copy()
        if config_path:
            self.load_config(config_path)
    
    def load_config(self, config_path: str) -> None:
        """Load configuration from a JSON file."""
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                self.config.update(user_config)
        except FileNotFoundError:
            print(f"Config file not found at {config_path}, using defaults")
        except json.JSONDecodeError:
            print(f"Invalid JSON in config file at {config_path}, using defaults")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config.get(key, default)
    
    def save_default_config(self, path: str = 'config.json') -> None:
        """Save the default configuration to a file."""
        with open(path, 'w') as f:
            json.dump(self.DEFAULT_CONFIG, f, indent=2)
