"""Configuration management for the TEE server."""

from pathlib import Path
from typing import Dict, Any, Optional
import json

from src.config.logging import logger

class Config:
    """Configuration class for managing server settings."""

    def __init__(self, config_path: str = "src/config/config.json"):
        """Initialize the configuration.

        Args:
            config_path: Path to the configuration file
        """
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self._remote_server_url: Optional[str] = None
        self._load_config()

    def _load_config(self):
        """Load configuration from file"""
        try:
            if not self.config_path.exists():
                logger.error("Config file not found at %s", self.config_path)
                raise FileNotFoundError(f"Config file not found at {self.config_path}")

            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            self._remote_server_url = self.config.get('remote_server_url')
            logger.info("Configuration loaded from %s", self.config_path)
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON in config file: %s", str(exc))
            raise
        except Exception as exc:
            logger.error("Error loading config: %s", str(exc))
            raise

    @property
    def remote_server(self) -> Dict[str, Any]:
        """Get remote server configuration"""
        if 'remote_server' not in self.config:
            logger.error("Remote server configuration not found")
            raise KeyError("Remote server configuration not found")
        return self.config['remote_server']

    @property
    def remote_server_url(self) -> str:
        """Get the full URL for the remote server"""
        if self._remote_server_url is None:
            logger.error("Remote server URL not set")
            raise ValueError("Remote server URL not set")
        return self._remote_server_url

    @remote_server_url.setter
    def remote_server_url(self, value: str) -> None:
        """Set the remote server URL.

        Args:
            value: The new remote server URL
        """
        self._remote_server_url = value

    def create_default_config(self) -> None:
        """Create a default configuration file."""
        default_config = {
            "remote_server_url": "http://localhost:8000/public-key"
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=4)
        logger.info("Default configuration created at %s", self.config_path)
        self._remote_server_url = default_config["remote_server_url"]

    def save_config(self) -> None:
        """Save current configuration to file."""
        config_data = {
            "remote_server_url": self._remote_server_url
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=4)
        logger.info("Configuration saved to %s", self.config_path)
