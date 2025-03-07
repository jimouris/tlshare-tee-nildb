"""Test configuration and fixtures."""

from pathlib import Path
from typing import Generator
import pytest

from src.key_management import KeyManager

@pytest.fixture
def test_keys_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary directory for test keys."""
    keys_dir = tmp_path / "test_keys"
    keys_dir.mkdir()
    yield keys_dir
    # Cleanup after tests
    for file in keys_dir.glob("*"):
        file.unlink()
    keys_dir.rmdir()

@pytest.fixture
def test_config(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary config file."""
    config_path = tmp_path / "test_config.json"
    config = {
        "remote_server_url": "http://localhost:8000/public-key"
    }
    with open(config_path, "w", encoding="utf-8") as f:
        import json
        json.dump(config, f)
    yield config_path
    # Cleanup after tests
    config_path.unlink()

@pytest.fixture
def key_manager(test_keys_dir: Path, test_config: Path) -> Generator[KeyManager, None, None]:
    """Create a KeyManager instance for testing."""
    manager = KeyManager(key_dir=str(test_keys_dir), config_path=str(test_config))
    yield manager
    # Cleanup after tests
    if manager.public_key_path.exists():
        manager.public_key_path.unlink()
    if manager.private_key_path.exists():
        manager.private_key_path.unlink()

@pytest.fixture
def sample_message() -> str:
    """Create a sample message for testing."""
    return "This is a test message that contains sensitive data. This is a test message that contains sensitive data. "

@pytest.fixture
def sample_sensitive_indices() -> list[int]:
    """Create sample sensitive block indices for testing."""
    return [1, 3]  # Use valid block indices
