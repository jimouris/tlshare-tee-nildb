"""Test configuration and fixtures."""

from pathlib import Path
from typing import Generator

import pytest

from src.config.key_management import KeyManager


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
def key_manager(test_keys_dir: Path) -> Generator[KeyManager, None, None]:
    """Create a KeyManager instance for testing."""
    manager = KeyManager(key_dir=str(test_keys_dir))
    yield manager
    # Cleanup after tests
    if manager.public_key_path.exists():
        manager.public_key_path.unlink()
    if manager.private_key_path.exists():
        manager.private_key_path.unlink()


@pytest.fixture
def sample_message() -> str:
    """Create a sample message for testing."""
    return "This is a test message that contains sensitive data. 100 is a test message that contains sensitive data. "


@pytest.fixture
def sample_blocks_to_redact() -> list[int]:
    """Create sample sensitive block indices for testing."""
    return [1, 3]


@pytest.fixture
def sample_blocks_to_extract() -> list[int]:
    """Create sample extract block indices for testing."""
    return [3]  # Default to extracting data from block 1
