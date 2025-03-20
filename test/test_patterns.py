"""Tests for pattern validation and configuration."""

import pytest
from pydantic import ValidationError

from src.server.server import JsonPattern


def test_json_pattern_validation():
    """Test JSON pattern validation."""
    # Valid pattern
    pattern = JsonPattern(
        pattern_type="json",
        path="$.value",
        data_type="number",
        should_extract=True,
        include_children=True,
        preserve_keys=False,
    )
    assert pattern.pattern_type == "json"
    assert pattern.path == "$.value"
    assert pattern.data_type == "number"
    assert pattern.should_extract is True
    assert pattern.include_children is True
    assert pattern.preserve_keys is False

    # Invalid pattern type
    with pytest.raises(ValidationError):
        JsonPattern(pattern_type="invalid", path="$.value")

    # Missing required field (path)
    with pytest.raises(ValidationError):
        JsonPattern(pattern_type="json")


def test_json_pattern_defaults():
    """Test JSON pattern default values."""
    pattern = JsonPattern(pattern_type="json", path="$.value")
    assert pattern.data_type == "number"  # Default data type
    assert pattern.should_extract is False  # Default should_extract
    assert pattern.include_children is False  # Default include_children
    assert pattern.preserve_keys is True  # Default preserve_keys


def test_json_pattern_data_types():
    """Test JSON pattern data type validation."""
    # String data type
    pattern = JsonPattern(pattern_type="json", path="$.value", data_type="string")
    assert pattern.data_type == "string"

    # Number data type
    pattern = JsonPattern(pattern_type="json", path="$.value", data_type="number")
    assert pattern.data_type == "number"
