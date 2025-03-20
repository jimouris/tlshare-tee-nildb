"""Tests for message processing functionality."""

import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from src.config.key_management import KeyManager
from src.server.server import JsonPattern, redact_message


def test_json_redaction():
    """Test redacting JSON data."""
    message = """
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "sensitive": "secret",
        "public": "hello",
        "nested": {
            "secret": "hidden",
            "visible": "shown"
        }
    }
    """

    patterns = [
        JsonPattern(pattern_type="json", path="$.sensitive", data_type="string"),
        JsonPattern(pattern_type="json", path="$.nested.secret", data_type="string"),
    ]

    sensitive_part, non_sensitive_part, extracted_values = redact_message(
        message.encode(), patterns
    )

    # Parse the redacted message
    redacted_data = non_sensitive_part.decode()
    redacted_json = json.loads(
        redacted_data[redacted_data.find("{") : redacted_data.rfind("}") + 1]
    )

    # Check that specified fields are redacted
    assert redacted_json["sensitive"] == "****"
    assert redacted_json["public"] == "hello"
    assert redacted_json["nested"]["secret"] == "****"
    assert redacted_json["nested"]["visible"] == "shown"

    # Check that no values were extracted
    assert not extracted_values


def test_json_extraction():
    """Test extracting values from JSON data."""
    message = """
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "value": 42,
        "nested": {
            "value": 100
        }
    }
    """

    patterns = [
        JsonPattern(
            pattern_type="json", path="$.value", data_type="number", should_extract=True
        ),
        JsonPattern(
            pattern_type="json",
            path="$.nested.value",
            data_type="number",
            should_extract=True,
        ),
    ]

    sensitive_part, non_sensitive_part, extracted_values = redact_message(
        message.encode(), patterns
    )

    # Check extracted values
    assert len(extracted_values) == 2
    assert 42 in extracted_values
    assert 100 in extracted_values

    # Parse the redacted message
    redacted_data = non_sensitive_part.decode()
    redacted_json = json.loads(
        redacted_data[redacted_data.find("{") : redacted_data.rfind("}") + 1]
    )

    # Check that extracted values are redacted
    assert redacted_json["value"] == "****"
    assert redacted_json["nested"]["value"] == "****"


def test_json_pattern_defaults():
    """Test JSON pattern with default values."""
    message = """
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "object": {
            "field1": "value1",
            "field2": "value2"
        }
    }
    """

    patterns = [JsonPattern(pattern_type="json", path="$.object")]

    sensitive_part, non_sensitive_part, extracted_values = redact_message(
        message.encode(), patterns
    )

    # Parse the redacted message
    redacted_data = non_sensitive_part.decode()
    redacted_json = json.loads(
        redacted_data[redacted_data.find("{") : redacted_data.rfind("}") + 1]
    )

    # Check that keys are preserved (default) and children not included (default)
    assert isinstance(redacted_json["object"], dict)
    assert redacted_json["object"]["field1"] == "****"
    assert redacted_json["object"]["field2"] == "****"


def test_process_secure_message():
    """Test the complete secure message processing flow."""
    # Generate keys
    key_manager = KeyManager()
    key_manager.generate_keys()

    # Create test records
    message1 = """
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "value": 42,
        "sensitive": "secret"
    }
    """

    message2 = """
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "data": {
            "value": 100,
            "sensitive": "hidden"
        }
    }
    """

    # Create patterns for each record
    patterns1 = [
        JsonPattern(
            pattern_type="json", path="$.value", data_type="number", should_extract=True
        ),
        JsonPattern(pattern_type="json", path="$.sensitive", data_type="string"),
    ]

    patterns2 = [
        JsonPattern(
            pattern_type="json",
            path="$.data.value",
            data_type="number",
            should_extract=True,
        ),
        JsonPattern(pattern_type="json", path="$.data.sensitive", data_type="string"),
    ]

    # Process each record
    sensitive_part1, non_sensitive_part1, extracted_values1 = redact_message(
        message1.encode(), patterns1
    )
    sensitive_part2, non_sensitive_part2, extracted_values2 = redact_message(
        message2.encode(), patterns2
    )

    # Check extracted values
    assert len(extracted_values1) == 1
    assert extracted_values1[0] == 42
    assert len(extracted_values2) == 1
    assert extracted_values2[0] == 100

    # Parse and check redacted messages
    redacted_json1 = json.loads(
        non_sensitive_part1.decode()[non_sensitive_part1.decode().find("{") :]
    )
    assert redacted_json1["value"] == "****"
    assert redacted_json1["sensitive"] == "****"

    redacted_json2 = json.loads(
        non_sensitive_part2.decode()[non_sensitive_part2.decode().find("{") :]
    )
    assert redacted_json2["data"]["value"] == "****"
    assert redacted_json2["data"]["sensitive"] == "****"


def test_invalid_signature():
    """Test handling of invalid signatures."""
    # Generate keys
    key_manager = KeyManager()
    key_manager.generate_keys()

    # Create a record with a JSON message
    message = """
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "value": 42,
        "sensitive": "secret"
    }
    """

    patterns = [
        JsonPattern(
            pattern_type="json", path="$.value", data_type="number", should_extract=True
        )
    ]

    # Process the record
    sensitive_part, non_sensitive_part, extracted_values = redact_message(
        message.encode(), patterns
    )

    # Check that the value was extracted and redacted
    assert len(extracted_values) == 1
    assert extracted_values[0] == 42

    redacted_json = json.loads(
        non_sensitive_part.decode()[non_sensitive_part.decode().find("{") :]
    )
    assert redacted_json["value"] == "****"
    assert redacted_json["sensitive"] == "secret"  # Not redacted


def test_invalid_pattern():
    """Test handling of invalid pattern configuration."""
    message = """
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "value": 42
    }
    """

    # Invalid pattern type
    with pytest.raises(ValidationError):
        JsonPattern(pattern_type="invalid", path="$.value")

    # Invalid data type
    with pytest.raises(ValidationError):
        JsonPattern(pattern_type="json", path="$.value", data_type="invalid")

    # Test with actual message processing
    patterns = [JsonPattern(pattern_type="json", path="$.value", data_type="number")]
    sensitive_part, non_sensitive_part, extracted_values = redact_message(
        message.encode(), patterns
    )
    assert extracted_values == []  # No extraction requested
