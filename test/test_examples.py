"""Tests for examples functionality."""

import pytest

from src.examples.data import EXAMPLES
from src.server.server import JsonPattern


def test_examples_structure():
    """Test that all examples have the correct structure."""
    for name, (message, patterns) in EXAMPLES.items():
        # Check message
        assert isinstance(message, str), f"Example {name} message should be a string"
        assert message.strip(), f"Example {name} message should not be empty"

        # Check patterns
        assert isinstance(patterns, list), f"Example {name} patterns should be a list"
        assert patterns, f"Example {name} patterns should not be empty"

        # Check each pattern
        for pattern in patterns:
            assert isinstance(pattern, dict), f"Pattern in {name} should be a dict"
            assert "pattern_type" in pattern, f"Pattern in {name} missing pattern_type"
            assert "path" in pattern, f"Pattern in {name} missing path"
            assert (
                pattern["pattern_type"] == "json"
            ), f"Pattern in {name} should be json type"


def test_toy_example():
    """Test the toy example configuration."""
    message, patterns = EXAMPLES["toy"]

    # Verify message format
    assert "JSON here" in message
    assert message.startswith("HTTP/1.1")

    # Verify patterns
    assert len(patterns) == 1
    pattern = JsonPattern(**patterns[0])
    assert pattern.path == "$.value"
    assert pattern.should_extract is True
    assert pattern.data_type == "number"


def test_amazon_example():
    """Test the Amazon example configuration."""
    message, patterns = EXAMPLES["amazon"]

    # Verify message format
    assert "orderId" in message
    assert "totalAmount" in message
    assert "shipping" in message
    assert message.startswith("HTTP/2")

    # Verify patterns
    assert len(patterns) == 4

    # Value extraction pattern
    value_pattern = JsonPattern(**patterns[0])
    assert value_pattern.path == "$.totalAmount.value"
    assert value_pattern.should_extract is True
    assert value_pattern.data_type == "number"

    # Total amount redaction pattern
    total_pattern = JsonPattern(**patterns[1])
    assert total_pattern.path == "$.totalAmount"
    assert total_pattern.include_children is True
    assert total_pattern.should_extract is False

    # Shipping redaction pattern
    shipping_pattern = JsonPattern(**patterns[2])
    assert shipping_pattern.path == "$.shipping"
    assert shipping_pattern.include_children is True
    assert shipping_pattern.should_extract is False

    # Order details redaction pattern
    order_pattern = JsonPattern(**patterns[3])
    assert order_pattern.path == "$['orderId', 'orderDate']"
    assert order_pattern.should_extract is False


def test_tiktok_example():
    """Test the TikTok example configuration."""
    message, patterns = EXAMPLES["tiktok"]

    # Verify message format
    assert "coins_balance" in message
    assert "redeem_info" in message
    assert message.startswith("HTTP/1.1")

    # Verify patterns
    assert len(patterns) == 2

    # Coins balance pattern
    coins_pattern = JsonPattern(**patterns[0])
    assert coins_pattern.path == "$.data.redeem_info.coins_balance"
    assert coins_pattern.should_extract is True
    assert coins_pattern.data_type == "number"

    # Redeem info pattern
    redeem_pattern = JsonPattern(**patterns[1])
    assert redeem_pattern.path == "$.data.redeem_info"
    assert redeem_pattern.include_children is True
    assert redeem_pattern.should_extract is False


def test_get_example_data():
    """Test getting example data."""
    from src.client.client import get_example_data

    # Test single example
    messages, patterns = get_example_data(["toy"])
    assert len(messages) == 1
    assert len(patterns) == 1
    assert messages[0] == EXAMPLES["toy"][0]
    assert patterns[0] == EXAMPLES["toy"][1]

    # Test multiple examples
    messages, patterns = get_example_data(["toy", "amazon"])
    assert len(messages) == 2
    assert len(patterns) == 2
    assert messages[0] == EXAMPLES["toy"][0]
    assert patterns[0] == EXAMPLES["toy"][1]
    assert messages[1] == EXAMPLES["amazon"][0]
    assert patterns[1] == EXAMPLES["amazon"][1]

    # Test invalid example
    with pytest.raises(ValueError, match="Unknown example"):
        get_example_data(["invalid"])
