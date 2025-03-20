"""Tests for examples functionality."""

import pytest

from src.examples.data import EXAMPLES
from src.server.server import JsonPattern


def test_examples_structure():
    """Test that all examples have the correct structure."""
    for name, (message, patterns) in EXAMPLES.items():
        # Check message - can be either a string or a list of strings
        if "split" in name:
            # Split examples should be a list of strings
            assert isinstance(
                message, list
            ), f"Split example {name} message should be a list"
            assert all(
                isinstance(m, str) for m in message
            ), f"All fragments in {name} should be strings"
            assert all(
                m.strip() for m in message
            ), f"All fragments in {name} should not be empty"
        else:
            # Regular examples should be a string
            assert isinstance(
                message, str
            ), f"Example {name} message should be a string"
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
    assert len(patterns) == 4

    # Coins balance pattern (extract)
    coins_balance_pattern = JsonPattern(**patterns[0])
    assert coins_balance_pattern.path == "$.data.redeem_info.coins_balance"
    assert coins_balance_pattern.should_extract is True
    assert coins_balance_pattern.data_type == "number"

    # Redeem info pattern (redact)
    redeem_pattern = JsonPattern(**patterns[1])
    assert redeem_pattern.path == "$.data.redeem_info"
    assert redeem_pattern.data_type == "string"
    assert redeem_pattern.should_extract is False

    # Coins pattern (redact)
    coins_pattern = JsonPattern(**patterns[2])
    assert coins_pattern.path == "$.data.coins"
    assert coins_pattern.data_type == "number"

    # Frozen coins pattern (redact)
    frozen_coins_pattern = JsonPattern(**patterns[3])
    assert frozen_coins_pattern.path == "$.data.frozen_coins"
    assert frozen_coins_pattern.data_type == "number"


def test_tiktok_split_examples():
    """Test the TikTok split example configurations."""
    # Test split1 example (split in middle of coins_balance)
    message1, patterns1 = EXAMPLES["tiktok-split1"]
    assert isinstance(message1, list)
    assert len(message1) == 2
    assert all(isinstance(m, str) for m in message1)
    assert 'coins_balance":1' in message1[0]  # First part of split number
    assert "23" in message1[1]  # Second part of split number

    # Test split2 example (split at redeem_info)
    message2, patterns2 = EXAMPLES["tiktok-split2"]
    assert isinstance(message2, list)
    assert len(message2) == 2
    assert all(isinstance(m, str) for m in message2)
    assert 'redeem_info":' in message2[0]  # First part ends with redeem_info
    assert '{"coins_balance"' in message2[1]  # Second part starts with coins_balance

    # Verify patterns for both examples
    for patterns in [patterns1, patterns2]:
        assert len(patterns) == 4

        # Coins balance pattern (extract)
        coins_balance_pattern = JsonPattern(**patterns[0])
        assert coins_balance_pattern.path == "$.data.redeem_info.coins_balance"
        assert coins_balance_pattern.should_extract is True
        assert coins_balance_pattern.data_type == "number"

        # Redeem info pattern (redact)
        redeem_pattern = JsonPattern(**patterns[1])
        assert redeem_pattern.path == "$.data.redeem_info"
        assert redeem_pattern.data_type == "string"
        assert redeem_pattern.should_extract is False

        # Coins pattern (redact)
        coins_pattern = JsonPattern(**patterns[2])
        assert coins_pattern.path == "$.data.coins"
        assert coins_pattern.data_type == "number"

        # Frozen coins pattern (redact)
        frozen_coins_pattern = JsonPattern(**patterns[3])
        assert frozen_coins_pattern.path == "$.data.frozen_coins"
        assert frozen_coins_pattern.data_type == "number"


def test_get_example_data():
    """Test getting example data."""
    from src.client.client import get_example_data

    # Test toy example
    message, patterns, origin = get_example_data("toy")
    assert isinstance(message, str)
    assert isinstance(patterns, list)
    assert isinstance(origin, str)
    assert message == EXAMPLES["toy"][0]
    assert patterns == EXAMPLES["toy"][1]
    assert origin == "toy"

    # Test amazon example
    message, patterns, origin = get_example_data("amazon")
    assert isinstance(message, str)
    assert isinstance(patterns, list)
    assert isinstance(origin, str)
    assert message == EXAMPLES["amazon"][0]
    assert patterns == EXAMPLES["amazon"][1]
    assert origin == "amazon"

    # Test invalid example
    with pytest.raises(ValueError, match="Unknown example"):
        get_example_data("invalid")
