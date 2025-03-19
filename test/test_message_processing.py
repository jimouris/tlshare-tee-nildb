"""Tests for message processing functionality."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.config.key_management import KeyManager
from src.server.server import BLOCK_SIZE, extract_number, redact_message


def test_extract_message_parts():
    """Test extracting sensitive and non-sensitive parts of a message."""
    # Create a test message with known content
    message = b"Hello, this is a test message with sensitive data!"
    sensitive_indices = [1, 3]

    # Extract parts
    sensitive_part, non_sensitive_part = redact_message(
        message, sensitive_indices, BLOCK_SIZE
    )

    # Verify lengths
    total_blocks = len(message) // BLOCK_SIZE
    remaining_bytes = len(message) % BLOCK_SIZE
    blocks_to_redact = [i for i in sensitive_indices if i < total_blocks]
    expected_sensitive_length = len(blocks_to_redact) * BLOCK_SIZE
    if total_blocks in sensitive_indices and remaining_bytes > 0:
        expected_sensitive_length += remaining_bytes

    assert len(sensitive_part) == expected_sensitive_length
    assert len(non_sensitive_part) == len(message) - expected_sensitive_length


def test_extract_message_parts_with_partial_block():
    """Test extracting parts when the last block is partial."""
    # Create a message that's not a multiple of BLOCK_SIZE
    message = b"Hello, this is a test message with sensitive data!"
    sensitive_indices = [1, 3]  # Include the last partial block

    # Extract parts
    sensitive_part, non_sensitive_part = redact_message(
        message, sensitive_indices, BLOCK_SIZE
    )

    # Verify lengths
    total_blocks = len(message) // BLOCK_SIZE
    remaining_bytes = len(message) % BLOCK_SIZE
    blocks_to_redact = [i for i in sensitive_indices if i < total_blocks]
    expected_sensitive_length = len(blocks_to_redact) * BLOCK_SIZE
    if total_blocks in sensitive_indices and remaining_bytes > 0:
        expected_sensitive_length += remaining_bytes

    assert len(sensitive_part) == expected_sensitive_length
    assert len(non_sensitive_part) == len(message) - expected_sensitive_length


def test_process_secure_message(
    key_manager: KeyManager,
    sample_message: str,
    sample_blocks_to_redact: list[int],
    sample_blocks_to_extract: list[int],
):
    """Test the complete secure message processing flow."""
    # Generate keys
    key_manager.generate_keys()

    # Generate AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    # Generate nonce and encrypt
    nonce = b"test_nonce_12"  # 12 bytes
    ciphertext = aesgcm.encrypt(nonce, sample_message.encode(), None)
    full_ciphertext = nonce + ciphertext

    # Sign the data
    data_to_sign = full_ciphertext
    signature = key_manager.sign_data(data_to_sign)

    # Verify the signature
    assert key_manager.verify_signature(data_to_sign, signature)

    # Test decryption
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    assert decrypted.decode() == sample_message

    # Test message parts extraction
    sensitive_part, non_sensitive_part = redact_message(
        decrypted, sample_blocks_to_redact, BLOCK_SIZE
    )
    current_pos = 0
    extracted_number = None
    for idx in sorted(sample_blocks_to_redact):
        block_length = min(BLOCK_SIZE, len(decrypted) - idx * BLOCK_SIZE)
        block = sensitive_part[current_pos : current_pos + block_length].decode("utf-8")
        print(f"Block {idx}: {block}")
        if (
            idx in sample_blocks_to_extract
        ):  # Check if the block is in blocks_to_extract
            extracted_number = extract_number(block)
        current_pos += block_length

    # Verify sensitive parts
    assert len(sensitive_part) == BLOCK_SIZE * len(sample_blocks_to_redact)
    assert len(non_sensitive_part) == len(decrypted) - len(sensitive_part)
    assert extracted_number == 100


def test_invalid_signature(key_manager: KeyManager, sample_message: str):
    """Test handling of invalid signatures."""
    # Generate keys
    key_manager.generate_keys()

    # Generate AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    # Generate nonce and encrypt
    nonce = b"test_nonce_12"
    ciphertext = aesgcm.encrypt(nonce, sample_message.encode(), None)
    full_ciphertext = nonce + ciphertext

    # Create invalid signature
    invalid_signature = b"invalid" * 8  # 64 bytes of invalid data

    # Verify that invalid signature is rejected
    data_to_verify = full_ciphertext + aes_key
    assert not key_manager.verify_signature(data_to_verify, invalid_signature)


def test_invalid_block_indices():
    """Test handling of invalid block indices."""
    message = b"Hello, this is a test message!"
    invalid_indices = [10]  # Index beyond message length

    with pytest.raises(ValueError):
        redact_message(message, invalid_indices, BLOCK_SIZE)
