"""Client for sending secure messages to the TEE server."""

import argparse
import base64
import os
from typing import Any, Dict, List, Tuple

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.config.key_management import KeyManager
from src.config.logging import logger
from src.examples.data import EXAMPLES


def generate_key() -> bytes:
    """Generate a random AES key.

    Returns:
        bytes: A 256-bit AES key
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt_message(message: str, key: bytes, associated_data: bytes) -> bytes:
    """Encrypt a message using AES-GCM.

    Args:
        message: The message to encrypt
        key: The AES key to use for encryption
        associated_data: The associated data for AES-GCM

    Returns:
        bytes: The encrypted message with nonce prepended
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), associated_data)
    # Prepend the nonce to the ciphertext
    return nonce + ciphertext


def process_messages(
    messages: List[str],
    patterns: List[List[Dict[str, Any]]],
    server_url: str = "http://localhost:8000",
) -> None:
    """Process and send messages to the server.

    Args:
        messages: List of messages to send.
        patterns: List of lists of patterns for redaction and extraction.
        server_url: The URL of the server (default: http://localhost:8000).
    """
    # Validate that all lists have the same length
    if len(messages) != len(patterns):
        raise ValueError(
            f"Messages and patterns must have the same length. Got: messages={len(messages)}, "
            f"patterns={len(patterns)}"
        )

    # Initialize key manager
    key_manager = KeyManager()

    try:
        # Verify private key exists
        key_manager.load_private_key()
        logger.info("Private key loaded successfully")
    except FileNotFoundError as exc:
        logger.error("Private key not found. Please generate keys first.")
        raise RuntimeError(
            "Private key not found. Please generate keys first."
        ) from exc

    # Generate a random AES key
    aes_key = generate_key()

    # Process each message
    records = []
    concatenated_ciphertexts = b""

    for i, (message, message_patterns) in enumerate(zip(messages, patterns)):
        aes_associated_data = os.urandom(12)
        ciphertext = encrypt_message(message, aes_key, aes_associated_data)
        concatenated_ciphertexts += ciphertext

        record = {
            "aes_ciphertext": base64.b64encode(ciphertext).decode(),
            "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
            "patterns": message_patterns,
        }
        records.append(record)

    # Sign the concatenated ciphertexts
    signature = key_manager.sign_data(concatenated_ciphertexts)

    # Prepare the request payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "records": records,
        "ecdsa_signature": base64.b64encode(signature).decode(),
    }

    # Send the request to the server
    response = requests.post(
        f"{server_url}/process-secure-message", json=payload, timeout=30
    )

    if response.status_code == 200:
        result = response.json()
        logger.info("Server response: %s", result)

        # Print redacted messages and extracted values
        logger.info("\nProcessed Messages:")
        for i, (message, redacted) in enumerate(
            zip(messages, result["redacted_messages"])
        ):
            logger.info("\nMessage %d:", i)
            logger.info("Original length: %d bytes", len(message))
            logger.info("Redacted message:")
            logger.info("%s", redacted)

        logger.info("Extracted Values:")
        for i, value in enumerate(result["extracted_values"]):
            logger.info("Value %d: %s", i, value)

        if result.get("record_ids"):
            logger.info("\nStored in nilDB with record IDs: %s", result["record_ids"])
        else:
            logger.info("\nTest mode - values not stored in nilDB")
    else:
        logger.error("Error: %d", response.status_code)
        logger.error(response.text)


def get_example_data(
    example_names: List[str],
) -> Tuple[List[str], List[List[Dict[str, Any]]]]:
    """Get example data and patterns for the specified examples.

    Args:
        example_names: List of example names to process

    Returns:
        Tuple of (messages, patterns)
    """
    messages = []
    patterns = []

    for name in example_names:
        if name not in EXAMPLES:
            raise ValueError(
                f"Unknown example: {name}. Available examples: {list(EXAMPLES.keys())}"
            )
        message, pattern = EXAMPLES[name]
        messages.append(message)
        patterns.append(pattern)

    return messages, patterns


def main():
    """Main function to parse arguments and run the client."""
    parser = argparse.ArgumentParser(
        description="Client for sending secure messages to the TEE server."
    )
    parser.add_argument(
        "--server-url",
        default="http://localhost:8000",
        help="URL of the server (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--examples",
        nargs="+",
        choices=list(EXAMPLES.keys()),
        default=["amazon"],
        help="Examples to run (default: amazon)",
    )

    args = parser.parse_args()

    try:
        messages, patterns = get_example_data(args.examples)
        process_messages(messages, patterns, args.server_url)
    except Exception as exc:
        logger.error("Error running client: %s", str(exc))
        raise


if __name__ == "__main__":
    main()
