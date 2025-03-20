"""Client for sending secure messages to the TEE server."""

import argparse
import base64
import os
from typing import Any, Dict, List, Tuple, Union

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


def process_message(
    message: Union[str, List[str]],
    patterns: List[Dict[str, Any]],
    origin: str,
    server_url: str = "http://localhost:8000",
) -> None:
    """Process and send a message to the server.

    Args:
        message: The message to send. Can be a string or list of strings for pre-split messages.
        patterns: List of patterns for redaction and extraction.
        origin: Origin of the data (e.g., "amazon", "tiktok").
        server_url: The URL of the server (default: http://localhost:8000).
    """
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
    fragments = []

    # Handle both string and list inputs
    message_parts = message if isinstance(message, list) else [message]
    logger.info("Processing message with %d fragments", len(message_parts))

    # Process each fragment
    for fragment in message_parts:
        aes_associated_data = os.urandom(12)
        ciphertext = encrypt_message(fragment, aes_key, aes_associated_data)
        fragments.append({
            "aes_ciphertext": base64.b64encode(ciphertext).decode(),
            "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
        })

    # Sign the concatenated ciphertexts
    concatenated_ciphertexts = b"".join(
        base64.b64decode(f["aes_ciphertext"]) for f in fragments
    )
    signature = key_manager.sign_data(concatenated_ciphertexts)

    # Prepare the request payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "origin": origin,
        "patterns": patterns,
        "fragments": fragments,
        "ecdsa_signature": base64.b64encode(signature).decode(),
    }

    # Send the request to the server
    response = requests.post(
        f"{server_url}/process-secure-message", json=payload, timeout=30
    )

    if response.status_code == 200:
        result = response.json()
        logger.info("Server response: %s", result)

        # Print redacted message and extracted values
        logger.info("\nProcessed Message:")
        total_length = sum(len(part) for part in message_parts)
        logger.info("Original length: %d bytes", total_length)
        logger.info("Number of fragments: %d", len(fragments))
        logger.info("Redacted message:")
        logger.info("%s", result["redacted_message"])

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


def get_example_data(example_name: str) -> Tuple[Union[str, List[str]], List[Dict[str, Any]], str]:
    """Get example data and patterns for the specified example.

    Args:
        example_name: Name of the example to process

    Returns:
        Tuple of (message, patterns, origin)
    """
    if example_name not in EXAMPLES:
        raise ValueError(
            f"Unknown example: {example_name}. Available examples: {list(EXAMPLES.keys())}"
        )
    message, patterns = EXAMPLES[example_name]
    return message, patterns, example_name


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
        "--example",
        choices=list(EXAMPLES.keys()),
        default="amazon",
        help="Example to run (default: amazon)",
    )

    args = parser.parse_args()

    try:
        message, patterns, origin = get_example_data(args.example)
        process_message(message, patterns, origin, args.server_url)
    except Exception as exc:
        logger.error("Error running client: %s", str(exc))
        raise


if __name__ == "__main__":
    main()
