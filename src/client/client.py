"""Client for sending secure messages to the TEE server."""

import os
import base64
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.config.key_management import KeyManager
from src.config.logging import logger

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

    Returns:
        bytes: The encrypted message with nonce prepended
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), associated_data)
    # Prepend the nonce to the ciphertext
    return nonce + ciphertext

def main(
        message: str,
        blocks_to_redact: list[int],
        blocks_to_extract: list[int],
        server_url: str = "http://localhost:8000"
    ) -> None:
    """Main function to demonstrate secure message sending.

    Args:
        message: The message to send.
        blocks_to_redact: List of indices for sensitive blocks.
        blocks_to_extract: List of block indices to extract data from (subset of blocks_to_redact).
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
        raise RuntimeError("Private key not found. Please generate keys first.") from exc

    # Generate a random AES key
    aes_key = generate_key()

    logger.info("Original message length: %d bytes", len(message))
    logger.info("Original message: %s", message)

    # Encrypt the message
    aes_associated_data = "This is a test message".encode()
    ciphertext = encrypt_message(message, aes_key, aes_associated_data)
    logger.info("Ciphertext length (including nonce): %d bytes", len(ciphertext))

    # Sign the ciphertext
    data_to_sign = ciphertext
    signature = key_manager.sign_data(data_to_sign)

    # Prepare the request payload
    payload = {
        "aes_ciphertext": base64.b64encode(ciphertext).decode(),
        "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
        "aes_key": base64.b64encode(aes_key).decode(),
        "ecdsa_signature": base64.b64encode(signature).decode(),
        "blocks_to_redact": blocks_to_redact,
        "blocks_to_extract": blocks_to_extract,
    }

    # Send the request to the server
    response = requests.post(
        f"{server_url}/process-secure-message",
        json=payload,
        timeout=30  # 30 second timeout
    )

    if response.status_code == 200:
        result = response.json()
        logger.info("Server response: %s", result)
    else:
        logger.error("Error: %d", response.status_code)
        logger.error(response.text)

if __name__ == "__main__":
    import sys
    # Parse command-line arguments
    if len(sys.argv) < 2:
        url = "http://localhost:8000"
    else:
        url = sys.argv[1]

    HTTPS_EXAMPLE = """
    HTTP/2 200 OK
    Content-Type: application/json
    Content-Length: 256
    Server: Server
    Date: Fri, 07 Mar 2025 12:34:56 GMT
    Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
    Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://amazon.com
    X-Frame-Options: DENY
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    Set-Cookie: session-id=145-9876543-1234567; Path=/; Secure; HttpOnly; SameSite=Strict
    Set-Cookie: session-token=xyz123abc456def789ghi000; Path=/; Secure; HttpOnly; SameSite=Strict

    {
      "orderId": "112-3456789-0123456",
      "status": "Confirmed",
      "orderDate": "2025-03-07T12:34:56Z",
      "totalAmount": {
        "currency": "USD",
        "value": "129.99"
      },
      "shipping": {
        "method": "Standard Shipping",
        "estimatedDelivery": "2025-03-10T18:00:00Z",
        "address": {
          "recipient": "John Doe",
          "line1": "1234 Elm Street",
          "line2": "Apt 567",
          "city": "Seattle",
          "state": "WA",
          "postalCode": "98101",
          "country": "US"
        }
      }
    }
    """
    blocks_to_redact_example = [51, 62, 64, 65, 67, 68, 70, 72]
    blocks_to_extract_example = [51]
    main(HTTPS_EXAMPLE, blocks_to_redact_example, blocks_to_extract_example, url)
