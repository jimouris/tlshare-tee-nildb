"""Integration tests for the FastAPI server."""

import base64
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from src.config.key_management import KeyManager
from src.server.server import app


@pytest.fixture
def client(key_manager: KeyManager) -> TestClient:
    """Create a test client with the FastAPI app."""
    # Override the global key manager with the test key manager
    import src.server.server

    src.server.server.key_manager = key_manager
    return TestClient(app)


def test_root_endpoint(client: TestClient):
    """Test the root endpoint redirects to docs."""
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307  # Temporary redirect
    assert response.headers["location"] == "/docs"


def test_process_secure_message(client: TestClient, key_manager: KeyManager):
    """Test processing multiple secure messages."""
    key_manager.generate_keys()
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    # Create two fragments with different patterns
    fragments = []
    concatenated_ciphertexts = b""

    # First fragment: toy example
    message1 = """
    HTTP/1.1 200 OK
    Content-Type: application/json
    Content-Length: 60

    {
    "message": "JSON here. You're welcome.",
    "value": 42,
    "success": true
    }
    """

    # Second fragment: simple redaction
    message2 = """
    HTTP/1.1 200 OK
    Content-Type: application/json
    Content-Length: 60

    {
    "public": "visible data",
    "sensitive": {
        "field1": "secret1",
        "field2": "secret2"
    }
    }
    """

    # Process both fragments
    for message in [message1, message2]:
        nonce = os.urandom(12)
        aes_associated_data = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode(), aes_associated_data)
        full_ciphertext = nonce + ciphertext
        concatenated_ciphertexts += full_ciphertext

        fragments.append(
            {
                "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
                "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
            }
        )

    # Define patterns for the entire message
    patterns = [
        {
            "pattern_type": "json",
            "path": "$.value",
            "data_type": "number",
            "should_extract": True,
        },
        {
            "pattern_type": "json",
            "path": "$.sensitive",
            "include_children": True,
            "data_type": "string",
        },
    ]

    # Sign concatenated ciphertexts
    signature = key_manager.sign_data(concatenated_ciphertexts)

    # Prepare payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "origin": "test",
        "patterns": patterns,
        "fragments": fragments,
        "ecdsa_signature": base64.b64encode(signature).decode(),
        "is_test": True,
    }

    # Send request
    response = client.post("/process-secure-message", json=payload)
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "success"
    assert "redacted_message" in result
    assert result["extracted_values"] == [42]
    assert result["record_ids"] is None  # Test mode


def test_invalid_signature(client: TestClient, key_manager: KeyManager):
    """Test handling of invalid signatures."""
    key_manager.generate_keys()
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    # Create a fragment
    message = '{"value": 42}'
    patterns = [{"pattern_type": "json", "path": "$.value"}]

    nonce = os.urandom(12)
    aes_associated_data = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), aes_associated_data)
    full_ciphertext = nonce + ciphertext

    fragments = [
        {
            "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
            "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
        }
    ]

    # Create invalid signature
    invalid_signature = os.urandom(64)  # Random invalid signature

    # Prepare payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "origin": "test",
        "patterns": patterns,
        "fragments": fragments,
        "ecdsa_signature": base64.b64encode(invalid_signature).decode(),
        "is_test": True,
    }

    # Send request
    response = client.post("/process-secure-message", json=payload)
    assert response.status_code == 400
    assert "Invalid signature" in response.json()["detail"]


def test_invalid_pattern(client: TestClient, key_manager: KeyManager):
    """Test handling of invalid pattern configuration."""
    key_manager.generate_keys()
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    # Create a fragment with invalid pattern
    message = '{"value": 42}'
    patterns = [{"pattern_type": "invalid", "path": "$.value"}]  # Invalid pattern type

    nonce = os.urandom(12)
    aes_associated_data = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), aes_associated_data)
    full_ciphertext = nonce + ciphertext

    fragments = [
        {
            "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
            "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
        }
    ]

    # Sign concatenated ciphertexts
    signature = key_manager.sign_data(full_ciphertext)

    # Prepare payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "origin": "test",
        "patterns": patterns,
        "fragments": fragments,
        "ecdsa_signature": base64.b64encode(signature).decode(),
        "is_test": True,
    }

    # Send request
    response = client.post("/process-secure-message", json=payload)
    assert response.status_code == 422  # Validation error
