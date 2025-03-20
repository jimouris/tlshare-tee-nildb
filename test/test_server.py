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

    # Create two records with different patterns
    records = []
    concatenated_ciphertexts = b""

    # First record: toy example
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
    patterns1 = [
        {
            "pattern_type": "json",
            "path": "$.value",
            "data_type": "number",
            "should_extract": True,
        }
    ]

    # Second record: simple redaction
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
    patterns2 = [
        {
            "pattern_type": "json",
            "path": "$.sensitive",
            "include_children": True,
            "data_type": "string",
        }
    ]

    # Process both records
    for message, patterns in [(message1, patterns1), (message2, patterns2)]:
        nonce = os.urandom(12)
        aes_associated_data = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode(), aes_associated_data)
        full_ciphertext = nonce + ciphertext
        concatenated_ciphertexts += full_ciphertext

        records.append(
            {
                "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
                "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
                "patterns": patterns,
            }
        )

    # Sign concatenated ciphertexts
    signature = key_manager.sign_data(concatenated_ciphertexts)

    # Prepare payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "records": records,
        "ecdsa_signature": base64.b64encode(signature).decode(),
        "is_test": True,
    }

    # Send request
    response = client.post("/process-secure-message", json=payload)
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "success"
    assert len(result["redacted_messages"]) == 2
    assert len(result["extracted_values"]) == 1
    assert result["extracted_values"][0] == 42
    assert result["record_ids"] is None  # Test mode


def test_invalid_signature(client: TestClient, key_manager: KeyManager):
    """Test handling of invalid signatures."""
    key_manager.generate_keys()
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    # Create a record
    message = '{"value": 42}'
    patterns = [{"pattern_type": "json", "path": "$.value"}]

    nonce = os.urandom(12)
    aes_associated_data = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), aes_associated_data)
    full_ciphertext = nonce + ciphertext

    records = [
        {
            "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
            "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
            "patterns": patterns,
        }
    ]

    # Create invalid signature
    invalid_signature = "invalid".encode() * 8  # 64 bytes of invalid data

    # Prepare payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "records": records,
        "ecdsa_signature": base64.b64encode(invalid_signature).decode(),
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

    # Create a record with invalid pattern
    message = '{"value": 42}'
    patterns = [{"pattern_type": "invalid", "path": "$.value"}]  # Invalid pattern type

    nonce = os.urandom(12)
    aes_associated_data = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), aes_associated_data)
    full_ciphertext = nonce + ciphertext

    records = [
        {
            "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
            "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
            "patterns": patterns,
        }
    ]

    # Sign concatenated ciphertexts
    signature = key_manager.sign_data(full_ciphertext)

    # Prepare payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "records": records,
        "ecdsa_signature": base64.b64encode(signature).decode(),
    }

    # Send request
    response = client.post("/process-secure-message", json=payload)
    assert response.status_code == 400  # Validation error
