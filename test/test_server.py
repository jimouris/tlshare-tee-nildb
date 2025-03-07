"""Integration tests for the FastAPI server."""

import base64
import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

from src.server import app
from src.key_management import KeyManager

@pytest.fixture
def client(key_manager: KeyManager) -> TestClient:
    """Create a test client with the FastAPI app."""
    # Override the global key manager with the test key manager
    import src.server
    src.main.key_manager = key_manager
    return TestClient(app)

def test_root_endpoint(client: TestClient):
    """Test the root endpoint redirects to docs."""
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307  # Temporary redirect
    assert response.headers["location"] == "/docs"

def test_public_key_endpoint(client: TestClient, key_manager: KeyManager):
    """Test the public key endpoint."""
    # Generate keys first
    key_manager.generate_keys()

    # Get the public key
    response = client.get("/public-key")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-pem-file"

def test_process_secure_message(client: TestClient, key_manager: KeyManager, sample_message: str, sample_sensitive_indices: list[int]):
    """Test processing a secure message."""
    # Generate keys
    key_manager.generate_keys()

    # Generate AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    # Generate nonce and encrypt
    nonce = os.urandom(12)  # Use random nonce instead of fixed one
    ciphertext = aesgcm.encrypt(nonce, sample_message.encode(), None)
    full_ciphertext = nonce + ciphertext

    # Sign the data
    data_to_sign = full_ciphertext
    signature = key_manager.sign_data(data_to_sign)

    # Prepare the request payload
    payload = {
        "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
        "aes_key": base64.b64encode(aes_key).decode(),
        "ecdsa_signature": base64.b64encode(signature).decode(),
        "sensitive_blocks_indices": sample_sensitive_indices
    }

    # Send the request
    response = client.post("/process-secure-message", json=payload)
    assert response.status_code == 200
    assert response.json() == {"status": "success"}

def test_invalid_signature(client: TestClient, key_manager: KeyManager, sample_message: str):
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

    # Prepare the request payload
    payload = {
        "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
        "aes_key": base64.b64encode(aes_key).decode(),
        "ecdsa_signature": base64.b64encode(invalid_signature).decode(),
        "sensitive_blocks_indices": [1, 3]
    }

    # Send the request
    response = client.post("/process-secure-message", json=payload)
    assert response.status_code == 400
    assert "Invalid signature" in response.json()["detail"]

def test_invalid_block_indices(client: TestClient, key_manager: KeyManager, sample_message: str):
    """Test handling of invalid block indices."""
    # Generate keys
    key_manager.generate_keys()

    # Generate AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    # Generate nonce and encrypt
    nonce = os.urandom(12)  # Use random nonce
    ciphertext = aesgcm.encrypt(nonce, sample_message.encode(), None)
    full_ciphertext = nonce + ciphertext

    # Sign the data
    data_to_sign = full_ciphertext
    signature = key_manager.sign_data(data_to_sign)

    # Prepare the request payload with invalid block indices
    payload = {
        "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
        "aes_key": base64.b64encode(aes_key).decode(),
        "ecdsa_signature": base64.b64encode(signature).decode(),
        "sensitive_blocks_indices": [100]  # Invalid index
    }

    # Send the request
    response = client.post("/process-secure-message", json=payload)
    assert response.status_code == 400
    assert "Invalid sensitive block indices" in response.json()["detail"]
