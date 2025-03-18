"""Integration tests for the FastAPI server."""

import base64
import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

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

def test_process_secure_message(
    client: TestClient,
    key_manager: KeyManager,
    sample_message: str,
    sample_blocks_to_redact: list[int],
    sample_blocks_to_extract: list[int],
):
    """Test processing multiple secure messages."""
    key_manager.generate_keys()
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    # Create two records
    records = []
    concatenated_ciphertexts = b''

    for _ in range(2):  # Create two records
        nonce = os.urandom(12)
        aes_associated_data = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, sample_message.encode(), aes_associated_data)
        full_ciphertext = nonce + ciphertext
        concatenated_ciphertexts += full_ciphertext

        records.append({
            "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
            "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
            "blocks_to_redact": sample_blocks_to_redact,
            "blocks_to_extract": sample_blocks_to_extract,
        })

    # Sign concatenated ciphertexts
    signature = key_manager.sign_data(concatenated_ciphertexts)

    # Prepare payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "records": records,
        "ecdsa_signature": base64.b64encode(signature).decode(),
        "is_test": True
    }

    # Send request
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

    # Create two records
    records = []
    concatenated_ciphertexts = b''

    for _ in range(2):  # Create two records
        nonce = os.urandom(12)
        aes_associated_data = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, sample_message.encode(), aes_associated_data)
        full_ciphertext = nonce + ciphertext
        concatenated_ciphertexts += full_ciphertext

        records.append({
            "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
            "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
            "blocks_to_redact": [1, 3],
            "blocks_to_extract": [1],
        })

    # Create invalid signature
    invalid_signature = "invalid".encode() * 8  # 64 bytes of invalid data

    # Prepare the request payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "records": records,
        "ecdsa_signature": base64.b64encode(invalid_signature).decode(),
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

    # Create records with invalid block indices
    records = []
    concatenated_ciphertexts = b''

    for _ in range(2):  # Create two records
        nonce = os.urandom(12)
        aes_associated_data = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, sample_message.encode(), aes_associated_data)
        full_ciphertext = nonce + ciphertext
        concatenated_ciphertexts += full_ciphertext

        records.append({
            "aes_ciphertext": base64.b64encode(full_ciphertext).decode(),
            "aes_associated_data": base64.b64encode(aes_associated_data).decode(),
            "blocks_to_redact": [100],  # Invalid index
            "blocks_to_extract": [],
        })

    # Sign concatenated ciphertexts
    signature = key_manager.sign_data(concatenated_ciphertexts)

    # Prepare the request payload
    payload = {
        "aes_key": base64.b64encode(aes_key).decode(),
        "records": records,
        "ecdsa_signature": base64.b64encode(signature).decode(),
    }

    # Send the request
    response = client.post("/process-secure-message", json=payload)
    assert response.status_code == 400
    assert "Invalid block indices" in response.json()["detail"]
