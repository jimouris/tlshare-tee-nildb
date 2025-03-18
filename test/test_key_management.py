"""Tests for key management functionality."""

import pytest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from src.config.key_management import KeyManager
from src.server.server import app

def test_generate_keys(key_manager: KeyManager):
    """Test key generation and saving."""
    # Generate keys
    key_manager.generate_keys()

    # Check that both keys were created
    assert key_manager.private_key_path.exists()
    assert key_manager.public_key_path.exists()

    # Verify key formats
    with open(key_manager.private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    with open(key_manager.public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
        assert isinstance(public_key, ec.EllipticCurvePublicKey)

def test_load_keys(key_manager: KeyManager):
    """Test loading keys from disk."""
    # First generate keys
    key_manager.generate_keys()

    # Test loading private key
    private_key = key_manager.load_private_key()
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    # Test loading public key
    public_key = key_manager.load_public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)

def test_sign_and_verify(key_manager: KeyManager):
    """Test signing and verification of data."""
    # Generate keys
    key_manager.generate_keys()

    # Test data
    test_data = b"Hello, World!"

    # Sign the data
    signature = key_manager.sign_data(test_data)
    assert isinstance(signature, bytes)
    assert len(signature) == 64  # 32 bytes for r + 32 bytes for s

    # Verify the signature
    assert key_manager.verify_signature(test_data, signature)

    # Test with modified data
    modified_data = b"Hello, World?"
    assert not key_manager.verify_signature(modified_data, signature)

def test_load_nonexistent_keys(key_manager: KeyManager):
    """Test loading nonexistent keys raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        key_manager.load_private_key()

    with pytest.raises(FileNotFoundError):
        key_manager.load_public_key()
