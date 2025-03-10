"""Key management module for handling cryptographic keys and signatures."""

from pathlib import Path
from typing import Optional

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256
from .config import Config
from .logging import logger

class KeyManager:
    """Manages cryptographic keys and signatures for secure communication."""

    def __init__(self, key_dir: str = "keys", config_path: str = "config.json"):
        """Initialize the key manager.

        Args:
            key_dir: Directory to store keys
        """
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(exist_ok=True)
        self.private_key_path = self.key_dir / "private_key.pem"
        self.public_key_path = self.key_dir / "public_key.pem"
        self.remote_public_key_path = self.key_dir / "public_key.pem"
        self.config = Config(config_path)

    def generate_keys(self) -> None:
        """Generate a new key pair and save them to disk."""
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()

        # Save private key
        with open(self.private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        logger.info("Private key saved to %s", self.private_key_path)

        # Save public key
        with open(self.public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        logger.info("Public key saved to %s", self.public_key_path)

    def load_private_key(self) -> ec.EllipticCurvePrivateKey:
        """Load the private key from disk.

        Returns:
            The loaded private key

        Raises:
            FileNotFoundError: If the private key file doesn't exist
        """
        with open(self.private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        logger.info("Private key loaded from %s", self.private_key_path)
        return private_key

    def load_public_key(self) -> ec.EllipticCurvePublicKey:
        """Load the public key from disk.

        Returns:
            The loaded public key

        Raises:
            FileNotFoundError: If the public key file doesn't exist
        """
        with open(self.public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        logger.info("Public key loaded from %s", self.public_key_path)
        return public_key

    def sign_data(self, data: bytes) -> bytes:
        """Sign data using the private key.

        Args:
            data: The data to sign

        Returns:
            The signature as bytes
        """
        private_key = self.load_private_key()
        signature = private_key.sign(
            data,
            ec.ECDSA(SHA256())
        )
        # Convert the signature to a fixed-length format
        r, s = decode_dss_signature(signature)
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature using the public key.

        Args:
            data: The data that was signed
            signature: The signature to verify

        Returns:
            True if the signature is valid, False otherwise
        """
        public_key = self.load_public_key()
        try:
            # Convert the fixed-length signature back to the format expected by verify
            r = int.from_bytes(signature[:32], 'big')
            s = int.from_bytes(signature[32:], 'big')
            public_key.verify(
                encode_dss_signature(r, s),
                data,
                ec.ECDSA(SHA256())
            )
            logger.info("Signature verification successful")
            return True
        except InvalidSignature:
            logger.error("Signature verification failed - invalid signature")
            return False
        except Exception as exc:
            raise RuntimeError(f"Signature verification failed: {str(exc)}") from exc

    def fetch_remote_public_key(self, remote_url: str) -> Optional[ec.EllipticCurvePublicKey]:
        """Fetch the remote public key from a URL.

        Args:
            remote_url: URL to fetch the public key from

        Returns:
            The remote public key if successful, None otherwise
        """
        try:
            response = requests.get(remote_url, timeout=30)
            response.raise_for_status()

            with open(self.remote_public_key_path, "wb") as f:
                f.write(response.content)
            logger.info("Remote public key saved to %s", self.remote_public_key_path)

            return serialization.load_pem_public_key(response.content)
        except Exception as exc:
            logger.error("Failed to fetch public key: %s", str(exc))
            raise RuntimeError(f"Failed to fetch public key: {str(exc)}") from exc

def generate_and_save_keys():
    """Generate and save a new key pair"""
    key_manager = KeyManager()
    key_manager.generate_keys()
    logger.info("New key pair generated and saved successfully")
    return key_manager.load_private_key(), key_manager.load_public_key()

if __name__ == "__main__":
    # Generate and save keys
    generate_and_save_keys()
