"""Key management module for handling cryptographic keys and signatures."""

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .logging import logger


class KeyManager:
    """Manages cryptographic keys and signatures for secure communication."""

    def __init__(self, key_dir: str = "keys"):
        """Initialize the key manager.

        Args:
            key_dir: Directory to store keys
        """
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(exist_ok=True)
        self.private_key_path = self.key_dir / "private_key.pem"
        self.public_key_path = self.key_dir / "public_key.pem"

    def generate_keys(self) -> None:
        """Generate a new key pair and save them to disk."""
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()

        # Save private key
        with open(self.private_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        logger.info("Private key saved to %s", self.private_key_path)

        # Save public key
        with open(self.public_key_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        logger.info("Public key saved to %s", self.public_key_path)

    def load_private_key(self) -> ec.EllipticCurvePrivateKey:
        """Load the private key from disk.

        Returns:
            The loaded private key

        Raises:
            FileNotFoundError: If the private key file doesn't exist
        """
        with open(self.private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
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
        """Sign data using ECDSA with SHA-256.

        Args:
            data: The data to sign

        Returns:
            bytes: The signature
        """
        # First compute SHA-256 hash of the data
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(data)
        data_hash = hasher.finalize()

        # Sign the hash with the private key
        private_key = self.load_private_key()
        signature = private_key.sign(data_hash, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify an ECDSA signature.

        Args:
            data: The data that was signed
            signature: The signature to verify

        Returns:
            bool: True if signature is valid
        """
        try:
            # First compute SHA-256 hash of the data
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(data)
            data_hash = hasher.finalize()

            # Verify the signature of the hash
            public_key = self.load_public_key()
            public_key.verify(signature, data_hash, ec.ECDSA(hashes.SHA256()))
            logger.info("Signature verification successful")
            return True
        except InvalidSignature:
            logger.error("Signature verification failed - invalid signature")
            return False
        except Exception as exc:
            raise RuntimeError(f"Signature verification failed: {str(exc)}") from exc


def generate_and_save_keys():
    """Generate and save a new key pair"""
    key_manager = KeyManager()
    key_manager.generate_keys()
    logger.info("New key pair generated and saved successfully")
    return key_manager.load_private_key(), key_manager.load_public_key()


if __name__ == "__main__":
    # Generate and save keys
    generate_and_save_keys()
