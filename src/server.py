"""FastAPI server that processes secure messages with AES encryption and ECDSA signatures."""

import asyncio
import contextlib
import datetime
import re
from base64 import b64decode
from typing import List

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse, Response
from nildb_operations import upload_amazon_purchase
from pydantic import BaseModel, Field, field_validator

from src.key_management import KeyManager
from src.logging_config import logger

# Initialize key manager
key_manager = KeyManager()

# Constants
BLOCK_SIZE = 16  # AES block size in bytes

@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    """Handle startup and shutdown events."""
    # Startup
    logger.info("Server starting up...")
    try:
        # Check if keys exist, generate them if they don't
        if not key_manager.public_key_path.exists():
            logger.info("Keys not found. Generating new key pair...")
            key_manager.generate_keys()
            logger.info("New key pair generated successfully")

        # Verify public key exists
        public_key = key_manager.load_public_key()
        logger.info("Public key loaded successfully")
        # Log public key details
        public_numbers = public_key.public_numbers()
        logger.info("Public key details:")
        logger.info("- Curve: %s", public_numbers.curve.name)
        logger.info("- X coordinate: %s", hex(public_numbers.x))
        logger.info("- Y coordinate: %s", hex(public_numbers.y))
    except Exception as exc:
        logger.error("Error during startup: %s", str(exc))
        raise RuntimeError("Server startup failed") from exc

    logger.info("Available endpoints:")
    logger.info("- GET /")
    logger.info("- GET /public-key")
    logger.info("- POST /process-secure-message")

    yield

    # Shutdown
    logger.info("Server shutting down...")

class SecureMessage(BaseModel):
    """Model for secure message containing encrypted data and metadata."""

    aes_ciphertext: str = Field(..., description="Base64 encoded AES encrypted data")
    aes_key: str = Field(..., description="Base64 encoded AES key used for encryption")
    ecdsa_signature: str = Field(..., description="Base64 encoded ECDSA signature for verification")
    sensitive_blocks_indices: List[int] = Field(..., description="List of indices for sensitive blocks")

    @field_validator('aes_ciphertext', 'aes_key', 'ecdsa_signature')
    @classmethod
    def decode_base64(cls, v: str) -> bytes:
        """Decode base64 string to bytes."""
        try:
            return b64decode(v)
        except Exception as exc:
            logger.error("Base64 decoding failed: %s", str(exc))
            raise ValueError("Invalid base64 encoding") from exc

app = FastAPI(
    title="TEE Secure Message Server",
    description="Server running in TEE that processes secure messages with AES ciphertext, keys, and signatures",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint that redirects to the API documentation."""
    logger.info("Root endpoint accessed, redirecting to docs")
    return RedirectResponse(url="/docs", status_code=307, headers={"Location": "/docs"})

@app.get("/public-key")
async def get_public_key():
    """Get the server's public key."""
    try:
        with open(key_manager.public_key_path, "rb") as f:
            public_key_data = f.read()
        logger.info("Public key retrieved successfully")
        return Response(content=public_key_data, media_type="application/x-pem-file")
    except Exception as exc:
        logger.error("Error retrieving public key: %s", str(exc))
        raise HTTPException(status_code=500, detail="Failed to retrieve public key") from exc

def extract_message_parts(plaintext: bytes, sensitive_indices: List[int], block_size: int) -> tuple[bytes, bytes]:
    """
    Extract sensitive and non-sensitive parts of the message based on block indices.

    Args:
        plaintext: The decrypted message bytes
        sensitive_indices: List of block indices that contain sensitive data
        block_size: Size of each block in bytes

    Returns:
        Tuple of (sensitive_part, non_sensitive_part) as bytes

    Raises:
        ValueError: If any block index is beyond the message length
    """
    # Validate block indices
    total_blocks = (len(plaintext) + block_size - 1) // block_size  # Ceiling division
    max_block_index = total_blocks - 1

    invalid_indices = [idx for idx in sensitive_indices if idx > max_block_index]
    if invalid_indices:
        raise ValueError(f"Invalid block indices: {invalid_indices}. Maximum valid index is {max_block_index}")

    # Sort indices to ensure we process blocks in order
    sorted_indices = sorted(sensitive_indices)

    # Initialize lists to store block indices
    sensitive_blocks = []
    non_sensitive_blocks = []

    # Distribute complete blocks into sensitive and non-sensitive
    for i in range(total_blocks):
        if i in sorted_indices:
            sensitive_blocks.append(i)
        else:
            non_sensitive_blocks.append(i)

    # Extract the actual data for each part
    sensitive_data = b''
    non_sensitive_data = b''

    # Process complete blocks
    for i in range(total_blocks):
        start = i * block_size
        end = min(start + block_size, len(plaintext))
        block_data = plaintext[start:end]
        if i in sensitive_blocks:
            sensitive_data += block_data
        else:
            non_sensitive_data += block_data

    return sensitive_data, non_sensitive_data

def extract_number(text: str):
    numbers = [
        int(float(num))
        for num in re.findall(r'\d+\.\d+|\d+', text)
    ]
    return numbers[0] if len(numbers) == 1 else numbers

@app.post("/process-secure-message")
async def process_secure_message(message: SecureMessage):
    """
    Process a secure message containing AES ciphertext, key, ECDSA signature, and sensitive block indices.

    Args:
        message: SecureMessage object containing encrypted data and metadata

    Returns:
        Dict with status "success" if processing is successful

    Raises:
        HTTPException: If signature verification fails, decryption fails, or block indices are invalid
    """
    request_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    logger.info("Processing secure message [request_id: %s]", request_id)

    try:
        # Log message details (excluding sensitive data)
        logger.info("Message details [request_id: %s]:", request_id)
        logger.info("- Ciphertext length: %d bytes", len(message.aes_ciphertext))
        logger.info("- Key length: %d bytes", len(message.aes_key))
        logger.info("- Signature length: %d bytes", len(message.ecdsa_signature))
        logger.info("- Number of sensitive blocks: %d", len(message.sensitive_blocks_indices))

        # Extract nonce and ciphertext
        nonce = message.aes_ciphertext[:12]
        ciphertext = message.aes_ciphertext[12:]
        logger.debug("Nonce and ciphertext extracted [request_id: %s]", request_id)

        # Calculate maximum block index based on ciphertext length
        # Subtract 12 bytes for the nonce and divide by block size
        max_block_index = (len(ciphertext) - 1) // BLOCK_SIZE
        logger.info("Maximum valid block index: %d [request_id: %s]", max_block_index, request_id)

        # Validate sensitive block indices
        invalid_indices = [
            idx for idx in message.sensitive_blocks_indices
            if idx > max_block_index
        ]
        if invalid_indices:
            logger.error(
                "Invalid sensitive block indices: %s [request_id: %s]",
                invalid_indices,
                request_id
            )
            logger.error("Block indices must be between 0 and %d", max_block_index)
            raise ValueError(
                f"Invalid sensitive block indices: {invalid_indices}. "
                f"Maximum valid index is {max_block_index}"
            )

        # Verify the signature
        data_to_verify = message.aes_ciphertext
        logger.info("Verifying signature [request_id: %s]", request_id)
        logger.info("- Data to verify length: %d bytes", len(data_to_verify))
        logger.info("- Signature length: %d bytes", len(message.ecdsa_signature))

        try:
            is_valid = key_manager.verify_signature(data_to_verify, message.ecdsa_signature)
            if not is_valid:
                logger.error("Signature verification failed - invalid signature [request_id: %s]", request_id)
                raise HTTPException(status_code=400, detail="Invalid signature")
            logger.info("Signature verification successful [request_id: %s]", request_id)
        except Exception as exc:
            logger.error("Signature verification error [request_id: %s]: %s", request_id, str(exc))
            raise HTTPException(status_code=400, detail="Invalid signature") from exc

        # Create AESGCM instance with the provided key
        aesgcm = AESGCM(message.aes_key)
        logger.debug("AESGCM instance created [request_id: %s]", request_id)

        # Decrypt the ciphertext
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            logger.info("Message successfully decrypted [request_id: %s]", request_id)
        except InvalidTag as exc:
            logger.error("Decryption failed - invalid ciphertext [request_id: %s]", request_id)
            raise HTTPException(status_code=400, detail="Invalid ciphertext") from exc
        except Exception as exc:
            logger.error("Decryption error [request_id: %s]: %s", request_id, str(exc))
            raise HTTPException(status_code=400, detail="Decryption failed") from exc

        # Extract and log sensitive and non-sensitive parts
        sensitive_part, non_sensitive_part = extract_message_parts(
            plaintext,
            message.sensitive_blocks_indices,
            BLOCK_SIZE
        )

        # Create the complete message with sensitive parts marked as asterisks
        complete_message = list(plaintext.decode('utf-8'))
        for idx in sorted(message.sensitive_blocks_indices):
            start_pos = idx * BLOCK_SIZE
            end_pos = min(start_pos + BLOCK_SIZE, len(complete_message))
            # Replace each character in the sensitive block with an asterisk
            complete_message[start_pos:end_pos] = ['*'] * (end_pos - start_pos)

        logger.info("Message parts [request_id: %s]:", request_id)
        logger.info("- Sensitive part length: %d bytes", len(sensitive_part))
        logger.info("- Non-sensitive part length: %d bytes", len(non_sensitive_part))
        logger.info("- Sensitive parts:")

        # Split sensitive part into blocks and log each one
        current_pos = 0
        value_for_nildb = None
        for idx in sorted(message.sensitive_blocks_indices):
            block_length = min(BLOCK_SIZE, len(plaintext) - idx * BLOCK_SIZE)
            block = sensitive_part[current_pos:current_pos + block_length].decode('utf-8')
            if "value" in block:
                value_for_nildb = extract_number(block)
            logger.info("  Block %d: %s", idx, block.replace('\n', ''))
            current_pos += block_length
        logger.info("- Complete message with sensitive parts: %s", ''.join(complete_message))

        logger.info("- Storing %s to nilDB.", value_for_nildb)
        record_ids = await upload_amazon_purchase(value_for_nildb)
        logger.info("- Stored value to nilDB with ID %s", record_ids)

        logger.info("Request completed successfully [request_id: %s]", request_id)
        return {"status": "success"}

    except HTTPException:
        raise
    except ValueError as exc:
        logger.error("Validation error [request_id: %s]: %s", request_id, str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("Error processing message [request_id: %s]: %s", request_id, str(exc))
        raise HTTPException(status_code=500, detail="Internal server error") from exc

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
