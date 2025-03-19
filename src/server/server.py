"""FastAPI server that processes secure messages with AES encryption and ECDSA signatures."""

import contextlib
import datetime
import re
from base64 import b64decode
from typing import List

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field, field_validator, ValidationInfo
from src.nildb.nildb_operations import upload_amazon_purchase

from src.config.key_management import KeyManager
from src.config.logging import logger

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
    logger.info("- POST /process-secure-message")

    yield

    # Shutdown
    logger.info("Server shutting down...")

class Record(BaseModel):
    """Model for a single record containing encrypted data and metadata."""
    aes_ciphertext: bytes = Field(..., description="Base64 encoded AES encrypted data")
    aes_associated_data: bytes = Field(..., description="Base64 encoded AES associated data")
    blocks_to_redact: List[int] = Field(..., description="List of indices for sensitive blocks")
    blocks_to_extract: List[int] = Field(default_factory=list, description="List of block indices to extract data from")

    @field_validator('blocks_to_extract')
    @classmethod
    def validate_blocks_to_extract(cls, v: List[int], info: ValidationInfo) -> List[int]:
        """Validate that blocks_to_extract is a subset of blocks_to_redact."""
        blocks_to_redact = info.data.get('blocks_to_redact', [])
        if not all(block in blocks_to_redact for block in v):
            raise ValueError("blocks_to_extract must be a subset of blocks_to_redact")
        return v

    @field_validator('aes_ciphertext', 'aes_associated_data', mode='before')
    @classmethod
    def decode_base64(cls, v: str) -> bytes:
        """Decode base64 string to bytes."""
        try:
            return b64decode(v)
        except Exception as exc:
            logger.error("Base64 decoding failed: %s", str(exc))
            raise ValueError("Invalid base64 encoding") from exc

class SecureMessage(BaseModel):
    """Model for secure message containing multiple records."""
    aes_key: bytes = Field(..., description="Base64 encoded AES key used for encryption")
    records: List[Record] = Field(..., description="List of records to process")
    ecdsa_signature: bytes = Field(..., description="Base64 encoded ECDSA signature for verification")
    is_test: bool = Field(False, description="Indicates if the message is a test")

    @field_validator('aes_key', 'ecdsa_signature', mode='before')
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

def redact_message(
    plaintext: bytes,
    blocks_to_redact: List[int],
    block_size: int
) -> tuple[bytes, bytes]:
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

    invalid_indices = [idx for idx in blocks_to_redact if idx > max_block_index]
    if invalid_indices:
        raise ValueError(f"Invalid block indices: {invalid_indices}. Maximum valid index is {max_block_index}")

    # Sort indices to ensure we process blocks in order
    sorted_indices = sorted(blocks_to_redact)

    # Initialize lists to store block indices
    blocks_to_redact = []
    non_blocks_to_redact = []

    # Distribute complete blocks into sensitive and non-sensitive
    for i in range(total_blocks):
        if i in sorted_indices:
            blocks_to_redact.append(i)
        else:
            non_blocks_to_redact.append(i)

    # Extract the actual data for each part
    sensitive_data = b''
    non_sensitive_data = b''

    # Process complete blocks
    for i in range(total_blocks):
        start = i * block_size
        end = min(start + block_size, len(plaintext))
        block_data = plaintext[start:end]
        if i in blocks_to_redact:
            sensitive_data += block_data
        else:
            non_sensitive_data += block_data

    return sensitive_data, non_sensitive_data

def extract_number(text: str):
    """Extract a number as an integer from a string."""
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
        # Verify the signature over concatenated ciphertexts
        concatenated_ciphertexts = b''.join(record.aes_ciphertext for record in message.records)
        logger.info("Verifying signature [request_id: %s]", request_id)
        logger.info("- Data to verify length: %d bytes", len(concatenated_ciphertexts))
        logger.info("- Signature length: %d bytes", len(message.ecdsa_signature))

        try:
            is_valid = key_manager.verify_signature(concatenated_ciphertexts, message.ecdsa_signature)
            if not is_valid:
                logger.error("Signature verification failed [request_id: %s]", request_id)
                raise HTTPException(status_code=400, detail="Invalid signature")
            logger.info("Signature verification successful [request_id: %s]", request_id)
        except Exception as exc:
            logger.error("Signature verification error [request_id: %s]: %s", request_id, str(exc))
            raise HTTPException(status_code=400, detail="Invalid signature") from exc

        # Create AESGCM instance with the provided key
        aesgcm = AESGCM(message.aes_key)
        logger.debug("AESGCM instance created [request_id: %s]", request_id)
        is_test = getattr(message, "is_test", False)  # Default to False if is_test is not provided

        # Process each record
        all_record_ids = []
        for i, record in enumerate(message.records):
            logger.info("Processing record %d [request_id: %s]", i, request_id)

            # Extract nonce and ciphertext
            nonce = record.aes_ciphertext[:12]
            ciphertext = record.aes_ciphertext[12:]

            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, record.aes_associated_data)
                logger.info("Message successfully decrypted [request_id: %s]", request_id)
            except InvalidTag as exc:
                logger.error("Decryption failed for record %d [request_id: %s]", i, request_id)
                raise HTTPException(status_code=400, detail=f"Invalid ciphertext in record {i}") from exc

            sensitive_part, non_sensitive_part = redact_message(
                plaintext,
                record.blocks_to_redact,
                BLOCK_SIZE
            )

            # Create the complete message with sensitive parts marked as asterisks
            complete_message = list(plaintext.decode('utf-8'))
            for idx in sorted(record.blocks_to_redact):
                start_pos = idx * BLOCK_SIZE
                end_pos = min(start_pos + BLOCK_SIZE, len(complete_message))
                # Replace each character in the sensitive block with an asterisk
                complete_message[start_pos:end_pos] = ['*'] * (end_pos - start_pos)

            logger.info("Message parts [request_id: %s]:", request_id)
            logger.info("- Sensitive part length: %d bytes", len(sensitive_part))
            logger.info("- Non-sensitive part length: %d bytes", len(non_sensitive_part))
            logger.info("- Sensitive parts:")

            # Process blocks and extract values
            current_pos = 0
            values_for_nildb = []
            for idx in sorted(record.blocks_to_redact):
                block_length = min(BLOCK_SIZE, len(plaintext) - idx * BLOCK_SIZE)
                block = sensitive_part[current_pos:current_pos + block_length].decode('utf-8')
                if idx in record.blocks_to_extract: # Check if the block is in blocks_to_extract
                    values_for_nildb.append(extract_number(block))
                logger.info("  Block %d: %s", idx, block.replace('\n', ''))
                current_pos += block_length
            logger.info("- Complete message with sensitive parts: %s", ''.join(complete_message))

            for value in values_for_nildb:
                if not isinstance(value, int):
                    raise ValueError(f"Value to store in nilDB is not an integer: {value}")

            # Store values in nildb if not a test
            if not is_test:
                logger.info("- Storing %s to nilDB.", values_for_nildb)
                record_ids = []
                for value in values_for_nildb:
                    record_ids.extend(await upload_amazon_purchase(value))
                all_record_ids.extend(record_ids)
                logger.info("- Stored values to nilDB with IDs %s", record_ids)
            else:
                logger.info("- Skipping nilDB storage (test mode).")

        if not is_test:
            logger.info("Stored all values to nilDB with IDs %s", all_record_ids)
        else:
            logger.info("Skipping nilDB storage (test mode)")

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
