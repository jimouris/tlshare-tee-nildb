"""FastAPI server that processes secure messages with AES encryption and ECDSA signatures."""

import contextlib
import datetime
import json
import re
from base64 import b64decode
from typing import List, Literal

import jsonpath_ng
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import (BaseModel, ConfigDict, Field, ValidationError,
                      field_validator)

from src.config.key_management import KeyManager
from src.config.logging import logger
from src.nildb.nildb_operations import upload_to_nildb

# Initialize key manager
key_manager = KeyManager()


@contextlib.asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    """Lifespan context manager for FastAPI application."""
    # Startup
    logger.info("Starting up server...")
    fastapi_app.state.startup_time = datetime.datetime.now()
    yield
    # Shutdown
    uptime = datetime.datetime.now() - fastapi_app.state.startup_time
    logger.info("Shutting down server after %s uptime", uptime)


class JsonPattern(BaseModel):
    """Pattern for JSON operations (both redaction and extraction)."""

    pattern_type: Literal["json"] = Field(..., description="Type of pattern")
    path: str = Field(..., description="JSONPath expression to locate the data")
    data_type: Literal["string", "number"] = Field(
        "number", description="Type of data (string/number)"
    )
    should_extract: bool = Field(
        False, description="Whether to extract this value for nilDB storage."
    )
    include_children: bool = Field(
        False, description="Whether to include nested fields."
    )
    preserve_keys: bool = Field(True, description="Whether to preserve JSON keys.")
    origin: str = Field(
        "unknown", description="Origin of the data (e.g., amazon, tiktok)"
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("data_type")
    @classmethod
    def validate_data_type(cls, v: str) -> str:
        """Validate data type is either string or number."""
        if v not in ["string", "number"]:
            raise ValidationError("data_type must be either 'string' or 'number'")
        return v


class Record(BaseModel):
    """Model for a single record containing encrypted data and metadata."""

    aes_ciphertext: bytes = Field(..., description="Base64 encoded AES encrypted data")
    aes_associated_data: bytes = Field(
        ..., description="Base64 encoded AES associated data"
    )
    patterns: List[JsonPattern] = Field(
        ..., description="List of patterns for redaction and extraction"
    )

    @field_validator("aes_ciphertext", "aes_associated_data", mode="before")
    @classmethod
    def decode_base64(cls, v: str) -> bytes:
        """Decode base64 string to bytes."""
        try:
            return b64decode(v)
        except (ValueError, TypeError) as exc:
            logger.error("Base64 decoding failed: %s", str(exc))
            raise ValueError("Invalid base64 encoding") from exc

    @field_validator("patterns", mode="before")
    @classmethod
    def validate_patterns(cls, v: List[dict]) -> List[dict]:
        """Validate patterns and convert validation errors to 400 status code."""
        try:
            # First validate that each pattern has a pattern_type
            for pattern in v:
                if not isinstance(pattern, dict):
                    raise HTTPException(
                        status_code=400, detail="Pattern must be a dictionary"
                    )
                if "pattern_type" not in pattern:
                    raise HTTPException(
                        status_code=400, detail="Pattern must have a pattern_type"
                    )
                if pattern["pattern_type"] != "json":
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid pattern type: {pattern['pattern_type']}. Must be 'json'.",
                    )
            return v
        except HTTPException as exc:
            # Re-raise HTTPException without wrapping
            raise exc
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


def extract_json_from_http_response(data: str) -> str:
    """Extract JSON body from HTTP response.

    Args:
        data: The HTTP response containing JSON

    Returns:
        str: The JSON body
    """
    try:
        # Find the first occurrence of '{'
        start = data.find("{")
        if start == -1:
            return data

        # Find the matching closing brace
        count = 1
        for i in range(start + 1, len(data)):
            if data[i] == "{":
                count += 1
            elif data[i] == "}":
                count -= 1
                if count == 0:
                    return data[start : i + 1]
        return data
    except (ValueError, IndexError) as exc:
        logger.error("Failed to extract JSON from HTTP response: %s", str(exc))
        return data


def apply_pattern(
    data: str, pattern: JsonPattern
) -> tuple[str, List[int], str | int | None]:
    """Apply a pattern to the data and return the redacted data and extracted value.

    Args:
        data: The data to process
        pattern: The pattern to apply

    Returns:
        Tuple of (processed_data, empty list for compatibility, extracted value)
    """
    try:
        # Extract JSON from HTTP response if needed
        json_str = extract_json_from_http_response(data)
        json_start = data.find(json_str)
        json_end = json_start + len(json_str)

        # Parse the data as JSON
        try:
            json_data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse JSON: %s", str(exc))
            return data, [], None

        # Find the JSON path
        jsonpath_expr = jsonpath_ng.parse(pattern.path)
        matches = jsonpath_expr.find(json_data)

        if not matches:
            logger.warning("No matches found for path: %s", pattern.path)
            return data, [], None

        # Extract value before redacting (only if should_extract is True)
        extracted_value = None
        if pattern.should_extract:
            match = matches[0]  # Take first match for extraction
            try:
                if pattern.data_type == "number":
                    # Handle both string numbers and actual numbers
                    if isinstance(match.value, (int, float)):
                        extracted_value = int(match.value)
                    else:
                        extracted_value = int(float(str(match.value).strip()))
                else:
                    extracted_value = str(match.value)
            except (ValueError, TypeError) as exc:
                logger.error("Failed to extract value: %s", str(exc))

        # Redact values while preserving structure
        for match in matches:
            if pattern.include_children:
                # If include_children is True, redact all nested values
                if isinstance(match.value, dict):
                    for key in match.value:
                        match.value[key] = "****"
                elif isinstance(match.value, list):
                    match.value[:] = ["****"] * len(match.value)
                else:
                    match.full_path.update(json_data, "****")
            else:
                # If include_children is False (default)
                if isinstance(match.value, dict):
                    if pattern.preserve_keys:
                        # Create a new dict with redacted values
                        redacted_dict = {key: "****" for key in match.value}
                        match.full_path.update(json_data, redacted_dict)
                    else:
                        match.full_path.update(json_data, "****")
                else:
                    match.full_path.update(json_data, "****")

        # Replace the JSON in the original data
        redacted_json = json.dumps(json_data, indent=2)
        redacted_data = data[:json_start] + redacted_json + data[json_end:]

        return redacted_data, [], extracted_value

    except (ValueError, TypeError, AttributeError) as exc:
        logger.error("Error applying pattern: %s", str(exc))
        return data, [], None


def redact_message(
    plaintext: bytes,
    patterns: List[JsonPattern],
    *,  # Force keyword arguments after this
    _legacy_block_size: int | None = None,  # For backward compatibility
) -> tuple[bytes, bytes, List[int | str]]:
    """
    Apply patterns to the message and return sensitive and non-sensitive parts, plus extracted values.

    Args:
        plaintext: The decrypted message bytes
        patterns: List of patterns for redaction and extraction
        _legacy_block_size: Ignored, kept for backward compatibility

    Returns:
        Tuple of (sensitive_part, non_sensitive_part, extracted_values) as (bytes, bytes, list)
    """
    # Convert bytes to string for processing
    data = plaintext.decode("utf-8")
    extracted_values = []
    redacted_data = data

    # Apply each pattern
    for pattern in patterns:
        try:
            new_data, _, extracted_value = apply_pattern(redacted_data, pattern)
            if (
                new_data != redacted_data
            ):  # Only update if the pattern changed something
                redacted_data = new_data
            if extracted_value is not None:
                extracted_values.append(extracted_value)
        except (ValueError, TypeError) as exc:
            logger.error("Error applying pattern: %s", str(exc))
            continue

    return plaintext, redacted_data.encode(), extracted_values


class SecureMessage(BaseModel):
    """Model for secure message containing multiple records."""

    aes_key: bytes = Field(
        ..., description="Base64 encoded AES key used for encryption"
    )
    records: List[Record] = Field(..., description="List of records to process")
    ecdsa_signature: bytes = Field(
        ..., description="Base64 encoded ECDSA signature for verification"
    )
    is_test: bool = Field(False, description="Indicates if the message is a test")

    @field_validator("aes_key", "ecdsa_signature", mode="before")
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
    openapi_url="/openapi.json",
)


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint that redirects to the API documentation."""
    logger.info("Root endpoint accessed, redirecting to docs")
    return RedirectResponse(url="/docs", status_code=307, headers={"Location": "/docs"})


def extract_number(text: str):
    """Extract a number as an integer from a string."""
    numbers = [int(float(num)) for num in re.findall(r"\d+\.\d+|\d+", text)]
    return numbers[0] if len(numbers) == 1 else numbers


def extract_data(text: str, rule: JsonPattern) -> str | int | None:
    """Extract data according to the extraction rule."""
    try:
        # Extract JSON from HTTP response first
        json_str = extract_json_from_http_response(text)
        json_data = json.loads(json_str)

        extracted_value = None
        matches = jsonpath_ng.parse(rule.path).find(json_data)
        if matches:
            match = matches[0]
            if isinstance(match.value, (int, float)):
                extracted_value = int(match.value)
            elif isinstance(match.value, str):
                extracted_value = (
                    int(float(match.value))
                    if rule.data_type == "number"
                    else match.value
                )
        return extracted_value
    except (ValueError, TypeError, json.JSONDecodeError, AttributeError) as exc:
        logger.error("Failed to extract JSON value: %s", str(exc))
        return None


@app.post("/process-secure-message")
async def process_secure_message(message: SecureMessage):
    """
    Process a secure message containing AES ciphertext, key, ECDSA signature, and patterns.

    Args:
        message: SecureMessage object containing encrypted data and metadata

    Returns:
        Dict containing:
        - status: "success" if processing is successful
        - redacted_messages: List of redacted messages (sensitive parts replaced with ****)
        - extracted_values: List of values extracted and stored in nilDB
        - record_ids: List of nilDB record IDs where values were stored (if not in test mode)

    Raises:
        HTTPException: If signature verification fails, decryption fails, or patterns are invalid
    """
    request_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    logger.info("Processing secure message [request_id: %s]", request_id)

    try:
        # Verify the signature over concatenated ciphertexts
        concatenated_ciphertexts = b"".join(
            record.aes_ciphertext for record in message.records
        )
        logger.info("Verifying signature [request_id: %s]", request_id)
        logger.info("- Data to verify length: %d bytes", len(concatenated_ciphertexts))
        logger.info("- Signature length: %d bytes", len(message.ecdsa_signature))

        try:
            is_valid = key_manager.verify_signature(
                concatenated_ciphertexts, message.ecdsa_signature
            )
            if not is_valid:
                logger.error(
                    "Signature verification failed [request_id: %s]", request_id
                )
                raise HTTPException(status_code=400, detail="Invalid signature")
            logger.info(
                "Signature verification successful [request_id: %s]", request_id
            )
        except (ValueError, TypeError, InvalidTag) as exc:
            logger.error(
                "Signature verification error [request_id: %s]: %s",
                request_id,
                str(exc),
            )
            raise HTTPException(status_code=400, detail="Invalid signature") from exc

        # Create AESGCM instance with the provided key
        aesgcm = AESGCM(message.aes_key)
        logger.debug("AESGCM instance created [request_id: %s]", request_id)
        is_test = getattr(
            message, "is_test", False
        )  # Default to False if is_test is not provided

        # Process each record
        all_record_ids = []
        all_redacted_messages = []
        all_extracted_values = []

        for i, record in enumerate(message.records):
            logger.info("Processing record %d [request_id: %s]", i, request_id)

            # Extract nonce and ciphertext
            nonce = record.aes_ciphertext[:12]
            ciphertext = record.aes_ciphertext[12:]

            try:
                plaintext = aesgcm.decrypt(
                    nonce, ciphertext, record.aes_associated_data
                )
                logger.info(
                    "Message successfully decrypted [request_id: %s]", request_id
                )
            except InvalidTag as exc:
                logger.error(
                    "Decryption failed for record %d [request_id: %s]", i, request_id
                )
                raise HTTPException(
                    status_code=400, detail=f"Invalid ciphertext in record {i}"
                ) from exc

            # Apply patterns and get sensitive/non-sensitive parts
            sensitive_part, non_sensitive_part, extracted_values = redact_message(
                plaintext, record.patterns
            )

            logger.info("Message parts [request_id: %s]:", request_id)
            logger.info("- Sensitive part length: %d bytes", len(sensitive_part))
            logger.info(
                "- Non-sensitive part length: %d bytes", len(non_sensitive_part)
            )
            logger.info("- Extracted values: %s", extracted_values)

            # Store the redacted message
            try:
                all_redacted_messages.append(non_sensitive_part.decode("utf-8"))
                logger.info("Redacted message for record %d:", i)
                logger.info(non_sensitive_part.decode("utf-8"))
            except (UnicodeDecodeError, AttributeError) as exc:
                logger.error("Error creating redacted message: %s", str(exc))
                all_redacted_messages.append("<error creating redacted message>")

            # Process and extract values - use the original plaintext for extraction
            values_for_nildb = []
            original_text = plaintext.decode("utf-8")
            last_origin = "unknown"  # Default origin if no extractable pattern is found
            for rule in record.patterns:
                if rule.should_extract:
                    extracted_value = extract_data(original_text, rule)
                    if extracted_value is not None:  # Changed from if extracted_value to handle 0 values
                        values_for_nildb.append(extracted_value)
                        last_origin = rule.origin  # Store the origin from the last extractable pattern

            all_extracted_values.extend(values_for_nildb)

            # Validate extracted values
            for value in values_for_nildb:
                if not isinstance(value, (int, str)):
                    raise ValueError(
                        f"Value to store in nilDB must be an integer or string: {value}"
                    )

            # Store values in nildb if not a test
            if not is_test:
                logger.info("- Storing %s to nilDB.", values_for_nildb)
                record_ids = []
                for value in values_for_nildb:
                    record_ids.extend(await upload_to_nildb(value, last_origin))
                all_record_ids.extend(record_ids)
                logger.info("- Stored values to nilDB with IDs %s", record_ids)
            else:
                logger.info("- Skipping nilDB storage (test mode).")

        if not is_test:
            logger.info("Stored all values to nilDB with IDs %s", all_record_ids)
        else:
            logger.info("Skipping nilDB storage (test mode)")

        return {
            "status": "success",
            "redacted_messages": all_redacted_messages,
            "extracted_values": all_extracted_values,
            "record_ids": all_record_ids if not is_test else None,
        }

    except HTTPException:
        raise
    except ValueError as exc:
        logger.error("Validation error [request_id: %s]: %s", request_id, str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.error(
            "Error processing message [request_id: %s]: %s", request_id, str(exc)
        )
        raise HTTPException(status_code=500, detail="Internal server error") from exc


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
