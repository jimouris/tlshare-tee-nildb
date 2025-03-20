# TLShare [![GitHub license](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/jimouris/tlshare-tee-nildb/blob/main/LICENSE)

## Secret Share Data from TLS Connections with Provenance

TLShare is a privacy-preserving solution that enables secure extraction and secret sharing of sensitive data from TLS connections.
It combines zkTLS (zero-knowledge TLS) with Trusted Execution Environments (TEE) to provide:
1. **Data Privacy**: Extracts and secret shares sensitive data (e.g., purchase amounts) while keeping the rest of the TLS traffic private. The secret shares are stored in [nilDB](https://docs.nillion.com/build/secret-vault).
2. **Data Provenance**: Ensures that the extracted data genuinely came from a specific TLS connection.
3. **Secure Processing**: Uses TEE to handle sensitive data securely and prevent tampering.

This repository contains the TEE server component that processes zkTLS client requests and handles the secure storage of extracted data.
We additionally provide a demo client that can be replaced by any zkTLS frontend implementation.

## API Specification

The server accepts a payload in the following format:
```json5
{
    // Base64 encoded AES-256 key used for encryption
    "aes_key": "base64_encoded_bytes",

    // Origin of the data (e.g., "amazon", "tiktok") - used for provenance
    "origin": "amazon",

    // Array of patterns for redaction and extraction
    "patterns": [
        {
            // Type of pattern - must be "json"
            "pattern_type": "json",

            // JSONPath expression to locate the data (e.g., "$.total_amount")
            "path": "$.total_amount",

            // Type of data to extract - "string" or "number" (defaults to "number")
            "data_type": "number",

            // Whether to extract this value for nilDB storage
            "should_extract": true,

            // Whether to include nested fields in redaction
            "include_children": false,

            // Whether to preserve JSON keys during redaction
            "preserve_keys": true
        }
    ],

    // Array of TLS record fragments to process
    "fragments": [
        {
            // Base64 encoded AES-GCM encrypted data (includes 12-byte nonce)
            "aes_ciphertext": "base64_encoded_bytes",

            // Base64 encoded associated data for AES-GCM
            "aes_associated_data": "base64_encoded_bytes"
        }
    ],

    // Base64 encoded ECDSA signature over concatenated ciphertexts
    "ecdsa_signature": "base64_encoded_bytes",

    // If true, values won't be stored in nilDB (for testing)
    "is_test": false
}
```

### Response Format

A successful response will have this structure:
```json5
{
    // Always "success" for successful requests
    "status": "success",

    // The redacted message (sensitive parts replaced with ****)
    "redacted_message": "redacted message content",

    // Array of extracted values (only present if should_extract was true)
    "extracted_values": [123],

    // Array of nilDB record IDs (null if is_test was true)
    "record_ids": ["nildb-record-id"]
}
```

### Error Handling

The API returns appropriate HTTP status codes:
- `400`: For invalid requests (bad signature, invalid pattern type, etc.)
- `422`: For validation errors in the request payload
- `500`: For internal server errors

Note: The `ecdsa_signature` is computed over the concatenation of all `aes_ciphertext` values in the records array.

## Key Generation

Before running the client or server, you need to generate ECDSA keys for signing and verifying messages:

```shell
python -m src.config.key_management
```

This will:
1. Create a `keys` directory if it doesn't exist
2. Generate a new ECDSA key pair
3. Save the private key to `keys/private_key.pem`
4. Save the public key to `keys/public_key.pem`

## Installation

This project uses `uv` for Python package management. To get started:

1. Install `uv` if you haven't already:
```shell
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2. Create and activate a virtual environment:
```shell
uv venv
source .venv/bin/activate  # On Unix/macOS
```

3. Install dependencies:
```shell
uv pip install -e ".[dev]"  # For all development tools
```

## Development

### Testing

The project uses `pytest` for testing. First, make sure you have installed the package in development mode:

```shell
# Install test dependencies and the package in development mode
uv pip install -e ".[test]"
```

Then you can run the tests:

```shell
python -m pytest
```

The test suite includes:
- Unit tests for message processing
- Integration tests for the FastAPI server
- Tests for key management and encryption
- Tests for handling multiple records in a single request
- Tests for signature verification over concatenated ciphertexts

### Linting

The project uses `pylint` for code linting. To run the linter:

```shell
uv pip install -e ".[lint]"
pylint src/
```

### Setup nilDB
After you get your nilDB credentials, copy `.env.sample` to `.env` and store your credentials.

The nilDB operations script provides two main operations:

1. Create schema and query:
```shell
python -m src.nildb.nildb_operations --create
```
This will:
- Create a new schema for storing data with provenance
- Create a new sum query that supports filtering by origin
- Print the new IDs that need to be stored in your `.env` file

2. Execute sum query:
```shell
# Query all data
python -m src.nildb.nildb_operations --query

# Query data from specific origin
python -m src.nildb.nildb_operations --query amazon
```

The sum query supports:
- Filtering by origin (e.g., "amazon", "tiktok")
- Using "*" to query all data (default)
- Returns both the sum and count of records for the specified origin

For help with the commands:
```shell
python -m src.nildb.nildb_operations -h
```

### Running the Server
To run the FastAPI server:
```shell
python -m src.server.server
```

The server will start on `http://0.0.0.0:8000`. You can:

- Access the API documentation at `http://localhost:8000/docs`
- Send POST requests to `http://localhost:8000/process-secure-message` with the message format shown above
- Use the interactive Swagger UI at `http://localhost:8000/docs` to test the API

### Running the Client

To run the client, use the following command:

```shell
python -m src.client.client [OPTIONS]
```

Available options:
- `--server-url`: The URL of the server (default: http://localhost:8000)
- `--example`: The example to run (default: amazon). Available examples: toy, amazon, tiktok

### Example Usage

1. **Default (amazon example)**:
   ```shell
   python -m src.client.client
   ```

2. **Run specific example**:
   ```shell
   # Run toy example
   python -m src.client.client --example toy

   # Run amazon example
   python -m src.client.client --example amazon

   # Run tiktok example
   python -m src.client.client --example tiktok
   ```

3. **Custom Server URL**:
   ```shell
   python -m src.client.client --server-url http://example.com:8000 --example toy
   ```

The client will send a secure message to the specified server URL. Each example demonstrates different patterns:

- **Toy Example**: Simple example with a single value extraction
- **Amazon Example**: Purchase response with total amount extraction and redaction of sensitive fields
- **TikTok Example**: Coins balance extraction and redaction of redeem info

### Test Mode

You can set `is_test: true` in the payload to prevent the server from storing extracted values in nilDB. This is useful for testing and development.