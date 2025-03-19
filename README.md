# TLShare [![GitHub license](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/jimouris/tlshare-tee-nildb/blob/main/LICENSE)

## Secret Share Data from TLS Connections with Provenance

TLShare is a privacy-preserving solution that enables secure extraction and secret sharing of sensitive data from TLS connections.
It combines zkTLS (zero-knowledge TLS) with Trusted Execution Environments (TEE) to provide:
1. **Data Privacy**: Extracts and secret shares sensitive data (e.g., purchase amounts) while keeping the rest of the TLS traffic private. The secret shares are stored in [nilDB](https://docs.nillion.com/build/secret-vault).
2. **Data Provenance**: Ensures that the extracted data genuinely came from a specific TLS connection.
3. **Secure Processing**: Uses TEE to handle sensitive data securely and prevent tampering.

This repository contains the TEE server component that processes zkTLS client requests and handles the secure storage of extracted data.
We additionally provide a demo client that can be replaced by any zkTLS frontend implementation.

The server accepts a payload with multiple records in the following format:
```json
{
    "aes_key": "base64_encoded_bytes",
    "records": [
        {
            "aes_ciphertext": "base64_encoded_bytes",
            "aes_associated_data": "base64_encoded_bytes",
            "blocks_to_redact": [1, 2, 3],
            "blocks_to_extract": [2]
        },
    ],
    "ecdsa_signature": "base64_encoded_bytes",
    "is_test": false
}
```

Note: The `ecdsa_signature` is computed over the concatenation of all `aes_ciphertext` values in the records array.

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
Then, set up a new nilDB schema and query by running:
```shell
python -m src.nildb.nildb_operations
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
python -m src.client.client [SERVER_URL]
```

- **`SERVER_URL`**: (Optional) The URL of the server. If not provided, the client defaults to `http://localhost:8000`.

### Example Usage

1. **Default (localhost)**:
   ```shell
   python -m src.client.client
   ```

2. **Custom Server URL**:
   ```shell
   python -m src.client.client http://example.com:8000
   ```

The client will send a secure message with multiple records to the specified server URL. Each record in the example contains an Amazon purchase response, with sensitive blocks (like total amount) being redacted and extracted for storage in nilDB.

### Test Mode

You can set `is_test: true` in the payload to prevent the server from storing extracted values in nilDB. This is useful for testing and development.
