# tlshare-tee-nildb
Server (running on a TEE) that accepts requests from a client of a zkTLS connection and secret shares the data to nilDB.

```json
{
    "aes_ciphertext": "base64_encoded_bytes",
    "aes_key": "base64_encoded_bytes",
    "ecdsa_signature": "base64_encoded_bytes",
    "sensitive_blocks_indices": [1, 2, 3]
}
```

## Installation

This project uses `uv` for Python package management. To get started:

1. Install `uv` if you haven't already:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2. Create and activate a virtual environment:
```bash
uv venv
source .venv/bin/activate  # On Unix/macOS
```

3. Install dependencies:
```bash
uv pip install -e ".[dev]"  # For all development tools
```

## Development

### Testing

The project uses `pytest` for testing. First, make sure you have installed the package in development mode:

```bash
# Install test dependencies and the package in development mode
uv pip install -e ".[test]"
```

Then you can run the tests:

```bash
python -m pytest
```

The test suite includes:
- Unit tests for message processing
- Integration tests for the FastAPI server
- Tests for key management and encryption

### Linting

The project uses `pylint` for code linting. To run the linter:

```bash
uv pip install -e ".[lint]"
pylint src/
```

### Setup nilDB
After you get your nilDB credentials, copy `.env.sample` to `.env` and store your credentials.
Then, set up a new nilDB schema and query by running:
```bash
python -m src.nildb.nildb_operations
```

### Running the Server
To run the FastAPI server:
```bash
python -m src.server.server
```

The server will start on `http://0.0.0.0:8000`. You can:

- Access the API documentation at `http://localhost:8000/docs`
- Send POST requests to `http://localhost:8000/process-secure-message` with the message format shown above
- Use the interactive Swagger UI at `http://localhost:8000/docs` to test the API

### Running the Client

To run the client, use the following command:

```bash
python src/client/client.py [SERVER_URL]
```

- **`SERVER_URL`**: (Optional) The URL of the server. If not provided, the client defaults to `http://localhost:8000`.

### Example Usage

1. **Default (localhost)**:
   ```bash
   python src/client/client.py
   ```

2. **Custom Server URL**:
   ```bash
   python src/client/client.py http://example.com:8000
   ```

The client will send a secure message to the specified server URL.
