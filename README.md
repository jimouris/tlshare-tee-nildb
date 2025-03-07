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

### Linting

The project uses `pylint` for code linting. To run the linter:

```bash
uv pip install -e ".[lint]"
pylint src/
```

### Running the Server

To run the FastAPI server:

```bash
python src/main.py
```

The server will start on `http://0.0.0.0:8000`. You can:

- Access the API documentation at `http://localhost:8000/docs`
- Send POST requests to `http://localhost:8000/process-secure-message` with the message format shown above
- Use the interactive Swagger UI at `http://localhost:8000/docs` to test the API

### Running the Client

To test the encryption and decryption flow, run the client in a separate terminal:

```bash
python src/client.py
```

The client will:
1. Generate a random AES key
2. Encrypt a sample message
3. Send the encrypted message and key to the server
4. Display the server's response with the decrypted message
