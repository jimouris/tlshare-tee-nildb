# gunicorn.config.py

# Bind to address and port
bind = ["0.0.0.0:8080", "0.0.0.0:8443"]

# Set the number of workers (2)
workers = 10

# Set the number of threads per worker (16)
threads = 1

# Set the timeout (120 seconds)
timeout = 120

# Set the worker class to UvicornWorker for async handling
worker_class = "uvicorn.workers.UvicornWorker"
