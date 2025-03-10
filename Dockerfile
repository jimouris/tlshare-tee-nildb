FROM python:3.12-slim

COPY --link . /app/

WORKDIR /app/

RUN pip install uv && \
uv sync

EXPOSE 8080 8443

CMD uv run gunicorn -c gunicorn.conf.py server.server
