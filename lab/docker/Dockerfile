# Minimal image for the ARIADNE console and CLI.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install uv for fast, reproducible dependency resolution.
RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY rules ./rules
COPY scenarios ./scenarios

RUN uv pip install --system -e ".[ui]"

EXPOSE 8000
CMD ["ariadne", "console", "--host", "0.0.0.0", "--port", "8000"]
