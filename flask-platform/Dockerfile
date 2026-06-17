FROM python:3.11-slim

WORKDIR /app

# wget is required by the docker-compose healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src/ ./src/

# Create platform data directory
RUN mkdir -p /platform-data

VOLUME ["/platform-data", "/flag-data"]

EXPOSE 5000

CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "src.app:create_app()"]
