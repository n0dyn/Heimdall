FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies. Upgrade first so a rebuilt image picks up
# fixed Debian packages instead of the base image's older copies.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    gcc \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies. The second install forces the fixed releases
# of packaging libraries Trivy flags. Then remove pip. Current pip releases
# vendor older setuptools, urllib3, and msgpack, and the API does not invoke
# pip at runtime.
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --upgrade \
        "setuptools>=84.2.1" \
        "certifi>=2026.10.19" \
        "wheel>=0.46.2" \
        "jaraco.context>=6.1.0" \
    && rm -rf /usr/local/lib/python3.11/site-packages/pip \
              /usr/local/lib/python3.11/site-packages/pip-*.dist-info \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.11

# Copy application code
COPY . .

# Create data directory for database persistence
RUN mkdir -p /app/data

# Make startup script executable
RUN chmod +x start.sh

# Expose ports
EXPOSE 8010 8501 5514/udp

# Use startup script
CMD ["./start.sh"]
