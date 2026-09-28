# REDRECON-X Dockerfile (Kali / Debian Security Base)
FROM python:3.12-slim-bookworm

LABEL maintainer="REDRECON-X Team"
LABEL description="Automated Web Reconnaissance & Attack-Surface Intelligence Framework"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install core system dependencies, Nmap, and network diagnostic tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    curl \
    git \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei binary
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then NUCLEI_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then NUCLEI_ARCH="arm64"; \
    else NUCLEI_ARCH="amd64"; fi && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_${NUCLEI_ARCH}.zip && \
    unzip nuclei_3.2.9_linux_${NUCLEI_ARCH}.zip -d /usr/local/bin && \
    rm nuclei_3.2.9_linux_${NUCLEI_ARCH}.zip && \
    chmod +x /usr/local/bin/nuclei

WORKDIR /app

# Copy dependency definitions and install
COPY requirements.txt setup.py pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

# Copy application source
COPY . .

# Create output volume mount
VOLUME ["/app/reports"]

EXPOSE 8000

ENTRYPOINT ["redrecon"]
CMD ["--help"]
