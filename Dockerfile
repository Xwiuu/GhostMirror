# GhostMirror — Internal Pentest Automation Platform
# Multi-purpose image: prints version on `docker compose up`, and can run the
# interactive CLI via `docker compose run --rm ghostmirror interactive`.

# Stage 1: Build Rust native engine
FROM rust:1.86-slim AS rust-builder
WORKDIR /rust
COPY ghostmirror-rs/ .
RUN cargo build --release && \
    cp target/release/ghostmirror-rs /usr/local/bin/ghostmirror-rs

# Stage 2: Python runtime
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    GHOSTMIRROR_HOME=/app

WORKDIR /app

# Install system dependencies (nmap, whatweb, curl, and weasyprint cairo/pango libraries)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whatweb \
    curl \
    ca-certificates \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libglib2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN curl -L -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.2.7/nuclei_3.2.7_linux_amd64.zip \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && apt-get purge -y --auto-remove unzip \
    && rm -rf /var/lib/apt/lists/* /tmp/nuclei.zip


# Install dependencies first to leverage Docker layer caching.
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the Rust binary from builder stage
COPY --from=rust-builder /usr/local/bin/ghostmirror-rs /usr/local/bin/ghostmirror-rs

# Copy the project and install it (provides the `ghostmirror` console script).
COPY . .
RUN pip install -e .

# Runtime data directories (also mounted as volumes via docker-compose).
RUN mkdir -p /app/projects /app/logs /app/reports /app/config

ENTRYPOINT ["ghostmirror"]
CMD ["version"]
