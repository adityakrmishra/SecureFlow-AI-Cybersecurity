# Build stage
FROM python:3.9-slim-buster as builder

WORKDIR /app

# Install system build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libpq-dev \
    libpcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.9-slim-buster

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Install runtime system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libgomp1 \
    libpcap0.8 \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY . .

# Security hardening
RUN useradd -m -u 1001 secureflow && \
    chown -R secureflow:secureflow /app && \
    chmod 755 /app/scripts/*.sh

USER secureflow

# Environment configuration
ENV PATH=/root/.local/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]

# Start command with gunicorn
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", \
    "--bind", "0.0.0.0:8000", "src.backend.api.main:app"]
