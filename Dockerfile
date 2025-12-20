# ---------- Stage 1: Builder ----------
FROM python:3.12-slim AS builder

WORKDIR /app

# Install Python dependencies into /install
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt


# ---------- Stage 2: Runtime ----------
FROM python:3.12-slim

# Timezone MUST be UTC
ENV TZ=UTC

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends cron tzdata && \
    rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code and keys
COPY app ./app
COPY scripts ./scripts
COPY cron ./cron
COPY student_private.pem .
COPY student_public.pem .
COPY instructor_public.pem .

# Setup cron job
RUN chmod 0644 cron/2fa-cron && \
    crontab cron/2fa-cron

# Create persistent directories
RUN mkdir -p /data /cron

# Expose API port
EXPOSE 8080

# --------------------------------------------------
# IMPORTANT: keep container alive
# - cron runs in background
# - uvicorn runs in foreground
# --------------------------------------------------
CMD ["sh", "-c", "cron && uvicorn app.main:app --host 0.0.0.0 --port 8080"]
