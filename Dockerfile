# ---------- Stage 1: Builder ----------
FROM python:3.12-slim AS builder

WORKDIR /app

# Install Python deps into a separate prefix (/install)
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt


# ---------- Stage 2: Runtime ----------
FROM python:3.12-slim

# Timezone MUST be UTC
ENV TZ=UTC

WORKDIR /app

# Install system dependencies: cron + tzdata
RUN apt-get update && \
    apt-get install -y --no-install-recommends cron tzdata && \
    rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy application code and keys into /app
COPY app ./app
COPY scripts ./scripts
COPY cron ./cron
COPY requirements.txt .
COPY student_private.pem .
COPY student_public.pem .
COPY instructor_public.pem .

# Setup cron: install crontab file
RUN chmod 0644 cron/2fa-cron && \
    crontab cron/2fa-cron

# Create volume mount points for seed and cron output
RUN mkdir -p /data /cron

# Document port
EXPOSE 8080

# Start cron daemon, then FastAPI server
CMD cron && uvicorn app.main:app --host 0.0.0.0 --port 8080
