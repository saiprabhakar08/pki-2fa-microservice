#!/usr/bin/env python3

import os
from datetime import datetime, timezone

# Allow imports from project root
import sys
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.totp_utils import generate_totp_code

# Use /data/seed.txt in Docker, fall back to local seed.txt when running directly
DOCKER_SEED_PATH = "/data/seed.txt"
LOCAL_SEED_PATH = "seed.txt"

SEED_PATH = DOCKER_SEED_PATH if os.path.exists(DOCKER_SEED_PATH) else LOCAL_SEED_PATH


def read_seed_or_none() -> str | None:
    if not os.path.exists(SEED_PATH):
        return None
    with open(SEED_PATH, "r") as f:
        return f.read().strip()


def main():
    # Always use UTC time
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    seed = read_seed_or_none()
    if not seed:
        print(f"{now_utc} - Seed not available")
        return

    try:
        code, _ = generate_totp_code(seed)
        print(f"{now_utc} - 2FA Code: {code}")
    except Exception as e:
        print(f"{now_utc} - Error generating TOTP: {e}")


if __name__ == "__main__":
    main()
