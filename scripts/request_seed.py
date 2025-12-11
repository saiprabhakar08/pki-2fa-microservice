import os
import sys
import requests


# === TODO: FILL THESE WITH YOUR REAL VALUES ===
STUDENT_ID = "23MH5A0516"
GITHUB_REPO_URL = "https://github.com/saiprabhakar08/pki-2fa-microservice"
# ==============================================

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
STUDENT_PUBLIC_KEY_PATH = "student_public.pem"
ENCRYPTED_SEED_OUTPUT = "encrypted_seed.txt"


def read_public_key_pem(path: str) -> str:
    with open(path, "r") as f:
        return f.read()


def request_seed():
    if STUDENT_ID == "YOUR_STUDENT_ID_HERE":
        raise RuntimeError("Please set STUDENT_ID in scripts/request_seed.py")
    if "your-username" in GITHUB_REPO_URL:
        raise RuntimeError("Please set GITHUB_REPO_URL in scripts/request_seed.py")

    public_key_pem = read_public_key_pem(STUDENT_PUBLIC_KEY_PATH)

    payload = {
        "student_id": STUDENT_ID,
        "github_repo_url": GITHUB_REPO_URL,
        "public_key": public_key_pem,
    }

    print("Sending request to instructor API...")
    resp = requests.post(API_URL, json=payload, timeout=20)
    print("Status code:", resp.status_code)
    resp.raise_for_status()

    data = resp.json()
    print("Response:", data)

    if data.get("status") != "success":
        raise RuntimeError(f"Instructor API error: {data}")

    encrypted_seed = data["encrypted_seed"]

    with open(ENCRYPTED_SEED_OUTPUT, "w") as f:
        f.write(encrypted_seed)

    print(f"Encrypted seed saved to {ENCRYPTED_SEED_OUTPUT}")


if __name__ == "__main__":
    request_seed()
