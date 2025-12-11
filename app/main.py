from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os

from app.crypto_utils import load_private_key, decrypt_seed
from app.totp_utils import generate_totp_code, verify_totp_code

app = FastAPI(title="PKI-based 2FA Microservice")

# Paths inside container
SEED_PATH = (
    "/data/seed.txt" if os.path.exists("/data") else "seed.txt"
)

# If running inside Docker, /app/student_private.pem exists.
# If running locally, fallback to local file path.
DOCKER_KEY_PATH = "/app/student_private.pem"
LOCAL_KEY_PATH = "student_private.pem"

STUDENT_PRIVATE_KEY_PATH = (
    DOCKER_KEY_PATH if os.path.exists(DOCKER_KEY_PATH) else LOCAL_KEY_PATH
)


# ---------- Request models ----------

class DecryptSeedRequest(BaseModel):
    encrypted_seed: str  # base64-encoded ciphertext from instructor API


class VerifyRequest(BaseModel):
    code: str | None = None


# ---------- Helper to read seed from file ----------

def read_seed() -> str:
    if not os.path.exists(SEED_PATH):
        raise FileNotFoundError("Seed not decrypted yet")
    with open(SEED_PATH, "r") as f:
        return f.read().strip()


# ---------- Endpoints ----------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(payload: DecryptSeedRequest):
    """
    POST /decrypt-seed
    Body: { "encrypted_seed": "BASE64..." }

    - Load student private key
    - Decrypt encrypted seed using RSA/OAEP-SHA256
    - Validate 64-char hex
    - Save to /data/seed.txt
    - Return { "status": "ok" } or error 500
    """
    # Load private key
    try:
        private_key = load_private_key(STUDENT_PRIVATE_KEY_PATH)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Private key load failed", "detail": str(e)},
        )

    # Decrypt seed
    try:
        hex_seed = decrypt_seed(payload.encrypted_seed, private_key)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Decryption failed", "detail": str(e)},
        )

    # Save to /data/seed.txt
        # Save to /data/seed.txt (in Docker) or seed.txt (locally)
    try:
        dir_name = os.path.dirname(SEED_PATH)
        if dir_name:  # only create directory if path has a folder component
            os.makedirs(dir_name, exist_ok=True)

        with open(SEED_PATH, "w") as f:
            f.write(hex_seed)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Failed to store seed", "detail": str(e)},
        )

    return {"status": "ok"}


@app.get("/generate-2fa")
def generate_2fa():
    """
    GET /generate-2fa

    - Read seed from /data/seed.txt
    - Generate current TOTP code
    - Calculate valid_for seconds remaining
    - Return { "code": "123456", "valid_for": 30 }
    """
    try:
        hex_seed = read_seed()
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Seed not decrypted yet", "detail": str(e)},
        )

    try:
        code, valid_for = generate_totp_code(hex_seed)
        return {"code": code, "valid_for": valid_for}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Failed to generate TOTP", "detail": str(e)},
        )


@app.post("/verify-2fa")
def verify_2fa(payload: VerifyRequest):
    """
    POST /verify-2fa
    Body: { "code": "123456" }

    - Return 400 if code missing
    - Return 500 if seed missing
    - Verify code with ±1 time window
    - Return { "valid": true/false }
    """
    if not payload.code:
        raise HTTPException(
            status_code=400,
            detail={"error": "Missing code"},
        )

    try:
        hex_seed = read_seed()
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Seed not decrypted yet", "detail": str(e)},
        )

    try:
        valid = verify_totp_code(hex_seed, payload.code, valid_window=1)
        return {"valid": bool(valid)}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Verification failed", "detail": str(e)},
        )
