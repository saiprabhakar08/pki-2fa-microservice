from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os

from app.crypto_utils import load_private_key, decrypt_seed
from app.totp_utils import generate_totp_code, verify_totp_code

app = FastAPI(title="PKI-based 2FA Microservice")

# ---------------- Paths ----------------
SEED_PATH = "/data/seed.txt"
STUDENT_PRIVATE_KEY_PATH = "/app/student_private.pem"


# ---------------- Models ----------------
class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str | None = None


# ---------------- Helpers ----------------
def get_seed():
    """Safely read seed from persistent storage."""
    if not os.path.exists(SEED_PATH):
        return None
    with open(SEED_PATH, "r") as f:
        return f.read().strip()


# ---------------- Endpoints ----------------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(payload: DecryptSeedRequest):
    """
    POST /decrypt-seed
    - Decrypt encrypted seed
    - Store at /data/seed.txt
    """
    try:
        private_key = load_private_key(STUDENT_PRIVATE_KEY_PATH)
        hex_seed = decrypt_seed(payload.encrypted_seed, private_key)

        os.makedirs("/data", exist_ok=True)
        with open(SEED_PATH, "w") as f:
            f.write(hex_seed)

        return {"status": "ok"}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Decryption failed", "detail": str(e)},
        )


@app.get("/generate-2fa")
def generate_2fa():
    """
    GET /generate-2fa
    - If seed missing: return error JSON (NOT crash)
    - Else: return TOTP code and validity
    """
    seed = get_seed()
    if seed is None:
        return {"error": "Seed not decrypted yet"}

    try:
        code, valid_for = generate_totp_code(seed)
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
    - 400 if code missing
    - 500 if seed missing
    - Return valid true/false
    """
    if not payload.code:
        raise HTTPException(status_code=400, detail="Missing code")

    seed = get_seed()
    if seed is None:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        valid = verify_totp_code(seed, payload.code, valid_window=1)
        return {"valid": bool(valid)}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Verification failed", "detail": str(e)},
        )
