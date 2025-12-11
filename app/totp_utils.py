import base64
import binascii
import time

import pyotp


def hex_to_base32(hex_seed: str) -> str:
    """
    Convert 64-char hex seed to base32 string (for TOTP libraries).
    """
    # hex -> raw bytes
    raw = binascii.unhexlify(hex_seed)
    # bytes -> base32 string
    return base64.b32encode(raw).decode("ascii")


def generate_totp_code(hex_seed: str) -> tuple[str, int]:
    """
    Generate current 6-digit TOTP code and seconds remaining in current 30s window.

    Returns:
        (code, valid_for_seconds)
    """
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)  # SHA-1 default

    code = totp.now()

    # how many seconds left in this 30s period
    now = int(time.time())
    valid_for = 30 - (now % 30)

    return code, valid_for


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with ±valid_window periods tolerance (default ±30s).
    """
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)
