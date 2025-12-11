from typing import Tuple
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import base64
import string



def generate_rsa_keypair(key_size: int = 4096) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate RSA key pair (4096-bit, e=65537) and return key objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key_pem(private_key, path: str):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_public_key_pem(public_key, path: str):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path: str):
    """
    Load RSA private key from PEM file.
    """
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )


def load_public_key(path: str):
    """
    Load RSA public key from PEM file.
    """
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP + SHA-256.

    Returns:
        64-character hex seed string
    """
    # 1. Base64 decode
    ciphertext = base64.b64decode(encrypted_seed_b64)

    # 2. RSA/OAEP decrypt with SHA-256, MGF1(SHA-256), label=None
    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Decode to UTF-8 string
    seed = plaintext_bytes.decode("utf-8").strip()

    # 4. Validate 64-char hex
    if len(seed) != 64:
        raise ValueError(f"Seed must be 64 hex chars, got length {len(seed)}")

    allowed = set(string.hexdigits.lower())
    if any(c.lower() not in allowed for c in seed):
        raise ValueError("Seed contains non-hex characters")

    return seed


def sign_message(message: str, private_key) -> bytes:
    """
    Sign commit hash (ASCII string) using RSA-PSS with SHA-256 and max salt length.
    """
    message_bytes = message.encode("utf-8")
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt data using RSA/OAEP with SHA-256 and MGF1(SHA-256).
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext
