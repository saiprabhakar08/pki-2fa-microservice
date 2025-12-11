import base64
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Load student private key
with open("student_private.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

# Load instructor public key
with open("instructor_public.pem", "rb") as f:
    instructor_pub = load_pem_public_key(f.read())

# Get latest commit hash
commit_hash = (
    subprocess.check_output(["git", "log", "-1", "--format=%H"])
    .decode()
    .strip()
)

print("Commit Hash:", commit_hash)

# Convert commit hash to bytes
commit_bytes = commit_hash.encode()

# Sign commit hash using RSA-PSS + SHA256
signature = private_key.sign(
    commit_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)

# Encrypt signature with instructor public key
encrypted_signature = instructor_pub.encrypt(
    signature,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

# Base64 encode for submission
encoded_sig = base64.b64encode(encrypted_signature).decode()

print("\nEncrypted Commit Signature (Base64):")
print(encoded_sig)
