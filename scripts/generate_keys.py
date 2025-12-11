import os
import sys

# Make parent directory (project root) importable
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.crypto_utils import generate_rsa_keypair, save_private_key_pem, save_public_key_pem


def main():
    private_key, public_key = generate_rsa_keypair()
    save_private_key_pem(private_key, "student_private.pem")
    save_public_key_pem(public_key, "student_public.pem")
    print("Generated student_private.pem and student_public.pem in repo root")


if __name__ == "__main__":
    main()
