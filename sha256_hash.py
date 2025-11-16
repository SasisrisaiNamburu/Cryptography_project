import hashlib
import os
from typing import Tuple

def hash_password(password: str) -> Tuple[str, str]:
    """Return (salt_hex, hash_hex) for a given password."""
    salt = os.urandom(16)                # generate random 16-byte salt
    salted_password = salt + password.encode()
    hash_value = hashlib.sha256(salted_password).hexdigest()
    return salt.hex(), hash_value

def verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    salt = bytes.fromhex(salt_hex)
    salted_password = salt + password.encode()
    new_hash = hashlib.sha256(salted_password).hexdigest()
    return new_hash == stored_hash

if __name__ == "__main__":
    pwd = input("Enter a password to hash: ")

    # Create hash
    salt_hex, hashed = hash_password(pwd)
    print("\nSalt (hex):", salt_hex)
    print("SHA-256 Hash:", hashed)

    check = input("\nRe-enter password to verify: ")

    if verify_password(check, salt_hex, hashed):
        print("Password verified successfully.")
    else:
        print("Incorrect password.")
