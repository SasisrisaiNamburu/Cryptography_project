from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

def pad(data: bytes) -> bytes:
    """PKCS7 padding"""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding"""
    pad_len = data[-1]
    return data[:-pad_len]

def generate_key() -> bytes:
    """Generate a 256-bit (32-byte) AES key"""
    return get_random_bytes(32)

def encrypt_message(key: bytes, plaintext: str) -> str:
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext.encode()))
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(key: bytes, encrypted_b64: str) -> str:
    encrypted = base64.b64decode(encrypted_b64)
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext.decode()

if __name__ == "__main__":
    print("\n=== AES Encryption & Decryption ===\n")

    # Step 1: Generate AES key
    key = generate_key()
    print("Generated AES Key (Base64):", base64.b64encode(key).decode())

    # Step 2: Get message from user
    msg = input("\nEnter text to encrypt: ")

    # Step 3: Encrypt
    encrypted = encrypt_message(key, msg)
    print("\nEncrypted (Base64):", encrypted)

    # Step 4: Decrypt
    decrypted = decrypt_message(key, encrypted)
    print("\nDecrypted Text:", decrypted)
