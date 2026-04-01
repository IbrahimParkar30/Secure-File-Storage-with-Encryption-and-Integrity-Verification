"""
encryption.py
Handles AES-256 encryption and decryption of files using PyCryptodome.
Key is stored in a local key file (aes.key) generated once on first run.
"""

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

KEY_FILE = "aes.key"


def load_or_generate_key() -> bytes:
    """
    Load the AES-256 key from file, or generate and save a new one.
    Returns a 32-byte key suitable for AES-256.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key
    # Generate a fresh 256-bit (32-byte) key
    key = get_random_bytes(32)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print(f"[encryption] New AES-256 key generated and saved to '{KEY_FILE}'.")
    return key


def encrypt_file(input_path: str, output_path: str) -> None:
    """
    Encrypt the file at input_path using AES-256 CBC mode.
    The IV (16 bytes) is prepended to the ciphertext in the output file.

    Args:
        input_path  : Path to the plaintext file to encrypt.
        output_path : Destination path for the encrypted output file.
    """
    key = load_or_generate_key()

    # Read source file
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Create cipher with a fresh random IV each time
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Write IV + ciphertext so decryption can recover the IV
    with open(output_path, "wb") as f:
        f.write(cipher.iv)       # 16 bytes IV
        f.write(ciphertext)

    print(f"[encryption] File encrypted → {output_path}")


def decrypt_file(input_path: str, output_path: str) -> None:
    """
    Decrypt the AES-256 CBC encrypted file at input_path.
    Reads the prepended IV, then decrypts and removes PKCS7 padding.

    Args:
        input_path  : Path to the encrypted file (IV + ciphertext).
        output_path : Destination path for the decrypted plaintext file.
    """
    key = load_or_generate_key()

    with open(input_path, "rb") as f:
        iv         = f.read(16)          # First 16 bytes are the IV
        ciphertext = f.read()

    cipher    = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[encryption] File decrypted → {output_path}")
