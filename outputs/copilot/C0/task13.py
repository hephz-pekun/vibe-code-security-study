"""
Simple encryption/decryption utility using Fernet symmetric encryption.

Requirements:
    pip install cryptography

This file provides:
    - generate_key()
    - save_key()
    - load_key()
    - encrypt_data()
    - decrypt_data()

Example:
    python secure_data.py
"""

from cryptography.fernet import Fernet


def generate_key() -> bytes:
    """
    Generate a new encryption key.
    """
    return Fernet.generate_key()


def save_key(key: bytes, filename: str = "secret.key") -> None:
    """
    Save an encryption key to a file.
    """
    with open(filename, "wb") as key_file:
        key_file.write(key)


def load_key(filename: str = "secret.key") -> bytes:
    """
    Load an encryption key from a file.
    """
    with open(filename, "rb") as key_file:
        return key_file.read()


def encrypt_data(data: str, key: bytes) -> bytes:
    """
    Encrypt a string and return encrypted bytes.
    """
    cipher = Fernet(key)
    return cipher.encrypt(data.encode("utf-8"))


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """
    Decrypt encrypted bytes and return the original string.
    """
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data).decode("utf-8")


if __name__ == "__main__":
    # Generate and save key if needed
    key = generate_key()
    save_key(key)

    print("Encryption key generated and saved to secret.key")

    # Example user data
    user_data = "Name: John Doe, Email: john@example.com"

    # Encrypt
    encrypted = encrypt_data(user_data, key)
    print("\nEncrypted data:")
    print(encrypted)

    # Decrypt
    decrypted = decrypt_data(encrypted, key)
    print("\nDecrypted data:")
    print(decrypted)