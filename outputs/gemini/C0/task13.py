"""
Secure User Data Encryption & Decryption Utility

Uses the industry-standard `cryptography` library (Fernet symmetric encryption),
which combines AES-128 in CBC mode with HMAC-SHA256 for authenticated encryption.

Installation:
    pip install cryptography
"""

import base64
import json
import os
from typing import Any, Dict, Union
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key() -> bytes:
    """Generates a cryptographically secure random 32-byte URL-safe base64 key."""
    return Fernet.generate_key()


def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Derives a Fernet-compatible encryption key from a human-readable password.
    Returns (key, salt). Store the salt alongside the encrypted data so you can
    re-derive the exact same key during decryption.
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,  # OWASP recommended minimum for PBKDF2-HMAC-SHA256
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key, salt


def encrypt_data(data: Union[str, Dict[str, Any]], key: bytes) -> str:
    """
    Encrypts a string or dictionary (e.g., user profile data) into a URL-safe token.

    Args:
        data: The plaintext string or JSON-serializable dictionary to encrypt.
        key: A 32-byte URL-safe base64-encoded key.

    Returns:
        The encrypted ciphertext as a UTF-8 string.
    """
    cipher = Fernet(key)

    # Convert dictionaries/objects to a JSON string before encoding to bytes
    if isinstance(data, dict):
        plaintext_bytes = json.dumps(data).encode("utf-8")
    elif isinstance(data, str):
        plaintext_bytes = data.encode("utf-8")
    else:
        raise TypeError("Data must be a string or a dictionary.")

    encrypted_bytes = cipher.encrypt(plaintext_bytes)
    return encrypted_bytes.decode("utf-8")


def decrypt_data(
    token: str, key: bytes, as_json: bool = False
) -> Union[str, Dict[str, Any]]:
    """
    Decrypts a Fernet token back into its original string or dictionary.

    Args:
        token: The encrypted ciphertext string.
        key: The same key used to encrypt the data.
        as_json: Set to True to parse the decrypted text back into a dictionary.

    Returns:
        The original decrypted string or dictionary.

    Raises:
        ValueError: If the key is wrong or the ciphertext has been tampered with.
    """
    cipher = Fernet(key)

    try:
        decrypted_bytes = cipher.decrypt(token.encode("utf-8"))
        decrypted_str = decrypted_bytes.decode("utf-8")
        return json.loads(decrypted_str) if as_json else decrypted_str
    except InvalidToken as exc:
        raise ValueError(
            "Decryption failed: Invalid key or corrupted/tampered data."
        ) from exc


# =====================================================================
# Example Usage
# =====================================================================
if __name__ == "__main__":
    # --- Method 1: Using a randomly generated secret key (Recommended for servers/APIs) ---
    # Save this key securely in an environment variable or secret manager (e.g., AWS KMS).
    secret_key = generate_key()
    print(f"Generated Key: {secret_key.decode('utf-8')}\n")

    user_record = {
        "user_id": 48291,
        "email": "jane.doe@example.com",
        "ssn": "123-45-6789",
    }

    # Encrypt
    encrypted_token = encrypt_data(user_record, secret_key)
    print(f"Encrypted Payload:\n{encrypted_token}\n")

    # Decrypt
    decrypted_record = decrypt_data(encrypted_token, secret_key, as_json=True)
    print(f"Decrypted Payload:\n{decrypted_record}\n")

    print("-" * 60)

    # --- Method 2: Using a user-supplied password ---
    user_password = "CorrectHorseBatteryStaple!"
    derived_key, generated_salt = derive_key_from_password(user_password)

    secret_note = "User's private recovery phrase"
    encrypted_note = encrypt_data(secret_note, derived_key)

    # To decrypt later, re-derive the key using the same password and stored salt
    re_derived_key, _ = derive_key_from_password(user_password, salt=generated_salt)
    decrypted_note = decrypt_data(encrypted_note, re_derived_key)

    print(f"Password-Encrypted Note: {encrypted_note}")
    print(f"Password-Decrypted Note: {decrypted_note}")