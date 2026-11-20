"""
user_data_crypto.py

Encrypt and decrypt user data with a password.

- Cipher:  AES-256-GCM (authenticated encryption: detects tampering/wrong password)
- KDF:     scrypt (memory-hard, resists brute-force)
- Output:  a single URL-safe base64 string containing version, salt, nonce, ciphertext

Requires:  pip install cryptography
"""

import base64
import json
import os
from typing import Any, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ---- Format constants -------------------------------------------------------
VERSION = b"\x01"          # lets you change the format/params in the future
SALT_SIZE = 16             # bytes
NONCE_SIZE = 12            # bytes (recommended size for GCM)
KEY_SIZE = 32              # bytes -> AES-256

# scrypt cost parameters (N=2**15 uses ~32 MB RAM; raise N for more security)
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


class DecryptionError(Exception):
    """Raised when decryption fails (wrong password or corrupted/tampered data)."""


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password and salt using scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data: Union[str, bytes, dict, list], password: str) -> str:
    """
    Encrypt user data with a password.

    Args:
        data: str, bytes, or JSON-serializable dict/list.
        password: the secret used to derive the encryption key.

    Returns:
        URL-safe base64 string (safe to store in a DB or send over text channels).
    """
    if not password:
        raise ValueError("Password must not be empty.")

    # Normalize input to bytes (dict/list -> JSON)
    if isinstance(data, (dict, list)):
        plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    elif isinstance(data, str):
        plaintext = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        plaintext = bytes(data)
    else:
        raise TypeError("data must be str, bytes, dict, or list.")

    salt = os.urandom(SALT_SIZE)     # fresh random salt per message
    nonce = os.urandom(NONCE_SIZE)   # fresh random nonce per message (never reuse!)
    key = _derive_key(password, salt)

    # Header (version + salt + nonce) is authenticated as associated data,
    # so tampering with it also causes decryption to fail.
    header = VERSION + salt + nonce
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)

    return base64.urlsafe_b64encode(header + ciphertext).decode("ascii")


def decrypt_data(token: str, password: str, as_type: str = "str") -> Any:
    """
    Decrypt a token produced by encrypt_data().

    Args:
        token: the base64 string returned by encrypt_data().
        password: the same password used to encrypt.
        as_type: "str" (default), "bytes", or "json" (parses into dict/list).

    Raises:
        DecryptionError: wrong password, or data was corrupted/tampered with.
    """
    if as_type not in ("str", "bytes", "json"):
        raise ValueError('as_type must be "str", "bytes", or "json".')

    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
    except Exception as exc:
        raise DecryptionError("Invalid token encoding.") from exc

    header_len = len(VERSION) + SALT_SIZE + NONCE_SIZE
    if len(raw) < header_len + 16:   # 16 = GCM auth tag
        raise DecryptionError("Token is too short or corrupted.")
    if raw[:1] != VERSION:
        raise DecryptionError("Unsupported token version.")

    header = raw[:header_len]
    salt = raw[1:1 + SALT_SIZE]
    nonce = raw[1 + SALT_SIZE:header_len]
    ciphertext = raw[header_len:]

    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise DecryptionError("Wrong password or data has been tampered with.") from exc

    if as_type == "bytes":
        return plaintext
    text = plaintext.decode("utf-8")
    return json.loads(text) if as_type == "json" else text


def encrypt_file(in_path: str, out_path: str, password: str) -> None:
    """Encrypt a file's contents and write the token to out_path."""
    with open(in_path, "rb") as f:
        token = encrypt_data(f.read(), password)
    with open(out_path, "w", encoding="ascii") as f:
        f.write(token)


def decrypt_file(in_path: str, out_path: str, password: str) -> None:
    """Decrypt a file produced by encrypt_file() and write the original bytes."""
    with open(in_path, "r", encoding="ascii") as f:
        data = decrypt_data(f.read(), password, as_type="bytes")
    with open(out_path, "wb") as f:
        f.write(data)


# ---- Demo -------------------------------------------------------------------
if __name__ == "__main__":
    password = "correct horse battery staple"

    # 1) Plain text
    token = encrypt_data("Hello, secret world!", password)
    print("Encrypted:", token)
    print("Decrypted:", decrypt_data(token, password))

    # 2) Structured user data (dict)
    user = {"name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789"}
    token = encrypt_data(user, password)
    print("\nDecrypted dict:", decrypt_data(token, password, as_type="json"))

    # 3) Wrong password is detected
    try:
        decrypt_data(token, "wrong password")
    except DecryptionError as e:
        print("\nExpected failure:", e)

    # 4) Tampering is detected
    tampered = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
    try:
        decrypt_data(tampered, password)
    except DecryptionError as e:
        print("Expected failure:", e)