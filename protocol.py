from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os

def derive_session_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session_key'
    ).derive(shared_secret)

def encrypt_message(message: str, session_key: bytes) -> tuple:
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    return (nonce, ciphertext)

def decrypt_message(nonce: bytes, ciphertext: bytes, session_key: bytes) -> str:
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()