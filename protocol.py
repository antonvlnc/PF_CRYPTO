from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os
import base64
import json

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

def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64decode_bytes(data: str) -> bytes:
    return base64.b64decode(data)

def json_send(sock, obj: dict):
    data = json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4, "big") + data)

def json_recv(sock) -> dict:
    length_bytes = sock.recv(4)
    if len(length_bytes) < 4:
        raise ValueError("No se recibió longitud completa del mensaje")

    length = int.from_bytes(length_bytes, "big")
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ValueError("Conexión cerrada inesperadamente")
        data += packet

    return json.loads(data.decode())