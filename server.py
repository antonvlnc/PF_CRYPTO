from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

class Server:
    def __init__(self, private_key):
        self.private_key = private_key
        #self.device_public_key = device_public_key
        self.device_registry = {}
        self.ec_private_key = None
        self.session_key = None
        self.used_nonces = set() #Utilizado para evitar el replay attack

    def register_device(self, device_id, device_public_key):
        self.device_registry[device_id] = device_public_key

    def generate_challenge(self):
        self.server_nonce = os.urandom(16)
        return self.server_nonce

    def verify_device_response(self, device_id, signature, device_nonce, ec_public_key):
        if device_nonce in self.used_nonces:
            print("[Servidor] Nonce repetido detectado")
            return None
        self.used_nonces.add(device_nonce)
        
        if device_id not in self.device_registry:
            print(f"[Servidor] ID desconocido: {device_id}")
            return None

        expected_public_key = self.device_registry[device_id]

        data_to_verify = self.server_nonce + device_nonce + ec_public_key
        try:
            expected_public_key.verify(
                signature,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.ec_private_key = ec.generate_private_key(ec.SECP256R1())
            server_ec_public = self.ec_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            data_to_sign = device_nonce + server_ec_public
            signature = self.private_key.sign(
                data_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return (signature, server_ec_public)
        except Exception as e:
            print("[Servidor] Error verificando firma:",e)
            return None