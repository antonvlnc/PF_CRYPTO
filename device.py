from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

class Device:
    def __init__(self, device_id, private_key, server_public_key):
        self.id = device_id
        self.private_key = private_key
        self.server_public_key = server_public_key
        self.ec_private_key = None
        self.session_key = None
        self.used_nonces = set() #Detectamos nonces duplicados

    def initiate_connection(self):
        return {"device_id": self.id}

    def respond_to_challenge(self, server_nonce):
        self.device_nonce = os.urandom(16)
        self.ec_private_key = ec.generate_private_key(ec.SECP256R1())
        ec_public_key = self.ec_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        data_to_sign = server_nonce + self.device_nonce + ec_public_key
        signature = self.private_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {
            "signature": signature,
            "device_nonce": self.device_nonce,
            "ec_public_key": ec_public_key
        }

    def verify_server_response(self, signature, server_ec_public_key):
        if self.device_nonce in self.used_nonces:
            print("[Disposiitvo] Nonce repetido detectado en la respuesta al servidor")
            return False
        self.used_nonces.add(self.device_nonce)

        data_to_verify = self.device_nonce + server_ec_public_key
        try:
            self.server_public_key.verify(
                signature,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print("[Dispositivo] Error verificando firma del servidor",e)
            return False