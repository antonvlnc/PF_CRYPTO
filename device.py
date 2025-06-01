from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

class Device:
    def __init__(self, device_id, private_key, server_public_key):
        # Inicializa el dispositivo con su ID, clave privada y clave pública del servidor
        self.id = device_id
        self.private_key = private_key
        self.server_public_key = server_public_key
        self.ec_private_key = None  # Clave privada efímera para ECDH
        self.session_key = None     # Clave de sesión (no usada aún)
        self.used_nonces = set()    # Para evitar reutilización de nonces

    def initiate_connection(self):
        # Método para iniciar conexión enviando el ID del dispositivo
        return {"device_id": self.id}

    def respond_to_challenge(self, server_nonce):
        # Cuando recibe un nonce del servidor, crea un nonce propio y una clave EC efímera
        self.device_nonce = os.urandom(16)  # Genera un nonce aleatorio de 16 bytes
        self.ec_private_key = ec.generate_private_key(ec.SECP256R1())  # Genera clave EC
        ec_public_key = self.ec_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Firma el mensaje concatenando nonce del servidor, nonce propio y clave pública EC
        data_to_sign = server_nonce + self.device_nonce + ec_public_key
        signature = self.private_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Devuelve la firma, el nonce generado y la clave pública EC
        return {
            "signature": signature,
            "device_nonce": self.device_nonce,
            "ec_public_key": ec_public_key
        }

    def verify_server_response(self, signature, server_ec_public_key):
        # Verifica que el nonce no haya sido usado antes para evitar ataques replay
        if self.device_nonce in self.used_nonces:
            print("[Disposiitvo] Nonce repetido detectado en la respuesta al servidor")
            return False
        self.used_nonces.add(self.device_nonce)

        # Prepara los datos que el servidor debió firmar (nonce del dispositivo + clave pública EC del servidor)
        data_to_verify = self.device_nonce + server_ec_public_key
        try:
            # Verifica la firma con la clave pública del servidor
            self.server_public_key.verify(
                signature,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True  # La verificación fue exitosa
        except Exception as e:
            print("[Dispositivo] Error verificando firma del servidor",e)
            return False
