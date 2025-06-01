from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

class Server:
    def __init__(self, private_key):
        # Inicializa el servidor con su clave privada
        self.private_key = private_key
        # Registro de dispositivos autorizados: device_id -> clave pública
        self.device_registry = {}
        self.ec_private_key = None  # Clave privada efímera para ECDH
        self.session_key = None     # Clave de sesión (no usada aún)
        self.used_nonces = set()    # Para evitar ataques replay con nonces repetidos

    def register_device(self, device_id, device_public_key):
        # Registra la clave pública de un dispositivo dado su ID
        self.device_registry[device_id] = device_public_key

    def generate_challenge(self):
        # Genera un nonce aleatorio para desafiar al dispositivo
        self.server_nonce = os.urandom(16)
        return self.server_nonce

    def verify_device_response(self, device_id, signature, device_nonce, ec_public_key):
        # Verifica que el nonce del dispositivo no haya sido usado antes (previene replay)
        if device_nonce in self.used_nonces:
            print("[Servidor] Nonce repetido detectado")
            raise ValueError("Nonce repetido detectado")
        self.used_nonces.add(device_nonce)
        
        # Verifica que el dispositivo esté registrado
        if device_id not in self.device_registry:
            print(f"[Servidor] ID desconocido: {device_id}")
            raise ValueError("Dispositivo no registrado")

        expected_public_key = self.device_registry[device_id]

        # Datos que el dispositivo debió firmar: nonce del servidor + nonce del dispositivo + clave pública EC del dispositivo
        data_to_verify = self.server_nonce + device_nonce + ec_public_key
        try:
            # Verifica la firma con la clave pública registrada del dispositivo
            expected_public_key.verify(
                signature,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # Si la firma es válida, genera su propia clave efímera EC
            self.ec_private_key = ec.generate_private_key(ec.SECP256R1())
            server_ec_public = self.ec_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Firma la concatenación del nonce del dispositivo y su clave pública EC
            data_to_sign = device_nonce + server_ec_public
            signature = self.private_key.sign(
                data_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # Devuelve la firma y la clave pública EC para que el dispositivo verifique
            return (signature, server_ec_public)
        except Exception as e:
            print("[Servidor] Error verificando firma:", e)
            raise ValueError("Error verificando firma")

