# Importación de los módulos necesarios para criptografía de clave pública, serialización y hashing
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
import os  # Para generación de nonces aleatorios

class Server:
    def __init__(self, private_key):
        self.private_key = private_key  # Clave privada RSA del servidor
        # Diccionario que mapea el ID de cada dispositivo a su clave pública registrada
        self.device_registry = {}
        # Clave privada EC generada al momento del intercambio de claves
        self.ec_private_key = None
        # Clave de sesión derivada (no se usa directamente en este fragmento)
        self.session_key = None
        # Nonces utilizados para prevenir ataques de repetición (replay attacks)
        self.used_nonces = set()

    def register_device(self, device_id, device_public_key):
        """
        Registra un dispositivo en el servidor almacenando su clave pública asociada a su ID.
        """
        self.device_registry[device_id] = device_public_key

    def generate_challenge(self):
        """
        Genera un nonce aleatorio que funcionará como desafío del servidor.
        """
        self.server_nonce = os.urandom(16)  # 16 bytes aleatorios
        return self.server_nonce

    def verify_device_response(self, device_id, signature, device_nonce, ec_public_key):
        """
        Verifica la firma del dispositivo, valida el nonce y genera la respuesta firmada del servidor.
        
        Parámetros:
        - device_id: ID del dispositivo que responde al desafío
        - signature: Firma enviada por el dispositivo
        - device_nonce: Nonce generado por el dispositivo
        - ec_public_key: Clave pública EC del dispositivo enviada para el intercambio de claves
        """
        # Verifica que el nonce del dispositivo no haya sido usado antes
        if device_nonce in self.used_nonces:
            print("[Servidor] Nonce repetido detectado")
            raise ValueError("Nonce repetido detectado")
        self.used_nonces.add(device_nonce)

        # Verifica que el dispositivo esté registrado en el servidor
        if device_id not in self.device_registry:
            print(f"[Servidor] ID desconocido: {device_id}")
            raise ValueError("Dispositivo no registrado")

        # Obtiene la clave pública esperada para ese dispositivo
        expected_public_key = self.device_registry[device_id]

        # Construye el mensaje que el dispositivo debió haber firmado
        data_to_verify = self.server_nonce + device_nonce + ec_public_key

        try:
            # Verifica la firma del dispositivo usando su clave pública
            expected_public_key.verify(
                signature,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),  # MGF1 con SHA-256
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Si la firma es válida, el servidor genera su propia clave EC
            self.ec_private_key = ec.generate_private_key(ec.SECP256R1())

            # Serializa su clave pública EC en formato PEM
            server_ec_public = self.ec_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Construye el mensaje que el servidor va a firmar y enviar de vuelta
            data_to_sign = device_nonce + server_ec_public

            # Firma ese mensaje con la clave RSA del servidor
            signature = self.private_key.sign(
                data_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Devuelve la firma y la clave pública EC del servidor al dispositivo
            return (signature, server_ec_public)

        except Exception as e:
            # Si la verificación falla, se lanza una excepción
            print("[Servidor] Error verificando firma:", e)
            raise ValueError("Error verificando firma")

