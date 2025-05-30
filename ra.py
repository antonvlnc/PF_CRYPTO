# Implementación de RegistrionAuthority para gestión de claves RSA

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class RegistrationAuthority:
    def __init__(self):
        # Cargar claves si existen, si no generarlas
        if os.path.exists("device_private.pem"):
            print("[RA] Clave privada del dispositivo cargada desde 'device_private.pem'")
            self.device_private_key = self._load_key("device_private.pem")
            self.device_public_key = self.device_private_key.public_key()
        else:
            print("[RA] Generando nueva clave privada para el dispositivo")
            self.device_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.device_public_key = self.device_private_key.public_key()
            self._save_key(self.device_private_key, "device_private.pem")

        if os.path.exists("server_private.pem"):
            print("[RA] Clave privada del servidor cargada desde 'server_private.pem'")
            self.server_private_key = self._load_key("server_private.pem")
            self.server_public_key = self.server_private_key.public_key()
        else:
            print("[RA] Generando nueva clave privada para el servidor")
            self.server_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.server_public_key = self.server_private_key.public_key()
            self._save_key(self.server_private_key, "server_private.pem")

    def _save_key(self, key, filename):
        with open(filename, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def _load_key(self, filename):
        with open(filename, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def get_device_credentials(self):
        return ("smartwatch_123", self.device_private_key, self.server_public_key)

    def get_server_credentials(self):
        return (self.server_private_key, self.device_public_key)
