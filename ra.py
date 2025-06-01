# Implementación de RegistrionAuthority para gestión de claves RSA

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

DEVICE_KEY_PATH = "device_private.pem"
SERVER_KEY_PATH = "server_private.pem"


class RegistrationAuthority:
    def __init__(self):

        """
        Inicializa la autoridad de registro cargando o generando
        las claves RSA necesarias para el dispositivo y el servidor.
        """
        
        # Cargar claves del dispostivio o generarlas
        if os.path.exists("device_private.pem"):
            print("[RA] Clave privada del dispositivo cargada desde 'device_private.pem'")
            self.device_private_key = self._load_key(DEVICE_KEY_PATH)
            self.device_public_key = self.device_private_key.public_key()
        else:
            print("[RA] Generando nueva clave privada para el dispositivo")
            self.device_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.device_public_key = self.device_private_key.public_key()
            self._save_key(self.device_private_key, DEVICE_KEY_PATH)

        # Cargar claves del servidor o generarlas
        if os.path.exists(SERVER_KEY_PATH):
            print("[RA] Clave privada del servidor cargada desde 'server_private.pem'")
            self.server_private_key = self._load_key(SERVER_KEY_PATH)
            self.server_public_key = self.server_private_key.public_key()
        else:
            print("[RA] Generando nueva clave privada para el servidor")
            self.server_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.server_public_key = self.server_private_key.public_key()
            self._save_key(self.server_private_key, SERVER_KEY_PATH)

    def _save_key(self, key, filename):
        """
        Guarda una clave privada RSA en un archivo en formato PEM.

        Parámetros:
            key (RSAPrivateKey): La clave privada a guardar.
            filename (str): Ruta del archivo donde se guardará la clave.
        """
        with open(filename, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def _load_key(self, filename):
        """
        Carga una clave privada RSA desde un archivo PEM.

        Parámetros:
            filename (str): Ruta del archivo que contiene la clave.

        Retorna:
            RSAPrivateKey: La clave privada cargada.
        """
        with open(filename, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def get_device_credentials(self):
        """
        Devuelve las credenciales del dispositivo.

        Retorna:
            tuple: (ID del dispositivo, clave privada del dispositivo, clave pública del servidor)
        """
        return ("smartwatch_123", self.device_private_key, self.server_public_key)

    def get_server_credentials(self):
        """
        Devuelve las credenciales del servidor.

        Retorna:
            tuple: (clave privada del servidor, clave pública del dispositivo)
        """
        return (self.server_private_key, self.device_public_key)
