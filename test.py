import unittest
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from ra import RegistrationAuthority
from server import Server
from device import Device
from protocol import derive_session_key

class TestSecureProtocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Configura el entorno de prueba inicializando la autoridad de registro, el servidor y el dispositivo.
        cls.ra = RegistrationAuthority()
        cls.server_private, cls.device_public = cls.ra.get_server_credentials()
        cls.device_id, cls.device_private, cls.server_public = cls.ra.get_device_credentials()
        
        # Inicializar componentes
        cls.server = Server(cls.server_private)
        cls.server.register_device(cls.device_id, cls.device_public)
        cls.device = Device(cls.device_id, cls.device_private, cls.server_public)

    def test_ataque_repeticion(self):
        # Prueba para detectar un ataque de repetición.
        print("\n[PRUEBA 1] Ataque de repetición (Replay Attack)")
        test_nonce = os.urandom(16)
        self.server.used_nonces.add(test_nonce)

        with self.assertRaises(ValueError) as error:
            self.server.verify_device_response(
                device_id=self.device_id,
                signature=os.urandom(256),
                device_nonce=test_nonce,
                ec_public_key=os.urandom(128)
            )

        self.assertIn("Nonce repetido", str(error.exception))
        print("[RESULTADO] Ataque de repetición detectado y prevenido correctamente.")

    def test_ataque_suplantacion(self):
        # Prueba para detectar un ataque de suplantación de identidad.
        print("\n[PRUEBA 2] Suplantación de identidad (Impersonation Attack)")

        fake_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        atacante = Device(self.device_id, fake_private_key, self.server_public)

        server_nonce = self.server.generate_challenge()
        respuesta = atacante.respond_to_challenge(server_nonce)

        with self.assertRaises(ValueError) as err:
            self.server.verify_device_response(
                self.device_id,
                respuesta["signature"],
                respuesta["device_nonce"],
                respuesta["ec_public_key"]
            )

        print("[RESULTADO] Suplantación de identidad detectada correctamente.")

    def test_manipulacion_mensaje(self):
        # Prueba para detectar la manipulación de mensajes.
        print("\n[PRUEBA 3] Manipulación del mensaje (Message Tampering)")

        challenge = self.device.respond_to_challenge(os.urandom(16))

        # Alterar la clave pública
        clave_alterada = challenge["ec_public_key"].replace(
            b"-----BEGIN PUBLIC KEY-----",
            b"-----BEGIN CLAVE ALTERADA--"
        )

        with self.assertRaises(ValueError):
            serialization.load_pem_public_key(clave_alterada)

        print("[RESULTADO] Manipulación del mensaje detectada correctamente.")

    def test_intercambio_claves(self):
        # Prueba para verificar el intercambio de claves exitoso.
        print("\n[PRUEBA 4] Intercambio de claves exitoso y verificado")

        server_nonce = self.server.generate_challenge()
        device_response = self.device.respond_to_challenge(server_nonce)

        server_response = self.server.verify_device_response(
            self.device_id,
            device_response["signature"],
            device_response["device_nonce"],
            device_response["ec_public_key"]
        )

        self.assertIsNotNone(server_response)

        # Derivar claves
        server_shared = self.server.ec_private_key.exchange(
            ec.ECDH(),
            serialization.load_pem_public_key(device_response["ec_public_key"])
        )
        server_key = derive_session_key(server_shared)

        device_shared = self.device.ec_private_key.exchange(
            ec.ECDH(),
            serialization.load_pem_public_key(server_response[1])
        )
        device_key = derive_session_key(device_shared)

        self.assertEqual(server_key, device_key)
        print("[RESULTADO] Claves de sesión coinciden en ambas partes.")

    def test_id_no_registrado(self):
        # Prueba para detectar un ID no registrado.
        print("\n[PRUEBA 5] ID no registrado (ID spoofing)")

        atacante = Device("hacker_device_999", self.device_private, self.server_public)  # ID falso pero clave legítima
        server_nonce = self.server.generate_challenge()
        respuesta = atacante.respond_to_challenge(server_nonce)

        with self.assertRaises(ValueError) as err:
            self.server.verify_device_response(
                atacante.id,
                respuesta["signature"],
                respuesta["device_nonce"],
                respuesta["ec_public_key"]
            )

        print("[RESULTADO] ID no registrado correctamente detectado y rechazado.")


if __name__ == "__main__":
    unittest.main()

