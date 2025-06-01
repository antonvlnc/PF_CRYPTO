# server_host.py
import socket
from ra import RegistrationAuthority
from server import Server
from protocol import json_send, json_recv, b64decode_bytes, b64encode_bytes, derive_session_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Inicialización de claves y registros desde la Autoridad de Registro (RA)
print("[RA] Inicializando claves y registros...")
ra = RegistrationAuthority()
device_id, device_private, server_public = ra.get_device_credentials()
server_private, device_public = ra.get_server_credentials()

# Registro del dispositivo con su ID y clave pública
print(f"[Servidor] Registrando dispositivo con ID: {device_id}")
server = Server(server_private)
server.register_device(device_id, device_public)

# Configuración del socket del servidor para aceptar conexiones
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('localhost', 9000)) # Asignar puerto y dirección
    s.listen(1) # Escuchar una conexión entrante
    print("[Servidor] Esperando conexión...")

    # Aceptar conexión entrante
    conn, addr = s.accept()
    with conn:
        print(f"[Servidor] Conectado con {addr}")

        # Fase 1: Esperar conexión inicial
        init_msg = json_recv(conn)
        print("[Servidor] ID recibido del dispositivo:", init_msg["device_id"])

        # Fase 2: Enviar nonce
        nonce = server.generate_challenge()
        json_send(conn, {"server_nonce": b64encode_bytes(nonce)})

        # Fase 3: Recibir respuesta del dispositivo
        print("[Servidor] Esperando respuesta del dispositivo...")
        response = json_recv(conn)
        
        # Decodificar firma desde base64
        signature_bytes = b64decode_bytes(response["signature"])

    # Verificar que la firma, el nonce y la clave pública del dispositivo sean válidas
        result = server.verify_device_response(
            response["device_id"],
            b64decode_bytes(response["signature"]),
            b64decode_bytes(response["device_nonce"]),
            b64decode_bytes(response["ec_public_key"])
        )

        if not result:
            print("Verificación del dispositivo fallida.")
            exit()

        # Imprimir los hashes generados
        print("[Servidor] Firma del dispositivo verificada correctamente.")
        print("[Servidor] Hash de la firma verificada:", b64encode_bytes(signature_bytes))
        device_nonce_bytes = b64decode_bytes(response["device_nonce"])
        print("[Servidor] Nonce recibido:", b64encode_bytes(device_nonce_bytes))
        
        print("[Servidor] Enviando firma del servidor y clave EC...")
        json_send(conn, {
            "signature": b64encode_bytes(result[0]),
            "ec_public_key": b64encode_bytes(result[1])
        })

        # Fase 4: Derivar clave
        device_ec_pub = serialization.load_pem_public_key(
            b64decode_bytes(response["ec_public_key"])
        )
        shared = server.ec_private_key.exchange(ec.ECDH(), device_ec_pub)
        server.session_key = derive_session_key(shared)
        print("[Servidor] Clave de sesión establecida.")

        # Fase 5: Comunicación cifrada
        print("[Servidor] Esperando mensaje cifrado del dispositivo...")
        msg = json_recv(conn)
        print("[Servidor] Mensaje cifrado recibido.")

        from protocol import decrypt_message
        plaintext = decrypt_message(
            b64decode_bytes(msg["nonce"]),
            b64decode_bytes(msg["ciphertext"]),
            server.session_key
        )
        print("[Servidor] Mensaje descifrado:", plaintext)

        # Enviar una respuesta cifrada al dispositivo
        print("[Servidor] Enviando respuesta cifrada al dispositivo...")
        print("[Servidor](mensaje) Hola Smartwatch")
        from protocol import encrypt_message
        nonce, ciphertext = encrypt_message("[Servidor]Hola Smartwatch", server.session_key)
        json_send(conn, {
            "nonce": b64encode_bytes(nonce),
            "ciphertext": b64encode_bytes(ciphertext)
        })
        print("[Servidor] Comunicación finalizada.")
