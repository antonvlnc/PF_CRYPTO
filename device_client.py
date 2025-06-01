# device_client.py
import socket
from ra import RegistrationAuthority
from device import Device
from protocol import json_send, json_recv, b64encode_bytes, b64decode_bytes, derive_session_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Inicio del dispositivo: carga de credenciales y claves
print("[Dispositivo] Iniciando dispositivo y cargando claves...")
ra = RegistrationAuthority()
device_id, device_private, server_public = ra.get_device_credentials()

# Creación del objeto Device con sus credenciales
device = Device(device_id, device_private, server_public)

# Conexión al servidor mediante socket TCP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print("[Dispositivo] Conectando al servidor...")
    s.connect(('localhost', 9000))
    print("[Dispositivo] Conectado al servidor.")

    # Fase 1: Iniciar conexión
    print(f"[Dispositivo] Enviando ID: {device_id}")
    json_send(s, device.initiate_connection())

    # Fase 2: Recibir nonce
    response = json_recv(s)
    server_nonce = b64decode_bytes(response["server_nonce"])
    print("[Dispositivo] Nonce recibido del servidor.")
    print("[Dispositivo] Nonce recibido del servidor:", b64encode_bytes(server_nonce))  # Imprimir nonce recibido

    # Fase 3: Enviar respuesta al reto
    print("[Dispositivo] Generando clave EC y firmando el reto...")
    challenge = device.respond_to_challenge(server_nonce)
    challenge["device_id"] = device.id
    json_send(s, {
        "signature": b64encode_bytes(challenge["signature"]),
        "device_nonce": b64encode_bytes(challenge["device_nonce"]),
        "ec_public_key": b64encode_bytes(challenge["ec_public_key"]),
        "device_id": challenge["device_id"]
    })
    
    # Fase 4: Verificar respuesta del servidor
    response = json_recv(s)
    print("[Dispositivo] Verificando firma del servidor...")
    success = device.verify_server_response(
        b64decode_bytes(response["signature"]),
        b64decode_bytes(response["ec_public_key"])
    )
    if not success:
        print("Falló verificación del servidor.")
        exit()
    print("[Dispositivo] Firma del servidor verificada correctamente.")
    # Imprimir el hash de la firma verificada
    print("[Dispositivo] Hash de la firma verificada:", b64encode_bytes(b64decode_bytes(response["signature"])))

    # Fase 5: Derivar clave
    print("[Dispositivo] Derivando clave de sesión compartida...")
    server_ec_pub = serialization.load_pem_public_key(b64decode_bytes(response["ec_public_key"]))
    shared = device.ec_private_key.exchange(ec.ECDH(), server_ec_pub)
    device.session_key = derive_session_key(shared)
    print("[Dispositivo] Clave de sesión establecida.")

    # Fase 6: Enviar mensaje cifrado
    print("[Dispositivo] Enviando mensaje cifrado...")
    from protocol import encrypt_message
    print("[Dispositivo](mensaje) Hola servidor")
    nonce, ciphertext = encrypt_message("Hola Servidor", device.session_key)
    json_send(s, {
        "nonce": b64encode_bytes(nonce),
        "ciphertext": b64encode_bytes(ciphertext)
    })

    # Fase 7: Recibir respuesta cifrada
    msg = json_recv(s)
    print("[Dispositivo] Recibiendo respuesta cifrada...")
    from protocol import decrypt_message
    plaintext = decrypt_message(
        b64decode_bytes(msg["nonce"]),  # Nonce recibido
        b64decode_bytes(msg["ciphertext"]), # Texto cifrado recibido
        device.session_key # Clave de sesión derivada
    )
    print("[Dispositivo] Mensaje descifrado:", plaintext)
    print("[Servidor] Comunicación finalizada.")

