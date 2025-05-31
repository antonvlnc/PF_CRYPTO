from ra import RegistrationAuthority
from device import Device
from server import Server
from protocol import derive_session_key, encrypt_message, decrypt_message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa #Generar claves falsas
def main():
    output = []
    try:
        # Configurar RA
        ra = RegistrationAuthority()
        device_id, device_private, server_public = ra.get_device_credentials()
        server_private, device_public = ra.get_server_credentials()

        # Inicializar componentes
        device = Device(device_id, device_private, server_public) #device_id es para auntenticar que el id sea el que se quiere
        server = Server(server_private)
        
        #Registrar el ID del dispositivo en el servidor
        server.register_device(device_id,device_public)

        # Fase 1: Iniciar conexión
        output.append("Dispositivo inicia conexión.")
        init_msg = device.initiate_connection()

        # Fase 2: Desafío del servidor
        output.append("Servidor envía nonce.")
        server_nonce = server.generate_challenge()

        # Fase 3: Respuesta del dispositivo
        output.append("Dispositivo responde al desafío.")
        device_response = device.respond_to_challenge(server_nonce)
        
        #Agregamos el ID a la respuesta
        device_response["device_id"] = device.id

        if not device_response or not all(k in device_response for k in ["signature", "device_nonce", "ec_public_key"]):
            raise ValueError("Respuesta del dispositivo inválida")

        # Fase 4: Verificación y respuesta del servidor
        server_response = server.verify_device_response(
            device_response["device_id"],
            device_response["signature"],
            device_response["device_nonce"],
            device_response["ec_public_key"]
        )

        if not server_response:
            raise ValueError("Falló la verificación del dispositivo")

        output.append("Servidor verifica dispositivo. Envía respuesta.")
        
        # Fase 5: Verificación del dispositivo
        if not device.verify_server_response(server_response[0], server_response[1]):
            raise ValueError("Falló la verificación del servidor")

        output.append("Dispositivo verifica servidor. Clave de sesión establecida.")
        
        # Establecer clave de sesión
        try:
            device_shared = device.ec_private_key.exchange(
                ec.ECDH(),
                serialization.load_pem_public_key(server_response[1])
            )
            device.session_key = derive_session_key(device_shared)
            
            server_shared = server.ec_private_key.exchange(
                ec.ECDH(),
                serialization.load_pem_public_key(device_response["ec_public_key"])
            )
            server.session_key = derive_session_key(server_shared)
        except Exception as e:
            raise ValueError(f"Error en intercambio de claves: {str(e)}")

        # Comunicación segura
        msg = "✅ Hola soy smartwatch. ✅"
        nonce, ciphertext = encrypt_message(msg, device.session_key)
        output.append(f"Mensaje cifrado enviado: {ciphertext.hex()}")

        decrypted = decrypt_message(nonce, ciphertext, server.session_key)
        output.append(f"Servidor descifra: {decrypted}")

        # Respuesta del servidor
        resp = " ✅ Confirmación del servidor. Hola Smartwatch ✅"
        resp_nonce, resp_cipher = encrypt_message(resp, server.session_key)
        output.append(f"Respuesta cifrada: {resp_cipher.hex()}")

        resp_decrypted = decrypt_message(resp_nonce, resp_cipher, device.session_key)
        output.append(f"Dispositivo descifra: {resp_decrypted}")

    except Exception as e:
        output.append(f"❌ERROR: {str(e)}")
    
    return "\n".join(output)  # Asegura que siempre retorna un string

def PruebaAttackReplay():
    output = ["[Prueba Replay Attack] Iniciando prueba..."]
    try:
        # Configurar RA
        ra = RegistrationAuthority()
        device_id, device_private, server_public = ra.get_device_credentials()
        server_private, device_public = ra.get_server_credentials()

        # Inicializar componentes
        device = Device(device_id, device_private, server_public)
        server = Server(server_private)
        server.register_device(device_id, device_public)

        # Fase 1: Servidor genera challenge
        server_nonce = server.generate_challenge()

        # Fase 2: Dispositivo responde al desafío
        device_response = device.respond_to_challenge(server_nonce)
        device_response["device_id"] = device_id
        output.append("Primer intento de autenticación...")

        result_1 = server.verify_device_response(
            device_response["device_id"],
            device_response["signature"],
            device_response["device_nonce"],
            device_response["ec_public_key"]
        )
        output.append("Resultado primer intento: " + ("✅ Aceptado" if result_1 else "❌ Rechazado"))

        # Fase 3: Intento de ataque de repetición con el mismo mensaje
        output.append("Segundo intento de autenticación (replay attack)...")

        result_2 = server.verify_device_response(
            device_response["device_id"],
            device_response["signature"],
            device_response["device_nonce"],
            device_response["ec_public_key"]
        )
        output.append("Resultado segundo intento: " + ("✅ Aceptado (MAL!)" if result_2 else "❌ Rechazado (Correcto)"))

    except Exception as e:
        output.append(f"[ERROR durante prueba replay attack]: {str(e)}")

    return "\n".join(output)

def PruebaSuplantacionID():
    output = ["[Prueba Suplantación ID] Iniciando prueba..."]
    try:
        ra = RegistrationAuthority()
        real_device_id, real_device_private, server_public = ra.get_device_credentials()
        server_private, real_device_public = ra.get_server_credentials()

        # Creamos un servidor y registramos el dispositivo legítimo
        server = Server(server_private)
        server.register_device(real_device_id, real_device_public)

        # Creamos un "atacante" que usa otro par de claves pero intenta usar el mismo ID
        fake_device_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        attacker = Device(real_device_id, fake_device_private, server_public)

        server_nonce = server.generate_challenge()
        device_response = attacker.respond_to_challenge(server_nonce)
        device_response["device_id"] = attacker.id

        output.append("El atacante intenta suplantar al dispositivo...")
        result = server.verify_device_response(
            device_response["device_id"],
            device_response["signature"],
            device_response["device_nonce"],
            device_response["ec_public_key"]
        )

        if result:
            output.append("❌ Suplantación aceptada (ERROR)")
        else:
            output.append("✅ Suplantación detectada y rechazada (Correcto)")

    except Exception as e:
        output.append(f"[ERROR en prueba de suplantación]: {str(e)}")

    return "\n".join(output)

if __name__ == "__main__":
    ##Ejecución del Programa sin prueba de ataque (descomentar)
    #result = main()
    #print(result)
    ##Ejecución del Programa con prueba del ataque
    print("=== Ejecución normal del protocolo ===")
    print(main())
    print("\n=== Prueba de Replay Attack ===")
    print(PruebaAttackReplay())
    print("\n=== Prueba de Suplantación de ID ===")
    print(PruebaSuplantacionID())