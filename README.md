# PF_CRYPTO - Secure Communication Protocol Implementation

**Proyecto de Criptografía - Semestre 2025-2**

Este proyecto implementa un protocolo seguro de comunicación entre un **dispositivo con recursos limitados** (como un smartwatch) y un **servidor de aplicaciones**, con el apoyo de una **Autoridad de Registro (RA)** como tercera parte confiable. Se garantiza la **confidencialidad, autenticidad e integridad** de los mensajes.

---

##  Objetivo

Diseñar e implementar un protocolo de comunicación segura que permita:

- Registro de dispositivos mediante RA.
- Autenticación mutua entre dispositivo y servidor.
- Intercambio seguro de clave de sesión (ECDH).
- Comunicación cifrada y autenticada (AES-GCM).

---

##  Componentes del Proyecto

- `app.py`: Interfaz gráfica (GUI) para iniciar servidor y cliente, con logs visuales.
- `ra.py`: Simulación de la Autoridad de Registro (RA), generación/carga de claves RSA.
- `device.py`: Clase del dispositivo (generación de nonce, firma, verificación).
- `server.py`: Clase del servidor (registro, autenticación, generación de reto y firma).
- `device_client.py`: Cliente TCP del dispositivo. Ejecuta todas las fases del protocolo.
- `server_host.py`: Servidor TCP. Controla autenticación y comunicación segura.
- `protocol.py`: Funciones criptográficas para ECDH, AES-GCM, hashing, codificación.
- `tests.py`: Pruebas unitarias para ataques y validación de la seguridad del protocolo.

---

##  Requisitos

- **Python 3.8+**
- Librería externa: [`cryptography`](https://pypi.org/project/cryptography/)

### Instalación

```bash
pip install cryptography
```

>Recomendado: usar un entorno virtual

```bash
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
pip install cryptography
```

---

## Ejecución del Proyecto

### 1. Ejecutar la interfaz gráfica

```bash
python app.py
```

### 2. Usar la GUI

1. Presiona ** Iniciar Servidor** (lanza `server_host.py`)
2. Presiona ** Ejecutar Cliente** (lanza `device_client.py`)
3. Observa los logs de conexión, autenticación, cifrado y comunicación.
4. Puedes presionar ** Limpiar Logs** para limpiar la consola.

---

##  Flujo del Protocolo

1. **Registro (simulado)**:
   - RA otorga un `device_id`, una clave privada y pública RSA al dispositivo.
   - RA registra la clave pública del dispositivo en el servidor.

2. **Inicio de conexión**:
   - El dispositivo se conecta al servidor TCP y envía su ID.

3. **Reto y autenticación mutua**:
   - El servidor envía un nonce.
   - El dispositivo responde con:
     - Su propio nonce.
     - Clave pública EC.
     - Firma (nonce del servidor + su nonce + clave EC) usando RSA.
   - El servidor verifica, y a su vez firma (nonce del dispositivo + clave EC del servidor).

4. **Intercambio de claves (ECDH)**:
   - Ambos generan una clave simétrica compartida.

5. **Comunicación cifrada (AES-GCM)**:
   - El dispositivo envía un mensaje cifrado con autenticación.
   - El servidor responde también cifrado.

---

##  Criptografía utilizada

-  **RSA-2048** para autenticación y firmas.
-  **ECDH (secp256r1)** para derivar clave compartida.
-  **AES-GCM** (clave de 256 bits) para cifrado autenticado.
-  **SHA-256** como función hash base.

---

##  Pruebas de seguridad

Ejecuta:

```bash
python tests.py
```

Incluye:

1. **Replay Attack** → Detección de nonce repetido
2. **Impersonation Attack** → Suplantación de identidad con clave falsa
3. **Message Tampering** → Alteración de clave pública
4. **Verificación de intercambio ECDH** → Validación de clave compartida
5. **ID no registrado** → Rechazo de ID no autorizado

---

##  Archivos generados

Estos archivos son creados automáticamente si no existen:

- `device_private.pem`: Clave privada RSA del dispositivo.
- `server_private.pem`: Clave privada RSA del servidor.

> Si deseas reiniciar el sistema, elimina estos archivos para forzar la regeneración.

---

##  Demostración esperada

La ejecución completa del protocolo debe mostrar en consola:

- Registro e identificación del dispositivo.
- Intercambio de nonces.
- Verificación de firmas (RSA).
- Intercambio ECDH.
- Comunicación cifrada (AES-GCM).
- Confirmación de integridad.

/link video

---

##  Autores

Equipo del proyecto – Criptografía 2025-2:

- Toledo Valencia Jesús Antonio  
- Vallejo Escamilla Oscar Daniel  
- Arredondo Granados Gerardo  
- García Hernández Diego Aldair  
- C


---

##  Licencia

Proyecto académico con fines educativos. Uso libre para fines de estudio.
