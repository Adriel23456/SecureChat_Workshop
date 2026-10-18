# Plan de desarrollo — SecureChat: comunicación segura con criptografía híbrida

**Curso:** CE-1115 Seguridad de la Información — II Semestre, 2026
**Escuela:** Escuela de Ingeniería en Computadores — Tecnológico de Costa Rica
**Integrantes:** Adriel S. Chaves Salazar · Henry D. Núñez Pérez
**Repositorio:** https://github.com/Adriel23456/SecureChat_Workshop
**Plataforma de desarrollo y demostración:** Windows 10/11, Python 3, PowerShell / Windows Terminal

Algoritmos de referencia: **RSA ≥ 2048 bits con OAEP** (establecimiento de sesión) y **AES-256-GCM** (mensajes).
Cada sección corresponde a un paso del enunciado. Una casilla se marca solo cuando hay evidencia (prueba, captura o commit).

---

### `00ConfiguracionInicial`

Base del repositorio y del entorno antes de escribir código del chat.

- [x] Clonar el repositorio en Windows y verificar `git config user.name` / `user.email` de ambos integrantes
- [x] Definir la estructura: `srcAlice/` y `srcBob/` (cada uno con su `main.py`, sus módulos y su `.venv`; **sin `__init__.py`**, los módulos se importan como archivos vecinos), `docs/` (con `img/` y `referencias.bib`), `requirements.txt` en la raíz
- [x] `.gitignore`: `.venv/`, `__pycache__/`, `*.pyc`, `keys/`, `*.pem`, `*.key`, `.pytest_cache/` y los auxiliares de LaTeX
- [x] Verificar la versión de Python (`py -3 --version`, 64 bits)
- [x] Un entorno virtual por participante: `srcBob\.venv` y `srcAlice\.venv`, ambos instalados desde el `requirements.txt` de la raíz
- [x] `requirements.txt` en la raíz con `cryptography` (fijar versiones con `pip freeze` al final)
- [x] `CurrentCommands.txt` con los comandos rápidos (crear entornos, activar y ejecutar cada lado)
- [x] Esqueleto de `README.md` en el repositorio
- [x] Esqueleto de `docs/DescripcionDelProtocolo.tex`
- [x] `PlanDeDesarrollo.md` en la raíz del repositorio
- [x] Acordar el flujo de trabajo en pareja (ramas por paso y revisión cruzada antes de unir a `main`)

### `01ComunicacionTCP` (Paso 1 — conectividad sin criptografía)

Objetivo: dos procesos en dos terminales, conectados por TCP sobre localhost. **Esta etapa no es el resultado seguro final.**

Archivos: `config.py`, `main.py`, `chat_session.py`, `framed_connection.py`, `message.py`, `console_view.py`, `connection_establisher.py`, `errors.py` en ambos lados, más `srcBob/tcp_server.py` y `srcAlice/tcp_client.py`.

- [x] Interfaz: `main.py` abre un **menú** (1 = conectar/esperar e iniciar chat, 2 = ver configuración, 3 = salir). El rol lo define la carpeta (`srcBob` / `srcAlice`); host, puerto y demás constantes viven en el `config.py` de cada lado (`127.0.0.1:5050`)
- [x] Bob (`TcpServer`): `bind(("127.0.0.1", PORT))`, `listen(1)`, `accept()` y muestra la dirección y el puerto del par conectado
- [x] Alice (`TcpClient`): `connect(("127.0.0.1", PORT))` con mensaje claro si Bob no está escuchando (`ConnectionRefusedError` / WinError 10061) o si se agota el tiempo
- [x] Reutilización del puerto: `SO_EXCLUSIVEADDRUSE` en Windows (allí `SO_REUSEADDR` permitiría que otro proceso comparta el puerto) y `SO_REUSEADDR` en Linux/macOS
- [x] **Framing** (`FramedConnection`): prefijo de longitud de 4 bytes big-endian (`struct.pack("!I", n)`) y `_receive_exact(n)`, que llama a `recv()` hasta completar n bytes
- [x] Límite máximo de trama de 64 KiB, validado antes de leer el cuerpo (al enviar y al recibir)
- [x] Concurrencia: hilo receptor dedicado y lectura de teclado en el hilo principal; impresión protegida con lock y el prompt se reimprime al llegar un mensaje
- [x] Formato de mensaje: 1 byte de tipo + cuerpo UTF-8 (`HELLO = 1`, `CHAT = 2`, `BYE = 3`)
- [x] Identificación del par: ambos envían `HELLO(nombre)` al conectar (timeout de 10 s) y muestran "Conectado con Bob @ 127.0.0.1:5050"; aviso si el nombre no es el esperado
- [x] Enviar y recibir varios mensajes en la misma sesión (texto plano **solo en esta etapa**)
- [x] Cierre ordenado: `/salir` envía `BYE`, `shutdown()` y `close()`; el otro extremo lo informa y vuelve al menú con Enter
- [x] Manejo de Ctrl+C (espera, conexión y chat), de desconexión abrupta (`ConnectionResetError` / WinError 10054 y `recv` que devuelve `b""`), de puerto ocupado (WinError 10048), de tipos de mensaje desconocidos y de tramas gigantes, sin trazas
- [x] Prueba manual en Windows Terminal (panel dividido): al menos 3 mensajes por lado, `/salir`, Ctrl+C y cierre abrupto de una de las ventanas
- [x] Commit etiquetado `paso1-conectividad`

### `02MaterialAsimetrico` (Paso 2 — claves RSA)

Archivos nuevos en `srcShared/`: `rsa_key_generator.py`, `key_store.py`, `key_fingerprint.py`, `trusted_peer_store.py`, `key_pair_verifier.py`, `key_management_actions.py`, `menu_option.py`. Modificados: `shared_config.py`, `errors.py`, `console_view.py`, ambos `config.py` y ambos `main.py`.

- [x] Tamaño decidido: **RSA-3072** (≈128 bits de seguridad); al cargar se rechaza cualquier llave < 2048 bits; `e = 65537`
- [x] Generación desde el menú (opción 2) con `rsa.generate_private_key(public_exponent=65537, key_size=3072)`; protege contra sobrescribir un par existente
- [x] Llave privada en PEM PKCS#8 **cifrada** (`BestAvailableEncryption`) en `srcXxx/keys/private_key.pem`; frase de paso de ≥ 8 caracteres pedida dos veces con `getpass`
- [x] Llave pública en PEM `SubjectPublicKeyInfo` en `srcXxx/keys/public_key.pem`
- [x] `keys/` cubierto por `.gitignore` (`git check-ignore -v srcBob/keys/private_key.pem`); ninguna llave en commits
- [x] Distribución decidida: **(c)** la llave pública viaja por el socket en el handshake y se valida contra una huella SHA-256 de confianza registrada fuera de banda (opción 4 del menú, archivo `trusted_<par>_fingerprint.txt`)
- [x] Solo se muestra la **huella** SHA-256 (opción 3); la llave privada y la frase de paso nunca se imprimen
- [x] Decidido: **Alice también usa su par**. Firma su mensaje del handshake con RSA-PSS y Bob la verifica con su huella de confianza (autenticación mutua; se implementa en el Paso 3)
- [x] Prueba (opción 5): coinciden `n` y `e`, la firma PSS con la privada se verifica con la pública, y lo cifrado con OAEP usando la pública se descifra con la privada; frase incorrecta → error limpio
- [x] Sección 3 del `.tex` redactada: qué es público, qué es secreto, por qué la pública no reemplaza a la privada, la huella, la distribución y el uso de cada par
- [x] Prueba manual en Windows: generar ambos pares, registrar las huellas cruzadas y verificar con la frase correcta e incorrecta
- [x] Commit etiquetado `paso2-material-asimetrico`

### `03Handshake` (Paso 3 — establecimiento de la clave de sesión)

Flujo implementado: HELLO(Alice) → HELLO(Bob) → PUBLIC_KEY(Bob) → SESSION_KEY(Alice) → CONFIRM(Bob) → CONFIRM(Alice).
Archivos nuevos: `srcShared/{binary_fields, handshake_transcript, rsa_operations, aes_gcm_cipher, session_identity, session_material, handshake_base}.py`, `srcAlice/alice_handshake.py`, `srcBob/bob_handshake.py`.

- [x] Tipos de mensaje (1 byte): `HELLO=1`, `CHAT=2`, `BYE=3`, `PUBLIC_KEY=4`, `SESSION_KEY=5`, `CONFIRM=6`, `ABORT=7`; cuerpos binarios con campos precedidos por su largo de 4 bytes
- [x] Alice genera la clave de sesión de 256 bits con `AESGCM.generate_key(bit_length=256)`; nueva por sesión, nunca en el código ni en pantalla
- [x] Alice cifra K con RSA-OAEP (SHA-256, MGF1-SHA-256) usando la pública de Bob y firma `T || pubA || OAEP(K)` con RSA-PSS
- [x] Bob verifica la huella y la firma de Alice y descifra con su privada; `ValueError` o firma inválida → ABORT
- [x] Confirmación doble con AES-256-GCM usando K (Bob primero, Alice después), con el hash del transcript como AAD
- [x] Decidido: **sí** hay transcript SHA-256 de todo el handshake (firma + AAD) y `session_id` = primeros 8 bytes del hash final, igual en ambas terminales; `client_random` y `server_random` impiden repetir un handshake viejo
- [x] El chat no se habilita hasta verificar ambas confirmaciones; cualquier mensaje fuera de orden (p. ej. CHAT antes de HELLO) aborta
- [x] Indicador "SESIÓN SEGURA ESTABLECIDA" con huella verificada del par, tamaño de la clave (256 bits, nunca su valor) e Id de sesión
- [x] Evidencia en consola: pasos `[HS ->]` / `[HS <-]`, vista hexadecimal de los valores públicos y comprobación automática de que K no aparece en los bytes enviados
- [x] Captura con Wireshark + Npcap (loopback, `tcp.port == 5050`) del mensaje SESSION_KEY para el video
- [x] Errores: llave mal formada o débil, huella distinta, firma inválida, descifrado fallido, tag de confirmación inválido y tiempo agotado (15 s) → ABORT con motivo y cierre; frase incorrecta o falta de huella → no se conecta
- [x] Limitación documentada en el `.tex` (MitM si no se autentica la llave pública; mitigación con la huella fuera de banda; sin secreto hacia adelante)
- [x] Probado con un proxy MitM: reemplazar PUBLIC_KEY, alterar 1 byte de SESSION_KEY y alterar 1 byte de CONFIRM → el handshake se aborta en los tres casos
- [x] Prueba manual en Windows y commit etiquetado `paso3-handshake`

### `04CifradoDeMensajes` (Paso 4 — AES-256-GCM)

- [ ] Toda salida de mensajes de usuario pasa por cifrado **antes** de llegar al socket; no existe una ruta de envío en claro después del handshake
- [ ] Estrategia de nonce de 96 bits **sin repetición con la misma clave**:
  - [ ] Separar los espacios de nonce por dirección (Alice → Bob y Bob → Alice comparten clave), por ejemplo 1 byte de dirección + contador de 11 bytes, o 4 bytes de dirección + contador de 8 bytes
  - [ ] Alternativa: nonce aleatorio de 12 bytes con `os.urandom(12)`. Documentar por qué el riesgo de colisión es despreciable para este volumen
  - [ ] Abortar la sesión si el contador se agota
- [ ] Datos asociados (AAD) autenticados sin cifrar: tipo de mensaje, dirección y número de secuencia
- [ ] Protección contra repetición (replay): el receptor exige un número de secuencia estrictamente creciente por dirección
- [ ] El receptor llama a `AESGCM.decrypt(nonce, ct, aad)` y **solo** muestra el plaintext si no se lanza `InvalidTag`
- [ ] Definir la estructura final de la trama: `longitud | tipo | nonce | ciphertext‖tag` (`cryptography` devuelve el tag de 16 bytes concatenado al ciphertext)
- [ ] Codificación del texto: UTF-8 para tildes y ñ (verificar en la consola de Windows)
- [ ] Visualización del emisor: plaintext local y luego ciphertext enviado (nonce, ciphertext y tag en hexadecimal, **solo para mostrar**; Base64 o hexadecimal no son cifrado)
- [ ] Visualización del receptor: ciphertext recibido, luego verificación del tag (OK o rechazo) y luego plaintext recuperado
- [ ] Prueba automatizada: el plaintext escrito por el usuario **no** aparece dentro de los bytes enviados (`assert plaintext not in frame`)
- [ ] Prueba automatizada: 10 000 cifrados seguidos no repiten nonce

### `05ChatBidireccional` (Paso 5 — conversación completa)

- [ ] Ambos extremos pueden enviar en cualquier momento (hilo receptor y entrada de usuario simultáneos)
- [ ] La salida en consola no se mezcla con lo que el usuario está escribiendo (bloqueo de impresión o reimpresión del prompt)
- [ ] Distinción visual consistente:
  - [ ] `[TÚ]` mensaje local (plaintext)
  - [ ] `[CIFRADO →]` datos transmitidos (nonce, ciphertext y tag)
  - [ ] `[← CIFRADO]` datos recibidos
  - [ ] `[BOB]` / `[ALICE]` mensaje recuperado después de la verificación
  - [ ] `[!]` errores y rechazos
- [ ] Opción para activar o desactivar la vista detallada del ciphertext (por ejemplo `--verbose` o comando `/detalle`)
- [ ] Comando de cierre controlado `/salir`: envía un mensaje de cierre **cifrado**, el otro extremo lo muestra y ambos terminan limpio
- [ ] Borrar la referencia a la clave de sesión al terminar (documentar que en Python no se puede garantizar que se borre de memoria)
- [ ] Prueba manual: al menos 3 mensajes de Alice y 3 de Bob, intercalados

### `06DeteccionDeManipulacion` (Paso 6 — integridad)

- [ ] Decidir el mecanismo de prueba controlada:
  - [ ] (a) bandera `--tamper` en el emisor que altera un byte del ciphertext después de cifrar y antes de enviar, o
  - [ ] (b) proxy intermedio `scripts/tamper_proxy.py` entre Alice y Bob que altera un byte en tránsito (simula un MitM activo; más realista)
- [ ] El byte modificado debe estar en el ciphertext o en el tag, no en el prefijo de longitud
- [ ] El receptor detecta `InvalidTag`, muestra "MENSAJE RECHAZADO: autenticación fallida" y **no** imprime ningún plaintext
- [ ] Decidir la política después del rechazo: descartar el mensaje y seguir, o cerrar la sesión. Justificarlo (un canal manipulado podría tratarse como comprometido)
- [ ] Prueba automatizada con `pytest`: alterar 1 byte (ciphertext, tag, nonce y AAD) produce `InvalidTag` en todos los casos
- [ ] Prueba de repetición: reenviar una trama válida capturada se rechaza por número de secuencia

### `07VerificacionDeRequisitos` (sección 5 del enunciado)

- [ ] ✓ Python 3 y sockets TCP/IP
- [ ] ✓ Biblioteca criptográfica reconocida (`cryptography`)
- [ ] ✓ Handshake basado en criptografía asimétrica (RSA-OAEP)
- [ ] ✓ Clave de sesión generada dinámicamente y no fija en el código (revisar con `git grep` que no haya llaves en el código)
- [ ] ✓ Ninguna llave privada se transmite por el socket (revisión de código + captura)
- [ ] ✓ Mensajes posteriores al handshake cifrados con esquema autenticado (AES-256-GCM)
- [ ] ✓ Nonce correcto y no repetido bajo la misma clave
- [ ] ✓ Rechazo de mensajes con authentication tag inválido
- [ ] ✓ Evidencia visible de plaintext local, ciphertext enviado, ciphertext recibido y plaintext recuperado
- [ ] ✗ Verificar que Base64 o hexadecimal se usan **solo** para mostrar o transportar, nunca como "cifrado"
- [ ] ✗ Verificar que no se usa ECB en ninguna parte (`git grep -i ecb`)
- [ ] Completar la tabla de cumplimiento del `.tex` (requisito, dónde se cumple y evidencia)

### `08Documentacion`

- [ ] `README.md` completo: instalación en Windows, generación de llaves, cómo iniciar cada instancia y guion para reproducir la demostración y la prueba de manipulación
- [ ] `DescripcionDelProtocolo.tex`: algoritmo asimétrico, algoritmo simétrico, tamaños de llave, estructura de los mensajes, diagramas de secuencia finales y análisis de seguridad
- [ ] Diagrama de secuencia del handshake actualizado con los mensajes reales
- [ ] Tabla del formato de trama con los tamaños reales
- [ ] Capturas de evidencia en `docs/img/` (handshake, conversación, ciphertext vs. plaintext, rechazo por manipulación y, opcionalmente, Wireshark)
- [ ] Respuestas breves a las 7 preguntas de cierre
- [ ] `referencias.bib` (documentación de `cryptography`, RFC 8017 para OAEP, NIST SP 800-38D para GCM y el material del curso)
- [ ] Declaración de uso de IA
- [ ] Compilar el PDF final y revisar ortografía

### `09VideoDeDemostracion` (4–6 minutos, ambos integrantes participan)

- [ ] Guion con tiempos asignados por integrante
- [ ] Herramienta de grabación (OBS Studio o la Grabadora de Xbox Game Bar); resolución legible y fuente de consola grande
- [ ] Mostrar las dos terminales visibles a la vez en la misma PC
- [ ] Conexión e indicador de handshake completado antes del primer mensaje
- [ ] Conversación en ambos sentidos (≥ 3 mensajes por lado)
- [ ] Comparar el mensaje legible con el ciphertext realmente transmitido (y opcionalmente Wireshark)
- [ ] Recepción, verificación y descifrado en el extremo opuesto
- [ ] Prueba de manipulación y rechazo correspondiente
- [ ] Explicación breve de dónde se usa la criptografía asimétrica y dónde la simétrica
- [ ] Ensayo completo y revisión del audio antes de la grabación final

### `10Entrega`

- [ ] Clonar el repositorio desde cero en una carpeta limpia y seguir el README al pie de la letra (prueba de reproducibilidad)
- [ ] `pytest` en verde
- [ ] Versión final etiquetada (`git tag v1.0`)
- [ ] Subir el código fuente, el README, el PDF del protocolo y el enlace al video según indique el profesor
- [ ] Confirmar que no hay llaves privadas ni secretos en el historial del repositorio