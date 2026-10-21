# SecureChat — Comunicación segura con criptografía híbrida

> Taller de Criptografía Aplicada · CE-1115 Seguridad de la Información · II Semestre, 2026
> Escuela de Ingeniería en Computadores — Tecnológico de Costa Rica

**Integrantes:** Adriel S. Chaves Salazar · Henry D. Núñez Pérez
**Profesor:** MSc. Andrés F. Vargas Rivera
**Repositorio:** https://github.com/Adriel23456/SecureChat_Workshop

Chat de consola entre dos procesos en la misma computadora. La sesión se establece con **RSA-OAEP** y cada mensaje se protege con **AES-256-GCM**.

---

## Tabla de contenidos

1. [Descripción general](#1-descripción-general)
2. [Requisitos](#2-requisitos)
3. [Estructura del repositorio](#3-estructura-del-repositorio)
4. [Instalación en Windows](#4-instalación-en-windows)
5. [Generación de llaves y registro de huellas](#5-generación-de-llaves-y-registro-de-huellas)
6. [Ejecución](#6-ejecución)
7. [Reproducir la demostración](#7-reproducir-la-demostración)
8. [Prueba de manipulación](#8-prueba-de-manipulación)
9. [Pruebas automatizadas](#9-pruebas-automatizadas)
10. [Resumen del protocolo](#10-resumen-del-protocolo)
11. [Preguntas de cierre](#11-preguntas-de-cierre)
12. [Solución de problemas en Windows](#12-solución-de-problemas-en-windows)
13. [Declaración de uso de IA](#13-declaración-de-uso-de-ia)

---

## 1. Descripción general

SecureChat ejecuta dos programas, uno para **Alice** (`srcAlice`) y otro para **Bob** (`srcBob`), que se comunican por un socket TCP en `127.0.0.1`. Antes de permitir cualquier mensaje, ambos completan un **handshake**:

- Cada participante tiene un par de llaves **RSA-3072**. Cada uno registra antes la **huella SHA-256** de la llave pública del otro, comparada por un canal independiente.
- Alice genera una **clave de sesión aleatoria de 256 bits** y la envía cifrada con la llave pública de Bob (**RSA-OAEP**). Además firma el handshake con su llave privada (**RSA-PSS**).
- Ambos confirman con AES-GCM que tienen la misma clave. Las dos terminales muestran **SESION SEGURA ESTABLECIDA** con el mismo id de sesión.

Después, cada mensaje sigue este camino:

```text
Mensaje legible -> AES-256-GCM cifra y autentica -> ciphertext en tránsito -> verificación del tag y descifrado -> mensaje recuperado
```

- La criptografía **asimétrica** (RSA) se usa solo en el handshake, para proteger la clave de sesión y autenticar a los participantes.
- La criptografía **simétrica autenticada** (AES-256-GCM) protege cada mensaje del chat y la despedida.
- Después del handshake, por el socket solo viajan nonce, ciphertext y tag. El texto del usuario nunca viaja en claro.

## 2. Requisitos

| Elemento | Versión / detalle |
|---|---|
| Sistema operativo | Windows 10 u 11 |
| Python | 3.10 o superior, 64 bits (`py -3 --version`). Probado con Python 3.13 y 3.15 |
| Terminal | Windows Terminal (recomendado), PowerShell o la terminal integrada de VS Code |
| Dependencias | `requirements.txt`: `cryptography` y `pytest` |
| Documento | Distribución LaTeX (MiKTeX, TeX Live u Overleaf) para compilar `DescripcionDelProtocolo.tex` |

## 3. Estructura del repositorio

```text
SecureChat_Workshop/
├── srcAlice/                 # programa de Alice (cliente)
│   ├── main.py               # menú de Alice
│   ├── config.py             # constantes de Alice
│   ├── tcp_client.py         # connect()
│   ├── alice_handshake.py    # pasos del handshake de Alice
│   ├── .venv/                # entorno virtual de Alice (no se versiona)
│   └── keys/                 # llaves de Alice (no se versiona)
├── srcBob/                   # programa de Bob (servidor)
│   ├── main.py, config.py, tcp_server.py, bob_handshake.py
│   ├── .venv/                # entorno virtual de Bob (no se versiona)
│   └── keys/                 # llaves de Bob (no se versiona)
├── srcShared/                # código común (framing, mensajes, llaves, AES-GCM, consola...)
├── tests/
│   ├── test_secure_channel.py   # 13 pruebas: cifrado, nonces, repetición
│   ├── test_console_input.py    # 9 pruebas: prompt del chat
│   └── test_tampering.py        # 19 pruebas: manipulación y política de rechazo
├── DescripcionDelProtocolo/
│   ├── DescripcionDelProtocolo.tex
│   ├── referencias.bib
│   └── img/                  # TUlogo.png y capturas de evidencia
├── requirements.txt
├── CurrentCommands.txt       # comandos rápidos
├── README.md
├── LICENSE
└── .gitignore                # excluye .venv/, keys/, __pycache__/, *.pem, auxiliares de LaTeX
```

## 4. Instalación en Windows

Todos los comandos se ejecutan en **PowerShell desde la raíz del repositorio**.

```powershell
git clone https://github.com/Adriel23456/SecureChat_Workshop.git
cd SecureChat_Workshop

# Entorno virtual de Bob
py -3 -m venv srcBob\.venv
srcBob\.venv\Scripts\python.exe -m pip install --upgrade pip
srcBob\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Entorno virtual de Alice
py -3 -m venv srcAlice\.venv
srcAlice\.venv\Scripts\python.exe -m pip install --upgrade pip
srcAlice\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Si PowerShell bloquea la activación de los entornos (`Activate.ps1 cannot be loaded`):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## 5. Generación de llaves y registro de huellas

Se hace **una sola vez** por par de llaves. Abre los dos programas (sección 6) y en cada uno:

| Paso | Bob | Alice |
|---|---|---|
| 1 | Opción **2** *Generar mi par de llaves RSA*. Elige una frase de paso (mínimo 8 caracteres) y escríbela dos veces. | Igual, con su propia frase de paso. |
| 2 | Opción **3** *Ver huella de mi llave pública*. Anota o dicta la huella `SHA256:...`. | Igual. |
| 3 | Opción **4** *Registrar huella de confianza de Alice*. Pega la huella de Alice y confirma con `s` **después de compararla con la que Alice ve en su pantalla**. | Opción **4** con la huella de Bob. |
| 4 | Opción **5** *Verificar mis llaves* (opcional): debe decir «aprobado». | Igual. |

- La llave privada se guarda en `srcXxx\keys\private_key.pem`, **cifrada con la frase de paso**. Nunca se muestra, nunca se sube al repositorio y nunca viaja por el socket.
- La llave pública (`public_key.pem`) se puede compartir. El programa solo muestra su huella.
- La frase de paso se pide sin eco en pantalla y no se guarda en ningún lado.
- Si se regeneran las llaves de un lado, el otro debe volver a registrar la huella (opción 4).

## 6. Ejecución

Abre **dos terminales**. En Windows Terminal, `Alt+Shift+D` divide el panel en dos.

**Terminal 1 — Bob (primero, espera la conexión):**

```powershell
cd srcBob
.\.venv\Scripts\Activate.ps1
python main.py
# Menú: opción 1 (Esperar conexión de Alice) y luego la frase de paso de Bob
```

**Terminal 2 — Alice (después, se conecta):**

```powershell
cd srcAlice
.\.venv\Scripts\Activate.ps1
python main.py
# Menú: opción 1 (Conectarse con Bob) y luego la frase de paso de Alice
```

Alternativa sin activar ni cambiar de carpeta (desde la raíz):

```powershell
srcBob\.venv\Scripts\python.exe srcBob\main.py
srcAlice\.venv\Scripts\python.exe srcAlice\main.py
```

### Menú (igual en ambos lados)

| Opción | Acción |
|---|---|
| 1 | Bob: esperar la conexión de Alice. Alice: conectarse con Bob. Luego handshake y chat. |
| 2 | Generar mi par de llaves RSA |
| 3 | Ver la huella de mi llave pública |
| 4 | Registrar la huella de confianza del otro participante |
| 5 | Verificar mis llaves (prueba de correspondencia) |
| 6 | Ver la configuración actual |
| 7 | Salir |

### Comandos dentro del chat

Las líneas que empiezan con `/` son comandos locales y **nunca se envían** al otro participante.

| Comando | Acción |
|---|---|
| `/ayuda` | Lista los comandos |
| `/detalle` | Activa o desactiva la vista de nonce, ciphertext y tag (cada terminal decide la suya) |
| `/estado` | Id de sesión, mensajes enviados, recibidos y rechazados, rechazos seguidos y último número de secuencia de cada dirección |
| `/alterar [ct\|tag\|nonce\|tipo]` | **Prueba de integridad:** el próximo mensaje sale con 1 byte alterado (por defecto `ct`) |
| `/salir` | Envía una despedida **cifrada** y cierra la sesión; ambos lados vuelven solos al menú |
| `Ctrl+C` | También cierra la sesión enviando la despedida cifrada |

### Leyenda de la salida en consola

| Etiqueta | Significado |
|---|---|
| `[TÚ] > ` | Tu prompt |
| `[TÚ] texto` | Tu mensaje en texto plano, antes de cifrar (no sale de tu terminal) |
| `[CIFRADO →]` | Lo que sale por el socket: seq, tamaño y, con `/detalle`, nonce, ciphertext y tag |
| `[← CIFRADO]` | Lo que llegó del socket, antes de cualquier verificación |
| `[TAG OK]` | El tag de AES-GCM es válido |
| `[ALICE]` / `[BOB]` | Mensaje recuperado, mostrado **solo** después de verificar el tag |
| `[!] MENSAJE RECHAZADO` | El mensaje no pasó la verificación; no se muestra su contenido |
| `[!]` | Errores y advertencias |
| `[i]` | Información |

## 7. Reproducir la demostración

Demostración de unos 5 minutos, con los dos integrantes:

1. **Arranque:** muestra las dos terminales lado a lado. Bob elige la opción 1 y escribe su frase de paso; luego Alice hace lo mismo.
2. **Handshake:** se ven los pasos `[HS ->]` / `[HS <-]` y el banner **SESION SEGURA ESTABLECIDA** en ambas terminales. Señala que el **Id de sesión es igual** en las dos y que la clave de sesión no se muestra.
3. **Conversación:** envía al menos **3 mensajes de Alice y 3 de Bob, intercalados** (A1 → B1 → A2 → B2 → A3 → B3). El `seq` sube 1, 2, 3 en cada dirección.
4. **Plaintext vs. ciphertext:** con la vista detallada activa, compara en el emisor `[TÚ] texto` con `[CIFRADO →]` (nonce, ciphertext y tag en hexadecimal). Destaca que el hexadecimal solo sirve para mostrar bytes: no es cifrado.
5. **Recepción:** en el otro lado se ve `[← CIFRADO]`, luego `[TAG OK]` y solo entonces `[BOB]` / `[ALICE]` con el texto recuperado.
6. **Manipulación:** ejecuta la prueba de la sección 8.
7. **Cierre:** `/salir` en Alice. Bob muestra que Alice cerró la sesión (despedida verificada) y ambos muestran el **Resumen de la sesión**.
8. **Explicación:** la asimétrica (RSA-OAEP y RSA-PSS) solo protege la clave de sesión y autentica en el handshake; la simétrica (AES-256-GCM) protege cada mensaje.

## 8. Prueba de manipulación

La prueba se hace con el comando `/alterar` **dentro del emisor**. El mensaje siguiente se cifra normalmente y, **después de cifrar y antes de enviar**, se cambia exactamente un byte del registro. El prefijo de longitud nunca se toca, así que la trama llega completa y con el mismo tamaño. Para el receptor es igual que una modificación en tránsito.

| Comando | Byte alterado | Qué demuestra |
|---|---|---|
| `/alterar` o `/alterar ct` | Un byte del ciphertext | Cambiar el contenido cifrado se detecta |
| `/alterar tag` | El último byte del tag | Un tag falso se detecta |
| `/alterar nonce` | El byte más alto del contador del nonce | El nonce está autenticado (el contador pasa la comprobación de secuencia, pero falla el tag) |
| `/alterar tipo` | Tipo CHAT → BYE | El tipo forma parte de la AAD: no se puede convertir un mensaje en una despedida falsa |

**Pasos (con la sesión ya establecida):**

1. En **Alice**: `/alterar` → aparece `[!] PRUEBA DE INTEGRIDAD: el proximo mensaje que envie saldra con 1 byte alterado (ct).`
2. En **Alice**: escribe `transferir 100 colones` y Enter. Alice ve su `[TÚ]`, el `[CIFRADO →]` y la línea `[!] PRUEBA: se altero 1 byte del ciphertext ...` con la posición y el valor original → alterado.
3. En **Bob** debe verse:
```text
   [← CIFRADO] de Alice | trama de 51 bytes recibida
   [!] MENSAJE RECHAZADO: autenticacion fallida
   [!]   motivo: Tag de autenticacion invalido: el mensaje fue alterado o no pertenece a esta sesion.
   [!]   no se muestra ningun plaintext de este mensaje; se descarta.
   [!]   rechazos seguidos: 1 de 3 (al llegar al maximo se cierra la sesion)
```
   **No aparece** ningún `[ALICE] transferir ...`.
4. En **Alice**: envía un mensaje normal (`mensaje legitimo`). Bob lo muestra con `[TAG OK]`: un rechazo no rompe la sesión.
5. Repite con `/alterar tag`, `/alterar nonce` y `/alterar tipo`; el resultado en Bob es el mismo.
6. **Política de rechazo:** si se envían 3 mensajes alterados **seguidos** (sin un mensaje válido entre ellos), Bob muestra `Se rechazaron 3 mensajes seguidos. El canal se considera comprometido; se cierra la sesion.` y ambos vuelven al menú.
7. `/estado` en cada lado muestra cuántos mensajes se alteraron (emisor) y cuántos se rechazaron (receptor).

**Política elegida:** un mensaje rechazado se descarta y la sesión continúa. Así un atacante no puede cortar el chat con un solo byte. Tras **3 rechazos seguidos** (`MAX_CONSECUTIVE_REJECTIONS` en `srcShared/shared_config.py`), el canal se considera comprometido y la sesión se cierra para empezar otra con una clave nueva.

La **repetición** de una trama válida capturada se comprueba con las pruebas automáticas (sección 9): una trama ya aceptada vuelve a llegar con un número de secuencia viejo y se rechaza.

## 9. Pruebas automatizadas

```powershell
srcBob\.venv\Scripts\python.exe -m pytest tests -v
```

Resultado esperado: **41 passed**.

| Archivo | Pruebas | Qué comprueba |
|---|---|---|
| `test_secure_channel.py` | 13 | El plaintext no aparece en los bytes enviados; 10 000 nonces sin repetición; direcciones disjuntas; cualquier byte alterado se rechaza; repetición, reflexión, cambio de tipo, otra sesión y agotamiento del contador |
| `test_console_input.py` | 9 | Prompt del chat: Backspace, teclas especiales, tildes y ñ, Ctrl+C, fin de sesión y texto preservado cuando llega un mensaje |
| `test_tampering.py` | 19 | 1 byte alterado en ciphertext, tag, nonce o AAD produce `InvalidTag` (con `AESGCM` directo y con `SecureChannel`); `/alterar` cambia exactamente 1 byte sin cambiar el tamaño; repetición de una trama capturada; el siguiente mensaje legítimo se acepta; política de rechazos |

## 10. Resumen del protocolo

La descripción completa está en `DescripcionDelProtocolo/DescripcionDelProtocolo.pdf`.

| Elemento | Decisión |
|---|---|
| Algoritmo asimétrico | RSA-3072, `e = 65537`; OAEP (SHA-256, MGF1-SHA-256) para la clave de sesión; PSS (SHA-256) para la firma de Alice |
| Autenticación de llaves | Huella SHA-256 de la llave pública, verificada fuera de banda y registrada en `keys/` |
| Algoritmo simétrico | AES-256-GCM |
| Clave de sesión | 256 bits, generada por Alice con el CSPRNG del sistema en cada conexión |
| Nonce | 96 bits = dirección (1 B) ‖ contador (11 B); nunca se repite bajo la misma clave |
| AAD | `"SecureChat-v1"` ‖ tipo (1 B) ‖ id de sesión (8 B) ‖ nonce (12 B) |
| Authentication tag | 128 bits |
| Protección contra repetición | Número de secuencia estrictamente creciente por dirección |
| Formato de trama | `longitud (4 B)` \| `tipo (1 B)` \| `nonce (12 B)` \| `ciphertext (n B)` \| `tag (16 B)` → 33 + n bytes |
| Handshake | HELLO → HELLO → PUBLIC_KEY → SESSION_KEY → CONFIRM → CONFIRM (ABORT ante cualquier fallo) |

## 11. Preguntas de cierre

Las respuestas completas están en la sección 10 del documento del protocolo.

1. **¿Qué problema resuelve la criptografía asimétrica durante el handshake?** Permite acordar una clave secreta sin haber compartido antes un secreto (solo Bob puede descifrar la clave enviada con su llave pública) y autentica a los participantes (huellas y firma).
2. **¿Por qué la conversación utiliza criptografía simétrica después del handshake?** AES-GCM es mucho más rápido que RSA, cifra mensajes de cualquier tamaño y autentica cada uno con solo 33 bytes extra por trama.
3. **¿Qué información puede observar un tercero que capture los paquetes?** Direcciones, puertos, horas y tamaños; los nombres y valores aleatorios del HELLO; las llaves públicas; la clave de sesión *cifrada*; y de cada mensaje el tipo, el nonce, el ciphertext y el tag. No ve el texto de los mensajes ni la clave de sesión.
4. **¿Por qué el nonce puede viajar junto al ciphertext y por qué no debe repetirse?** No es secreto, solo debe ser único. Repetirlo con la misma clave revela el XOR de dos plaintexts y permite falsificar tags.
5. **¿Qué función cumple el authentication tag?** Detecta cualquier cambio en el ciphertext, el nonce o la AAD: si no coincide, el mensaje se rechaza sin mostrarse.
6. **¿Qué ocurriría si la clave de sesión se transmitiera sin protección?** Quien la capturara podría leer todos los mensajes y fabricar mensajes falsos con tags válidos.
7. **¿Qué ocurriría si un atacante obtiene una de las claves privadas?** Con la de Bob podría descifrar las claves de sesión de handshakes grabados y suplantar a Bob; con la de Alice, suplantar a Alice. Habría que generar llaves nuevas y registrar las huellas otra vez.

## 12. Solución de problemas en Windows

| Problema | Solución |
|---|---|
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Alice: «Nadie está escuchando en 127.0.0.1:5050» | Bob debe estar en la opción 1 antes de que Alice se conecte |
| Bob: `WinError 10048` (puerto en uso) | Hay otra instancia de Bob abierta; ciérrala o cambia `PORT` en **ambos** `config.py` |
| «Falta la huella de confianza del par» | Registra la huella del otro con la opción 4 (sección 5) |
| «La huella recibida no coincide» | Alguien regeneró sus llaves: vuelve a comparar y registrar las huellas |
| Frase de paso incorrecta | El chat no se inicia; vuelve a elegir la opción 1 y escríbela de nuevo. Si se olvidó, genera llaves nuevas (opción 2) y registra las huellas otra vez |
| Handshake abortado por tiempo | El otro lado tardó más de 15 s en un paso; vuelve a intentarlo |
| Aviso del Firewall de Windows | El programa solo escucha en `127.0.0.1`; si aparece, permite solo redes privadas |
| Se ven códigos como `[92m` | Usa Windows Terminal o pon `USE_COLORS = False` en `config.py` |
| Tildes y ñ se ven mal | Usa Windows Terminal; el texto viaja en UTF-8 |
| Hay que presionar Enter para volver al menú | La entrada está redirigida (por ejemplo, la consola de depuración de VS Code); ejecuta en una terminal real. La opción 6 indica el modo de entrada |
| `pytest` no se encuentra | Ejecútalo con el Python del entorno: `srcBob\.venv\Scripts\python.exe -m pytest tests -v` |

## 13. Declaración de uso de IA

Durante el taller se utilizó un asistente de inteligencia artificial (Claude, de Anthropic) como apoyo para planificar el desarrollo por pasos, proponer la estructura de clases y redactar borradores del código, de las pruebas automáticas y de la documentación. Los integrantes revisaron todo lo generado, tomaron las decisiones de diseño, ejecutaron cada paso en Windows, corrieron las 41 pruebas automáticas y verificaron manualmente la conversación y la prueba de manipulación. Ambos comprenden el flujo completo del protocolo y asumen la responsabilidad del trabajo entregado.