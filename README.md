# SecureChat — Comunicación segura con criptografía híbrida

> Taller de Criptografía Aplicada · CE-1115 Seguridad de la Información · II Semestre, 2026
> Escuela de Ingeniería en Computadores — Tecnológico de Costa Rica

**Integrantes:** Adriel S. Chaves Salazar · Henry D. Núñez Pérez
**Profesor:** MSc. Andrés F. Vargas Rivera

Chat de consola entre dos procesos en la misma computadora. La sesión se establece con **RSA-OAEP** y cada mensaje se protege con **AES-256-GCM**.

---

## Tabla de contenidos

1. [Descripción general](#1-descripción-general)
2. [Requisitos](#2-requisitos)
3. [Estructura del repositorio](#3-estructura-del-repositorio)
4. [Instalación en Windows](#4-instalación-en-windows)
5. [Generación de llaves](#5-generación-de-llaves)
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

> **PENDIENTE:** párrafo final que explique qué hace la aplicación y el flujo plaintext local → AES-GCM → ciphertext en tránsito → verificación → plaintext recuperado.

- La criptografía **asimétrica** (RSA-OAEP) se usa solo en el handshake, para proteger la clave de sesión.
- La criptografía **simétrica autenticada** (AES-256-GCM) protege cada mensaje del chat.
- Después del handshake, por el socket solo viaja ciphertext.

## 2. Requisitos

| Elemento | Versión / detalle |
|---|---|
| Sistema operativo | Windows 10 u 11 |
| Python | 3.10 o superior, 64 bits (`py -3 --version`) |
| Terminal | Windows Terminal (recomendado) o PowerShell |
| Dependencias | Ver `requirements.txt` (`cryptography`, ...) |
| Opcional | Wireshark + Npcap con soporte de loopback (para capturar el tráfico de localhost) |

## 3. Estructura del repositorio

> **PENDIENTE:** actualizar con la estructura final.

```text
SecureChat_Workshop/
├── src/securechat/          # código fuente (PENDIENTE)
├── scripts/                 # utilidades (generación de llaves, proxy de manipulación) (PENDIENTE)
├── tests/                   # pruebas con pytest (PENDIENTE)
├── docs/
│   ├── DescripcionDelProtocolo.tex
│   ├── referencias.bib
│   └── img/
├── keys/                    # llaves locales — NO se versiona
├── PlanDeDesarrollo.md
├── README.md
├── requirements.txt
└── .gitignore
```

## 4. Instalación en Windows

```powershell
git clone https://github.com/Adriel23456/SecureChat_Workshop.git
cd SecureChat_Workshop

py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt
```

Si PowerShell bloquea la activación del entorno virtual:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## 5. Generación de llaves

> **PENDIENTE:** comando final, tamaño de llave (2048/3072), ruta de salida y si la llave privada se protege con frase de paso.

```powershell
# PENDIENTE
python <script_de_llaves> --name bob
python <script_de_llaves> --name alice
```

- La llave privada se queda en `keys/<participante>/` y **nunca** sale de la máquina ni se sube al repositorio.
- La llave pública se puede compartir. El programa muestra solo su huella SHA-256.

## 6. Ejecución

Abrir **dos terminales** (en Windows Terminal: `Alt+Shift+D` divide el panel), activar el entorno virtual en ambas y ejecutar:

**Terminal B — Bob (espera conexiones):**

```powershell
# PENDIENTE
python -m securechat <argumentos de Bob>
```

**Terminal A — Alice (inicia la conexión):**

```powershell
# PENDIENTE
python -m securechat <argumentos de Alice>
```

### Comandos dentro del chat

| Comando | Acción |
|---|---|
| `/salir` | Cierra la sesión de forma controlada (PENDIENTE) |
| `PENDIENTE` | PENDIENTE |

### Leyenda de la salida en consola

| Etiqueta | Significado |
|---|---|
| `PENDIENTE` | Mensaje local (plaintext antes de cifrar) |
| `PENDIENTE` | Datos cifrados enviados (nonce, ciphertext, tag) |
| `PENDIENTE` | Datos cifrados recibidos |
| `PENDIENTE` | Mensaje recuperado después de verificar el tag |
| `PENDIENTE` | Error o mensaje rechazado |

## 7. Reproducir la demostración

> **PENDIENTE:** completar con las capturas y la salida esperada.

1. Iniciar Bob y luego Alice.
2. Esperar el indicador **sesión segura establecida** en ambas terminales.
3. Enviar al menos **3 mensajes de Alice** y **3 de Bob**.
4. Comparar en el emisor el plaintext con el ciphertext enviado.
5. Verificar en el receptor que el plaintext aparece solo después de la verificación.
6. Ejecutar la prueba de manipulación (sección 8).
7. Cerrar la sesión con `/salir`.

### (Opcional) Ver el tráfico real con Wireshark

> **PENDIENTE:** pasos para capturar en el *Npcap Loopback Adapter* con el filtro `tcp.port == <PUERTO>`.

## 8. Prueba de manipulación

> **PENDIENTE:** mecanismo final (bandera `--tamper` en el emisor o proxy intermedio) y comando.

```powershell
# PENDIENTE
```

Resultado esperado: el receptor detecta que el authentication tag no es válido, rechaza el mensaje y **no muestra ningún plaintext**.

## 9. Pruebas automatizadas

```powershell
pip install -r requirements-dev.txt
pytest -v
```

> **PENDIENTE:** lista de pruebas (framing, nonce único, rechazo por tag inválido, plaintext ausente en los bytes enviados, replay).

## 10. Resumen del protocolo

La descripción completa está en `docs/DescripcionDelProtocolo.pdf`.

| Elemento | Decisión |
|---|---|
| Algoritmo asimétrico | RSA-PENDIENTE bits, OAEP con SHA-256 y MGF1 |
| Algoritmo simétrico | AES-256-GCM |
| Clave de sesión | 256 bits, generada con CSPRNG en cada sesión |
| Nonce | 96 bits, PENDIENTE (contador por dirección / aleatorio) |
| Authentication tag | 128 bits |
| Formato de trama | PENDIENTE |

## 11. Preguntas de cierre

> **PENDIENTE:** respuestas breves (también incluidas en el documento del protocolo).

1. ¿Qué problema resuelve la criptografía asimétrica durante el handshake?
2. ¿Por qué la conversación utiliza criptografía simétrica después del handshake?
3. ¿Qué información puede observar un tercero que capture los paquetes de la conversación?
4. ¿Por qué el nonce puede viajar junto al ciphertext y por qué no debe repetirse?
5. ¿Qué función cumple el authentication tag?
6. ¿Qué ocurriría si la clave de sesión se transmitiera sin protección?
7. ¿Qué ocurriría si un atacante obtiene una de las claves privadas?

## 12. Solución de problemas en Windows

| Problema | Solución |
|---|---|
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `ConnectionRefusedError` | Bob debe estar escuchando antes de que Alice se conecte; revisar el puerto |
| `Address already in use` | Esperar unos segundos o cambiar de puerto |
| Aviso del Firewall de Windows | Escuchar solo en `127.0.0.1`; si aparece, permitir solo redes privadas |
| Tildes y ñ se ven mal | Usar Windows Terminal; PENDIENTE |
| Ctrl+C no cierra el programa | Usar `/salir`; PENDIENTE |

## 13. Declaración de uso de IA

> **PENDIENTE.**