# =============================================================================
# shared_config.py (srcShared)
# -----------------------------------------------------------------------------
# Protocol constants that MUST be identical for Alice and Bob. Keeping them
# in one shared file makes it impossible for the two sides to disagree.
#
# Constants that belong to only one participant (name, port, timeouts, menu
# title...) stay in srcAlice/config.py or srcBob/config.py.
# =============================================================================

import struct


# -----------------------------------------------------------------------------
# Framing (how messages are delimited inside the TCP byte stream)
# -----------------------------------------------------------------------------
# Every frame starts with an unsigned 32-bit big-endian integer ("!I") that
# says how many payload bytes follow.
LENGTH_PREFIX_FORMAT = "!I"

# Size in bytes of the prefix above (4 for "!I").
LENGTH_PREFIX_SIZE = struct.calcsize(LENGTH_PREFIX_FORMAT)

# Largest payload accepted in one frame (64 KiB). Anything larger is treated
# as a protocol violation and the connection is closed.
MAX_FRAME_SIZE = 64 * 1024


# -----------------------------------------------------------------------------
# Text
# -----------------------------------------------------------------------------
# Text encoding used for every string that travels through the socket.
TEXT_ENCODING = "utf-8"


# -----------------------------------------------------------------------------
# RSA key pair (Paso 2)
# -----------------------------------------------------------------------------
# Modulus size in bits for newly generated keys. 3072 bits gives about 128 bits
# of security (NIST SP 800-57) and stays valid beyond 2030; 2048 is the
# minimum the workshop allows.
RSA_KEY_SIZE = 3072

# Smallest modulus accepted when LOADING a key from disk.
RSA_MINIMUM_KEY_SIZE = 2048

# Public exponent e. 65537 is the standard value (fast and safe).
RSA_PUBLIC_EXPONENT = 65537


# -----------------------------------------------------------------------------
# Key files (each participant keeps them inside its own folder: srcXxx/keys/)
# -----------------------------------------------------------------------------
# Name of the folder, created inside srcAlice/ or srcBob/. It is listed in
# .gitignore ("keys/"), so nothing inside it can be committed by accident.
KEYS_FOLDER_NAME = "keys"

# Private key: PEM, PKCS#8, encrypted with the passphrase.
PRIVATE_KEY_FILE_NAME = "private_key.pem"

# Public key: PEM, SubjectPublicKeyInfo (X.509 public key format).
PUBLIC_KEY_FILE_NAME = "public_key.pem"


# -----------------------------------------------------------------------------
# Passphrase that encrypts the private key on disk
# -----------------------------------------------------------------------------
MIN_PASSPHRASE_LENGTH = 8


# -----------------------------------------------------------------------------
# Public key fingerprint
# -----------------------------------------------------------------------------
# SHA-256 over the DER encoding of the public key -> 32 bytes.
FINGERPRINT_SIZE_BYTES = 32

# Bytes shown in the short version of the fingerprint (first 8 bytes).
FINGERPRINT_SHORT_SIZE_BYTES = 8


# -----------------------------------------------------------------------------
# Key self-test (menu option "Verificar mis llaves")
# -----------------------------------------------------------------------------
# Size of the random test value that is signed and encrypted during the test.
KEY_SELF_TEST_SIZE_BYTES = 32


# -----------------------------------------------------------------------------
# Handshake (Paso 3)
# -----------------------------------------------------------------------------
# Label that starts every handshake transcript. Changing the protocol version
# changes every hash, so messages from another version are never accepted.
PROTOCOL_LABEL = "SecureChat-v1"

# Random value each side contributes to the handshake (client_random from
# Alice, server_random from Bob). Makes every session's transcript unique, so
# a recorded old handshake cannot be replayed.
HANDSHAKE_RANDOM_SIZE_BYTES = 32

# Size of the symmetric session key (AES-256).
SESSION_KEY_SIZE_BITS = 256

# Every variable-length field inside a handshake message is preceded by its
# length as an unsigned 32-bit big-endian integer.
FIELD_LENGTH_FORMAT = "!I"

# Plaintext of the two key-confirmation messages. Each side encrypts its own
# label with the new session key; the other side checks it decrypts correctly.
CONFIRMATION_LABEL_RESPONDER = "SecureChat-v1:confirmacion:responder"
CONFIRMATION_LABEL_INITIATOR = "SecureChat-v1:confirmacion:iniciador"

# The session id is the first bytes of the final transcript hash. Both sides
# compute it independently; seeing the same value on both screens shows that
# both processed exactly the same handshake.
SESSION_ID_SIZE_BYTES = 8


# -----------------------------------------------------------------------------
# AES-GCM
# -----------------------------------------------------------------------------
# 96-bit nonce, the size recommended for GCM (NIST SP 800-38D).
AES_GCM_NONCE_SIZE_BYTES = 12

# GCM authentication tag size (128 bits). The library appends it to the
# ciphertext.
AES_GCM_TAG_SIZE_BYTES = 16


# -----------------------------------------------------------------------------
# Nonce layout (Paso 4)
# -----------------------------------------------------------------------------
# Alice and Bob encrypt with the SAME session key, so each direction gets its
# own nonce space:
#
#     nonce (12 bytes) = direction (1 byte) || counter (11 bytes, big-endian)
#
# Two nonces from different directions always differ in the first byte, and
# two nonces from the same direction always differ in the counter. Therefore
# no nonce can ever repeat under the same key.
NONCE_DIRECTION_SIZE_BYTES = 1
NONCE_COUNTER_SIZE_BYTES = 11

# Direction bytes.
DIRECTION_INITIATOR_TO_RESPONDER = 1   # Alice -> Bob
DIRECTION_RESPONDER_TO_INITIATOR = 2   # Bob -> Alice

# Counter 0 of each direction is used ONCE by the handshake confirmation.
HANDSHAKE_CONFIRMATION_COUNTER = 0

# Chat messages of each direction start at this counter (1, 2, 3, ...).
FIRST_MESSAGE_COUNTER = 1

# Largest counter that fits in NONCE_COUNTER_SIZE_BYTES (2^88 - 1). If a
# direction ever reached it, the session would end instead of reusing a nonce.
MAX_MESSAGE_COUNTER = (2 ** (8 * NONCE_COUNTER_SIZE_BYTES)) - 1

# Associated data (authenticated, not encrypted) of every chat record:
#     PROTOCOL_LABEL || type (1 B) || session id (8 B) || nonce (12 B)
# The nonce already carries the direction and the sequence number.


# -----------------------------------------------------------------------------
# Console evidence
# -----------------------------------------------------------------------------
# How many bytes of a binary value are shown in hexadecimal on screen.
HEX_PREVIEW_SIZE_BYTES = 16

# How many bytes of a chat ciphertext are shown in hexadecimal (Paso 4).
MESSAGE_HEX_PREVIEW_SIZE_BYTES = 48