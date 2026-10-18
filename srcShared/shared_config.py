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