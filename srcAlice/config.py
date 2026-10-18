# =============================================================================
# config.py (Alice)
# -----------------------------------------------------------------------------
# Every constant used by Alice's program lives in this file. Nothing else in
# srcAlice should hard-code a host, port, size, timeout or command.
#
# Protocol constants shared with the other side (frame size, length prefix,
# text encoding) live in srcShared/shared_config.py.
# =============================================================================

# -----------------------------------------------------------------------------
# Identity
# -----------------------------------------------------------------------------
# Name this instance announces to the peer during the initial greeting.
LOCAL_NAME = "Alice"

# Name we expect the peer to announce. If it differs, a warning is shown.
EXPECTED_PEER_NAME = "Bob"


# -----------------------------------------------------------------------------
# Network
# -----------------------------------------------------------------------------
# Address where Bob is listening (same machine, loopback interface).
HOST = "127.0.0.1"

# Port where Bob is listening. Must match PORT in srcBob/config.py.
PORT = 5050

# How long connect() may take before giving up.
CONNECT_TIMEOUT = 5.0


# -----------------------------------------------------------------------------
# Timeouts (seconds)
# -----------------------------------------------------------------------------
# Blocking socket calls (recv) wake up at this interval so the program can
# check whether it should stop and so Ctrl+C works on Windows.
SOCKET_POLL_TIMEOUT = 1.0

# Maximum time to wait for EACH handshake message from the peer. If it
# expires, the handshake is aborted and the connection is closed.
HANDSHAKE_TIMEOUT = 15.0

# How long to wait for the receiver thread to finish when closing a session.
RECEIVER_JOIN_TIMEOUT = 3.0


# -----------------------------------------------------------------------------
# Chat
# -----------------------------------------------------------------------------
# Command that ends the session in an orderly way.
EXIT_COMMAND = "/salir"


# -----------------------------------------------------------------------------
# Keys (Paso 2)
# -----------------------------------------------------------------------------
# File inside srcAlice/keys/ that stores the SHA-256 fingerprint of the peer's
# public key, verified by the user through an independent channel.
TRUSTED_PEER_FINGERPRINT_FILE_NAME = "trusted_bob_fingerprint.txt"


# -----------------------------------------------------------------------------
# Handshake evidence (Paso 3)
# -----------------------------------------------------------------------------
# True: print every handshake step with the size and first bytes (hex) of the
# PUBLIC values that travel (randoms, RSA ciphertext, signature, AES-GCM
# confirmation). The session key and private key are never printed.
SHOW_HANDSHAKE_DETAILS = True


# -----------------------------------------------------------------------------
# Message evidence (Paso 4)
# -----------------------------------------------------------------------------
# True: for every chat message show the nonce, ciphertext and tag in hex (sent
# and received). False: show only a one-line summary per record.
SHOW_MESSAGE_DETAILS = True


# -----------------------------------------------------------------------------
# Console
# -----------------------------------------------------------------------------
# Set to False if the terminal shows strange characters such as "[92m".
USE_COLORS = True

# Program title shown in the banner.
APP_TITLE = "SecureChat - Alice (cliente)"