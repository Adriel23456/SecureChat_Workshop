# =============================================================================
# config.py (Bob)
# -----------------------------------------------------------------------------
# Every constant used by Bob's program lives in this file. Nothing else in
# srcBob should hard-code a host, port, size, timeout or command.
#
# Protocol constants shared with the other side (frame size, length prefix,
# text encoding) live in srcShared/shared_config.py.
# =============================================================================

# -----------------------------------------------------------------------------
# Identity
# -----------------------------------------------------------------------------
# Name this instance announces to the peer during the initial greeting.
LOCAL_NAME = "Bob"

# Name we expect the peer to announce. If it differs, a warning is shown.
EXPECTED_PEER_NAME = "Alice"


# -----------------------------------------------------------------------------
# Network
# -----------------------------------------------------------------------------
# Bob only listens on the loopback interface. Binding to 127.0.0.1 (and not
# 0.0.0.0) keeps the socket unreachable from other machines and usually avoids
# the Windows Firewall prompt.
HOST = "127.0.0.1"

# Port Bob listens on. Must match PORT in srcAlice/config.py. Any value
# above 1024 avoids privileged ports.
PORT = 5050

# Maximum number of pending connections queued by listen().
# Bob only talks to one peer, so one is enough.
LISTEN_BACKLOG = 1


# -----------------------------------------------------------------------------
# Timeouts (seconds)
# -----------------------------------------------------------------------------
# Blocking socket calls (accept, recv) wake up at this interval so the program
# can check whether it should stop and so Ctrl+C works on Windows.
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
# File inside srcBob/keys/ that stores the SHA-256 fingerprint of the peer's
# public key, verified by the user through an independent channel.
TRUSTED_PEER_FINGERPRINT_FILE_NAME = "trusted_alice_fingerprint.txt"


# -----------------------------------------------------------------------------
# Handshake evidence (Paso 3)
# -----------------------------------------------------------------------------
# True: print every handshake step with the size and first bytes (hex) of the
# PUBLIC values that travel (randoms, RSA ciphertext, signature, AES-GCM
# confirmation). The session key and private key are never printed.
SHOW_HANDSHAKE_DETAILS = True


# -----------------------------------------------------------------------------
# Console
# -----------------------------------------------------------------------------
# Set to False if the terminal shows strange characters such as "[92m".
USE_COLORS = True

# Program title shown in the banner.
APP_TITLE = "SecureChat - Bob (servidor)"