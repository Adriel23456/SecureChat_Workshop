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