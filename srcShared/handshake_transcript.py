# =============================================================================
# handshake_transcript.py
# -----------------------------------------------------------------------------
# A running SHA-256 hash of EVERY handshake message, in the order they were
# exchanged:
#
#     transcript = SHA-256( label || HELLO_alice || HELLO_bob || PUBLIC_KEY ||
#                           SESSION_KEY || CONFIRM_bob || CONFIRM_alice )
#
# Both sides compute it independently from what they sent and received. If an
# attacker changed, removed or reordered any byte, the two hashes differ, and
# the later steps that depend on it (Alice's signature, the AES-GCM
# confirmations, the session id) fail.
#
# Each message is preceded by its length before hashing, so two different
# sequences of messages can never produce the same stream of bytes.
# =============================================================================

import hashlib
import struct


class HandshakeTranscript:
    """Incremental SHA-256 over all handshake messages."""

    def __init__(self, protocol_label_bytes, length_format):
        self._length_format = length_format
        self._hasher = hashlib.sha256()
        self._add_bytes(protocol_label_bytes)

    def add_message(self, message_bytes):
        """Append one complete encoded message (type byte + body)."""
        self._add_bytes(message_bytes)

    def current_digest(self):
        """
        Hash of everything added so far.

        copy() is used so the running hash can keep growing afterwards.
        """
        hasher_copy = self._hasher.copy()
        return hasher_copy.digest()

    def _add_bytes(self, data_bytes):
        length_prefix = struct.pack(self._length_format, len(data_bytes))
        self._hasher.update(length_prefix)
        self._hasher.update(data_bytes)