# =============================================================================
# trusted_peer_store.py
# -----------------------------------------------------------------------------
# Remembers the fingerprint of the PEER's public key that the user verified
# through an independent channel (out-of-band: reading it on the other
# terminal, aloud, by chat, etc.).
#
# In Paso 3 the peer's public key arrives through the socket. Before using it,
# its fingerprint will be compared with the one stored here. If they differ,
# someone may have replaced the key (man in the middle) and the handshake is
# aborted.
#
# File content: one line with 64 hexadecimal characters. It holds only
# public information, but it still lives in srcXxx/keys/ (ignored by git).
# =============================================================================

import os

from errors import KeyMaterialError
from key_fingerprint import KeyFingerprint


class TrustedPeerStore:
    """Stores the trusted fingerprint of the peer's public key."""

    def __init__(self, file_path, fingerprint_size):
        self._file_path = file_path
        self._fingerprint_size = fingerprint_size

    def get_file_path(self):
        return self._file_path

    def has_trusted_fingerprint(self):
        return os.path.isfile(self._file_path)

    def save_trusted_fingerprint(self, fingerprint):
        """Write the fingerprint as one line of hexadecimal text."""
        folder = os.path.dirname(self._file_path)
        os.makedirs(folder, exist_ok=True)

        file_handle = open(self._file_path, "w", encoding="ascii")
        try:
            file_handle.write(fingerprint.to_hex() + "\n")
        finally:
            file_handle.close()

    def load_trusted_fingerprint(self):
        """Read and parse the stored fingerprint."""
        if not self.has_trusted_fingerprint():
            raise KeyMaterialError("No hay huella de confianza registrada: " + self._file_path)

        file_handle = open(self._file_path, "r", encoding="ascii")
        try:
            stored_text = file_handle.read()
        finally:
            file_handle.close()

        return KeyFingerprint.from_text(stored_text, self._fingerprint_size)