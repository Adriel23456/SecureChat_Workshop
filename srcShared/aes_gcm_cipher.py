# =============================================================================
# aes_gcm_cipher.py
# -----------------------------------------------------------------------------
# Authenticated symmetric encryption with AES-256-GCM.
#
#   encrypt(plaintext, aad)  -> (nonce, ciphertext || tag)
#   decrypt(nonce, ciphertext || tag, aad) -> plaintext   or   InvalidTag
#
#   - nonce : 12 bytes, must NEVER repeat under the same key. Here it comes
#             from the operating system CSPRNG (os.urandom). Paso 4 will
#             replace it with a per-direction counter for chat messages.
#   - aad   : "associated data". It is NOT encrypted and does NOT travel
#             inside the ciphertext, but it is authenticated: if the receiver
#             uses a different aad, decryption fails. The handshake uses the
#             transcript hash as aad.
#   - tag   : 16 bytes appended by the library; it is what lets the receiver
#             detect any modification before accepting the plaintext.
# =============================================================================

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AesGcmCipher:
    """AES-GCM with a fixed key and random 96-bit nonces."""

    def __init__(self, key_bytes, nonce_size):
        self._aes_gcm = AESGCM(key_bytes)
        self._nonce_size = nonce_size

    def encrypt(self, plaintext, associated_data):
        nonce = os.urandom(self._nonce_size)
        ciphertext_with_tag = self._aes_gcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext_with_tag

    def decrypt(self, nonce, ciphertext_with_tag, associated_data):
        """Raises cryptography.exceptions.InvalidTag if anything was altered."""
        return self._aes_gcm.decrypt(nonce, ciphertext_with_tag, associated_data)