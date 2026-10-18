# =============================================================================
# aes_gcm_cipher.py
# -----------------------------------------------------------------------------
# Authenticated symmetric encryption with AES-256-GCM.
#
#   encrypt(nonce, plaintext, aad)            -> ciphertext || tag
#   decrypt(nonce, ciphertext || tag, aad)    -> plaintext   or   InvalidTag
#
#   - nonce : 12 bytes, must NEVER repeat under the same key. Since Paso 4 the
#             caller always provides it, built by NonceSequence as
#             direction || counter, so uniqueness is guaranteed by design.
#   - aad   : "associated data". It is NOT encrypted and does NOT travel
#             inside the ciphertext, but it is authenticated: if the receiver
#             uses a different aad, decryption fails.
#   - tag   : 16 bytes appended by the library; it is what lets the receiver
#             detect any modification before accepting the plaintext.
# =============================================================================

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AesGcmCipher:
    """AES-GCM with a fixed key; the nonce is always supplied by the caller."""

    def __init__(self, key_bytes):
        self._aes_gcm = AESGCM(key_bytes)

    def encrypt(self, nonce, plaintext, associated_data):
        return self._aes_gcm.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, nonce, ciphertext_with_tag, associated_data):
        """Raises cryptography.exceptions.InvalidTag if anything was altered."""
        return self._aes_gcm.decrypt(nonce, ciphertext_with_tag, associated_data)