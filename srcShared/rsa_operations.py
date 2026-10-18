# =============================================================================
# rsa_operations.py
# -----------------------------------------------------------------------------
# The four RSA operations the handshake needs, always with modern padding:
#
#   encrypt  (public key)  -> RSA-OAEP, SHA-256, MGF1(SHA-256)
#   decrypt  (private key) -> RSA-OAEP, SHA-256, MGF1(SHA-256)
#   sign     (private key) -> RSA-PSS,  SHA-256, MGF1(SHA-256)
#   verify   (public key)  -> RSA-PSS,  SHA-256, MGF1(SHA-256)
#
# OAEP and PSS add randomness, so encrypting or signing the same value twice
# gives different results ("textbook" RSA would not).
# =============================================================================

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class RsaOperations:
    """RSA-OAEP encryption and RSA-PSS signatures with SHA-256."""

    def _build_oaep_padding(self):
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

    def _build_pss_padding(self):
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )

    # -------------------------------------------------------------------------
    # Confidentiality: only the owner of the private key can read it
    # -------------------------------------------------------------------------
    def encrypt(self, public_key, plaintext):
        return public_key.encrypt(plaintext, self._build_oaep_padding())

    def decrypt(self, private_key, ciphertext):
        """Raises ValueError if the ciphertext was not made for this key or was altered."""
        return private_key.decrypt(ciphertext, self._build_oaep_padding())

    # -------------------------------------------------------------------------
    # Authenticity: only the owner of the private key could have produced it
    # -------------------------------------------------------------------------
    def sign(self, private_key, data):
        return private_key.sign(data, self._build_pss_padding(), hashes.SHA256())

    def verify(self, public_key, signature, data):
        """Return True if the signature is valid for data, False otherwise."""
        try:
            public_key.verify(signature, data, self._build_pss_padding(), hashes.SHA256())
        except InvalidSignature:
            return False
        return True