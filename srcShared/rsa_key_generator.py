# =============================================================================
# rsa_key_generator.py
# -----------------------------------------------------------------------------
# Creates a brand new RSA key pair. It only GENERATES; saving to disk is the
# job of KeyStore and computing fingerprints is the job of KeyFingerprint.
#
# The private key object contains everything (n, e, d, p, q). The public key
# (n, e) is derived from it with private_key.public_key().
# =============================================================================

from cryptography.hazmat.primitives.asymmetric import rsa


class RsaKeyGenerator:
    """Generates RSA private keys with a fixed size and public exponent."""

    def __init__(self, key_size, public_exponent):
        # Modulus size in bits (for example 3072).
        self._key_size = key_size

        # Public exponent e (65537).
        self._public_exponent = public_exponent

    def get_key_size(self):
        return self._key_size

    def get_public_exponent(self):
        return self._public_exponent

    def generate_private_key(self):
        """
        Generate a new private key.

        The library picks the two secret primes p and q with the operating
        system's cryptographically secure random generator. This can take a
        second or two for 3072-bit keys.
        """
        private_key = rsa.generate_private_key(
            public_exponent=self._public_exponent,
            key_size=self._key_size,
        )
        return private_key