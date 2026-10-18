# =============================================================================
# key_pair_verifier.py
# -----------------------------------------------------------------------------
# Proves that the public key stored on disk really belongs to the private key
# stored on disk. Three independent checks:
#
#   1. Same numbers : the public key derived from the private key has the
#                     same modulus n and exponent e as public_key.pem.
#   2. Signature    : sign a random value with the PRIVATE key (RSA-PSS) and
#                     verify it with the PUBLIC key. Only the matching private
#                     key can produce a signature the public key accepts.
#   3. Encryption   : encrypt a random value with the PUBLIC key (RSA-OAEP)
#                     and decrypt it with the PRIVATE key. This is exactly
#                     the operation Paso 3 uses to protect the session key.
#
# Nothing secret is printed: the test value is random, used once and
# discarded; only "passed / failed" is reported.
# =============================================================================

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class VerificationCheck:
    """Result of one individual check."""

    def __init__(self, name, passed, detail):
        self.name = name
        self.passed = passed
        self.detail = detail


class KeyPairVerificationResult:
    """Collection of checks; the pair is valid only if every check passed."""

    def __init__(self):
        self.checks = []

    def add_check(self, check):
        self.checks.append(check)

    def all_passed(self):
        for check in self.checks:
            if not check.passed:
                return False
        return True


class KeyPairVerifier:
    """Runs the three correspondence checks on a private/public key pair."""

    def __init__(self, test_value_size):
        # Size in bytes of the random value used by checks 2 and 3.
        self._test_value_size = test_value_size

    def verify(self, private_key, public_key):
        result = KeyPairVerificationResult()
        result.add_check(self._check_same_numbers(private_key, public_key))
        result.add_check(self._check_signature_round_trip(private_key, public_key))
        result.add_check(self._check_encryption_round_trip(private_key, public_key))
        return result

    # -------------------------------------------------------------------------
    # Check 1: same public numbers (n, e)
    # -------------------------------------------------------------------------
    def _check_same_numbers(self, private_key, public_key):
        derived_numbers = private_key.public_key().public_numbers()
        stored_numbers = public_key.public_numbers()

        same_modulus = derived_numbers.n == stored_numbers.n
        same_exponent = derived_numbers.e == stored_numbers.e

        if same_modulus and same_exponent:
            return VerificationCheck("Modulo n y exponente e coinciden", True, "")

        return VerificationCheck(
            "Modulo n y exponente e coinciden",
            False,
            "public_key.pem no corresponde a private_key.pem.",
        )

    # -------------------------------------------------------------------------
    # Check 2: sign with private, verify with public (RSA-PSS + SHA-256)
    # -------------------------------------------------------------------------
    def _check_signature_round_trip(self, private_key, public_key):
        test_value = os.urandom(self._test_value_size)

        pss_padding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )

        signature = private_key.sign(test_value, pss_padding, hashes.SHA256())

        try:
            public_key.verify(signature, test_value, pss_padding, hashes.SHA256())
        except InvalidSignature:
            return VerificationCheck(
                "Firma con privada, verificacion con publica (PSS)",
                False,
                "La llave publica no acepta la firma de la privada.",
            )

        return VerificationCheck("Firma con privada, verificacion con publica (PSS)", True, "")

    # -------------------------------------------------------------------------
    # Check 3: encrypt with public, decrypt with private (RSA-OAEP + SHA-256)
    # -------------------------------------------------------------------------
    def _check_encryption_round_trip(self, private_key, public_key):
        test_value = os.urandom(self._test_value_size)

        oaep_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

        ciphertext = public_key.encrypt(test_value, oaep_padding)

        try:
            recovered_value = private_key.decrypt(ciphertext, oaep_padding)
        except ValueError:
            return VerificationCheck(
                "Cifrado con publica, descifrado con privada (OAEP)",
                False,
                "La llave privada no pudo descifrar.",
            )

        if recovered_value != test_value:
            return VerificationCheck(
                "Cifrado con publica, descifrado con privada (OAEP)",
                False,
                "El valor recuperado no coincide.",
            )

        return VerificationCheck("Cifrado con publica, descifrado con privada (OAEP)", True, "")