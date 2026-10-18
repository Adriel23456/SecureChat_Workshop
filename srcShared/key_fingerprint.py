# =============================================================================
# key_fingerprint.py
# -----------------------------------------------------------------------------
# A fingerprint is a short, fixed-size summary of a PUBLIC key:
#
#     fingerprint = SHA-256( DER encoding of the public key )
#
# Why it exists:
#   - A 3072-bit public key is ~400 bytes; a person cannot compare it by eye.
#   - 32 bytes of SHA-256 can be read aloud or compared on screen.
#   - If an attacker replaces the public key during the handshake, the
#     fingerprint changes completely, so comparing fingerprints through an
#     independent channel (out-of-band) detects the substitution.
#
# The fingerprint is PUBLIC information; showing it reveals nothing secret.
# This class is a value object: it holds 32 bytes and knows how to print,
# parse and compare them.
# =============================================================================

import hashlib

from cryptography.hazmat.primitives import serialization

from errors import KeyMaterialError


# Character placed between bytes in the long human readable form.
BYTE_SEPARATOR = ":"

# Characters the user may type between hex digits when pasting a fingerprint.
IGNORED_INPUT_CHARACTERS = [":", " ", "-", "\t"]

# Valid hexadecimal digits (lowercase; input is converted to lowercase first).
HEX_DIGITS = "0123456789abcdef"


class KeyFingerprint:
    """SHA-256 fingerprint of an RSA public key."""

    def __init__(self, digest_bytes, expected_size):
        if len(digest_bytes) != expected_size:
            raise KeyMaterialError(
                "Una huella debe medir " + str(expected_size) + " bytes y esta mide "
                + str(len(digest_bytes)) + "."
            )
        self._digest_bytes = digest_bytes

    # -------------------------------------------------------------------------
    # Construction
    # -------------------------------------------------------------------------
    @staticmethod
    def from_public_key(public_key, expected_size):
        """Compute the fingerprint of a public key object."""
        # DER = the binary form of SubjectPublicKeyInfo. Both sides encode the
        # same key to the same bytes, so both compute the same fingerprint.
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest_bytes = hashlib.sha256(der_bytes).digest()
        return KeyFingerprint(digest_bytes, expected_size)

    @staticmethod
    def from_text(typed_text, expected_size):
        """
        Parse a fingerprint typed or pasted by the user.

        Accepts "ab:cd:...", "ab cd ...", "ABCD..." and an optional "SHA256:"
        prefix. Raises KeyMaterialError if the text is not a valid fingerprint.
        """
        normalized_text = typed_text.strip().lower()

        # Remove an optional "sha256:" label at the beginning.
        if normalized_text.startswith("sha256:"):
            normalized_text = normalized_text[len("sha256:"):]

        # Keep only hexadecimal digits; drop separators; reject anything else.
        hex_characters = []
        for character in normalized_text:
            if character in IGNORED_INPUT_CHARACTERS:
                continue
            if character not in HEX_DIGITS:
                raise KeyMaterialError("Caracter no valido en la huella: '" + character + "'.")
            hex_characters.append(character)

        clean_hex = "".join(hex_characters)

        expected_hex_length = expected_size * 2
        if len(clean_hex) != expected_hex_length:
            raise KeyMaterialError(
                "La huella debe tener " + str(expected_hex_length) + " digitos hexadecimales y tiene "
                + str(len(clean_hex)) + "."
            )

        digest_bytes = bytes.fromhex(clean_hex)
        return KeyFingerprint(digest_bytes, expected_size)

    # -------------------------------------------------------------------------
    # Representation
    # -------------------------------------------------------------------------
    def to_hex(self):
        """64 hexadecimal characters with no separators (used for storage)."""
        return self._digest_bytes.hex()

    def to_display_text(self):
        """"SHA256:ab:cd:..." (long form, easy to compare byte by byte)."""
        byte_texts = []
        for single_byte in self._digest_bytes:
            byte_texts.append(format(single_byte, "02x"))
        return "SHA256:" + BYTE_SEPARATOR.join(byte_texts)

    def to_short_text(self, short_size):
        """First short_size bytes, for quick visual reference."""
        byte_texts = []
        index = 0
        while index < short_size:
            byte_texts.append(format(self._digest_bytes[index], "02x"))
            index = index + 1
        return BYTE_SEPARATOR.join(byte_texts) + BYTE_SEPARATOR + "..."

    # -------------------------------------------------------------------------
    # Comparison
    # -------------------------------------------------------------------------
    def matches(self, other_fingerprint):
        """True if both fingerprints contain exactly the same 32 bytes."""
        return self._digest_bytes == other_fingerprint._digest_bytes