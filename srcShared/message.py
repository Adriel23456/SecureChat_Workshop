# =============================================================================
# message.py
# -----------------------------------------------------------------------------
# Defines WHAT travels inside a frame:
#
#     +----------------+---------------------------------------+
#     | type (1 byte)  | body (bytes; meaning depends on type) |
#     +----------------+---------------------------------------+
#
# Since Paso 3 the body is raw BYTES, because handshake messages carry binary
# data (public keys, RSA ciphertext, signatures, AES-GCM output). Text bodies
# (names, chat lines, abort reasons) are converted with text_to_body() and
# body_to_text().
#
# Single responsibility:
#   - MessageType  -> the list of valid message kinds.
#   - Message      -> one message in memory.
#   - MessageCodec -> converts Message <-> bytes and text <-> body bytes.
# =============================================================================

from enum import IntEnum

from errors import ProtocolError


class MessageType(IntEnum):
    """Every kind of message the protocol understands."""

    # ---- Handshake (Paso 3) -------------------------------------------------
    # Greeting. Body = fields [name, random 32 bytes].
    HELLO = 1

    # Bob -> Alice. Body = Bob's public key (DER, SubjectPublicKeyInfo).
    PUBLIC_KEY = 4

    # Alice -> Bob. Body = fields [Alice public key DER,
    #                              RSA-OAEP(session key), RSA-PSS signature].
    SESSION_KEY = 5

    # Both directions. Body = fields [nonce, AES-GCM(confirmation label)].
    CONFIRM = 6

    # Either side, when the handshake fails. Body = reason (UTF-8 text).
    ABORT = 7

    # ---- Chat ----------------------------------------------------------------
    # A chat line typed by the user. Body = UTF-8 text (encrypted in Paso 4).
    CHAT = 2

    # Orderly goodbye before closing. Body = empty.
    BYE = 3


class Message:
    """One protocol message: a type plus a body of bytes."""

    def __init__(self, message_type, body):
        self.message_type = message_type
        self.body = body


class MessageCodec:
    """Encodes Message objects to bytes and decodes bytes back to Messages."""

    # Number of bytes used for the message type at the start of the payload.
    TYPE_FIELD_SIZE = 1

    def __init__(self, text_encoding):
        self._text_encoding = text_encoding

    # -------------------------------------------------------------------------
    # Message <-> payload bytes
    # -------------------------------------------------------------------------
    def encode(self, message):
        """Message -> bytes (type byte followed by the body)."""
        type_byte = bytes([int(message.message_type)])
        return type_byte + message.body

    def decode(self, payload):
        """bytes -> Message. Raises ProtocolError if the bytes are invalid."""
        # A valid payload has at least the type byte.
        if len(payload) < self.TYPE_FIELD_SIZE:
            raise ProtocolError("Se recibio un mensaje vacio (sin tipo).")

        # payload[0] on a bytes object already returns an int (0..255).
        type_value = payload[0]

        # Convert the number into a MessageType; unknown numbers are rejected.
        try:
            message_type = MessageType(type_value)
        except ValueError:
            raise ProtocolError("Tipo de mensaje desconocido: " + str(type_value))

        body = payload[self.TYPE_FIELD_SIZE:]
        return Message(message_type, body)

    # -------------------------------------------------------------------------
    # Text <-> body bytes
    # -------------------------------------------------------------------------
    def text_to_body(self, text):
        return text.encode(self._text_encoding)

    def body_to_text(self, body):
        try:
            return body.decode(self._text_encoding)
        except UnicodeDecodeError:
            raise ProtocolError("El cuerpo del mensaje no es texto " + self._text_encoding + " valido.")