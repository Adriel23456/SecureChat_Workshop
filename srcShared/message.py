# =============================================================================
# message.py
# -----------------------------------------------------------------------------
# Defines WHAT travels inside a frame. In this stage (Paso 1) the payload is
# plain text. In later steps the CHAT payload will be replaced by ciphertext,
# but the idea of "1 type byte + body" stays the same.
#
#     +----------------+---------------------------------+
#     | type (1 byte)  | body (UTF-8 text in this stage) |
#     +----------------+---------------------------------+
#
# Single responsibility:
#   - MessageType  -> the list of valid message kinds.
#   - Message      -> one message in memory.
#   - MessageCodec -> converts Message <-> bytes. Nothing else.
# =============================================================================

from enum import IntEnum

from errors import ProtocolError


class MessageType(IntEnum):
    """Every kind of message the protocol understands."""

    # First message sent by each side after connecting. Body = sender name.
    HELLO = 1

    # A chat line typed by the user. Body = the text (plaintext in Paso 1).
    CHAT = 2

    # Orderly goodbye before closing. Body = empty.
    BYE = 3


class Message:
    """One protocol message: a type plus a text body."""

    def __init__(self, message_type, text):
        self.message_type = message_type
        self.text = text

    def describe(self):
        """Short human readable description, useful for debugging."""
        return self.message_type.name + "(" + repr(self.text) + ")"


class MessageCodec:
    """Encodes Message objects to bytes and decodes bytes back to Messages."""

    # Number of bytes used for the message type at the start of the payload.
    TYPE_FIELD_SIZE = 1

    def __init__(self, text_encoding):
        self._text_encoding = text_encoding

    def encode(self, message):
        """Message -> bytes (type byte followed by the encoded text)."""
        type_byte = bytes([int(message.message_type)])
        body_bytes = message.text.encode(self._text_encoding)
        return type_byte + body_bytes

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

        # Everything after the type byte is the text body.
        body_bytes = payload[self.TYPE_FIELD_SIZE:]
        try:
            text = body_bytes.decode(self._text_encoding)
        except UnicodeDecodeError:
            raise ProtocolError("El cuerpo del mensaje no es texto " + self._text_encoding + " valido.")

        return Message(message_type, text)