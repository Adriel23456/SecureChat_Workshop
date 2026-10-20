# =============================================================================
# record_tamperer.py
# -----------------------------------------------------------------------------
# CONTROLLED integrity test of Paso 6 (only used by the /alterar command).
#
# It changes ONE byte of an already encrypted record of our OWN program,
# after AES-GCM sealed it and before it is handed to the socket. The receiver
# must detect the change, reject the record and show no plaintext.
#
# What it receives is the frame PAYLOAD (what goes after the 4-byte length
# prefix), so the length prefix is never touched:
#
#     payload = type (1 B) || nonce (12 B) || ciphertext (n B) || tag (16 B)
#
# Available targets:
#   ct     one byte in the middle of the ciphertext
#   tag    the last byte of the authentication tag
#   nonce  the most significant byte of the counter (the counter becomes much
#          larger, so it passes the sequence check and fails at the tag)
#   tipo   the type byte CHAT -> BYE (it belongs to the AAD)
#
# The size of the payload never changes.
# =============================================================================


class TamperResult:
    """What was changed: the altered payload and a description for the screen."""

    def __init__(self, payload, field_name, position, original_value, altered_value):
        self.payload = payload
        self.field_name = field_name
        self.position = position
        self.original_value = original_value
        self.altered_value = altered_value


class RecordTamperer:
    """Changes exactly one byte of an encrypted record payload."""

    TARGET_CIPHERTEXT = "ct"
    TARGET_TAG = "tag"
    TARGET_NONCE = "nonce"
    TARGET_TYPE = "tipo"

    # Value XOR-ed into the chosen byte (flips its lowest bit).
    FLIP_MASK = 0x01

    def __init__(self, type_size, direction_size, nonce_size, tag_size, chat_type_value, bye_type_value):
        self._type_size = type_size
        self._direction_size = direction_size
        self._nonce_size = nonce_size
        self._tag_size = tag_size
        self._chat_type_value = chat_type_value
        self._bye_type_value = bye_type_value

    def get_targets(self):
        targets = []
        targets.append(self.TARGET_CIPHERTEXT)
        targets.append(self.TARGET_TAG)
        targets.append(self.TARGET_NONCE)
        targets.append(self.TARGET_TYPE)
        return targets

    def is_valid_target(self, target):
        for known_target in self.get_targets():
            if known_target == target:
                return True
        return False

    def tamper(self, payload, target):
        """Return a TamperResult with one byte of payload changed."""
        minimum_size = self._type_size + self._nonce_size + self._tag_size
        if len(payload) < minimum_size:
            raise ValueError("El registro es demasiado corto para alterarlo.")

        if target == self.TARGET_CIPHERTEXT:
            return self._tamper_ciphertext(payload)
        if target == self.TARGET_TAG:
            return self._tamper_tag(payload)
        if target == self.TARGET_NONCE:
            return self._tamper_nonce(payload)
        if target == self.TARGET_TYPE:
            return self._tamper_type(payload)
        raise ValueError("Objetivo de alteracion desconocido: " + str(target))

    # -------------------------------------------------------------------------
    # One method per target
    # -------------------------------------------------------------------------
    def _tamper_ciphertext(self, payload):
        ciphertext_start = self._type_size + self._nonce_size
        ciphertext_size = len(payload) - ciphertext_start - self._tag_size
        if ciphertext_size == 0:
            # Empty message: there is no ciphertext byte, use the tag instead.
            return self._tamper_tag(payload)
        position = ciphertext_start + (ciphertext_size // 2)
        return self._flip_byte(payload, position, "ciphertext")

    def _tamper_tag(self, payload):
        position = len(payload) - 1
        return self._flip_byte(payload, position, "tag")

    def _tamper_nonce(self, payload):
        # First byte of the counter (right after the direction byte). The
        # direction byte itself is kept, so the record is not rejected as
        # "reflected" but by the authentication tag.
        position = self._type_size + self._direction_size
        return self._flip_byte(payload, position, "nonce (contador)")

    def _tamper_type(self, payload):
        position = 0
        original_value = payload[position]
        altered_value = self._bye_type_value
        if original_value != self._chat_type_value:
            altered_value = original_value ^ self.FLIP_MASK
        return self._replace_byte(payload, position, altered_value, "tipo (parte de la AAD)")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------
    def _flip_byte(self, payload, position, field_name):
        altered_value = payload[position] ^ self.FLIP_MASK
        return self._replace_byte(payload, position, altered_value, field_name)

    def _replace_byte(self, payload, position, altered_value, field_name):
        altered_payload = bytearray(payload)
        original_value = altered_payload[position]
        altered_payload[position] = altered_value
        return TamperResult(bytes(altered_payload), field_name, position, original_value, altered_value)