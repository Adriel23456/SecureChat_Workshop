# =============================================================================
# secure_channel.py
# -----------------------------------------------------------------------------
# Protects every message AFTER the handshake with AES-256-GCM.
#
# Body of every protected record (CHAT and BYE):
#
#     +------------------+-------------------------+----------------+
#     | nonce (12 B)     | ciphertext (n B)        | tag (16 B)     |
#     +------------------+-------------------------+----------------+
#       direction||counter  (same length as plaintext)
#
# Associated data (authenticated, never sent, rebuilt by the receiver):
#
#     "SecureChat-v1" || message type (1 B) || session id (8 B) || nonce (12 B)
#
# This binds each record to:
#   - its TYPE      : a CHAT record cannot be passed off as a BYE.
#   - this SESSION  : a record from another session does not verify.
#   - its DIRECTION and SEQUENCE NUMBER (both inside the nonce).
#
# seal()  : plaintext -> SealedRecord   (sender side)
# open()  : body      -> OpenedRecord   (receiver side). Checks, in order:
#             1. size and nonce format
#             2. direction (must come from the peer, not a reflected copy)
#             3. sequence number strictly greater than the last accepted one
#             4. AES-GCM tag  -> only now is the plaintext returned
#           The "last accepted" counter only advances after step 4 succeeds.
# =============================================================================

from cryptography.exceptions import InvalidTag

from aes_gcm_cipher import AesGcmCipher
from errors import MessageAuthenticationError
from errors import ProtocolError
from errors import ReplayError
from nonce_sequence import NonceSequence


class SecureChannelSettings:
    """Constants used by SecureChannel (injected from main.py)."""

    def __init__(self, protocol_label_bytes, nonce_layout, tag_size, first_counter, max_counter):
        self.protocol_label_bytes = protocol_label_bytes
        self.nonce_layout = nonce_layout
        self.tag_size = tag_size
        self.first_counter = first_counter
        self.max_counter = max_counter

    @staticmethod
    def from_shared_config(shared_config_module, nonce_layout):
        return SecureChannelSettings(
            shared_config_module.PROTOCOL_LABEL.encode(shared_config_module.TEXT_ENCODING),
            nonce_layout,
            shared_config_module.AES_GCM_TAG_SIZE_BYTES,
            shared_config_module.FIRST_MESSAGE_COUNTER,
            shared_config_module.MAX_MESSAGE_COUNTER,
        )


class SealedRecord:
    """What the sender produced: the pieces (for display) and the body to send."""

    def __init__(self, nonce, counter, ciphertext, tag, body):
        self.nonce = nonce
        self.counter = counter
        self.ciphertext = ciphertext
        self.tag = tag
        self.body = body


class OpenedRecord:
    """What the receiver accepted: the pieces (for display) and the plaintext."""

    def __init__(self, nonce, counter, ciphertext, tag, plaintext):
        self.nonce = nonce
        self.counter = counter
        self.ciphertext = ciphertext
        self.tag = tag
        self.plaintext = plaintext


class SecureChannel:
    """AES-256-GCM record protection with per-direction nonces and replay protection."""

    def __init__(self, session_material, settings):
        self._settings = settings
        self._session_id = session_material.session_id
        self._receive_direction = session_material.receive_direction
        self._cipher = AesGcmCipher(session_material.session_key)

        # Nonces for what WE send.
        self._send_sequence = NonceSequence(
            settings.nonce_layout,
            session_material.send_direction,
            settings.first_counter,
            settings.max_counter,
        )

        # Highest sequence number accepted from the peer (none yet).
        self._last_received_counter = settings.first_counter - 1

    # =========================================================================
    # Sender side
    # =========================================================================
    def seal(self, message_type, plaintext):
        """Encrypt and authenticate plaintext for the given message type."""
        nonce, counter = self._send_sequence.next_nonce()
        associated_data = self._build_associated_data(message_type, nonce)

        ciphertext_with_tag = self._cipher.encrypt(nonce, plaintext, associated_data)

        ciphertext = ciphertext_with_tag[:-self._settings.tag_size]
        tag = ciphertext_with_tag[-self._settings.tag_size:]
        body = nonce + ciphertext_with_tag
        return SealedRecord(nonce, counter, ciphertext, tag, body)

    # =========================================================================
    # Receiver side
    # =========================================================================
    def open(self, message_type, body):
        """
        Verify and decrypt a received body.

        Raises ProtocolError, ReplayError or MessageAuthenticationError; in
        those cases NO plaintext is returned.
        """
        nonce_size = self._settings.nonce_layout.get_nonce_size()
        minimum_size = nonce_size + self._settings.tag_size

        # ---- 1. Format ----------------------------------------------------------
        if len(body) < minimum_size:
            raise ProtocolError("Registro cifrado demasiado corto (" + str(len(body)) + " bytes).")

        nonce = body[:nonce_size]
        ciphertext_with_tag = body[nonce_size:]
        ciphertext = ciphertext_with_tag[:-self._settings.tag_size]
        tag = ciphertext_with_tag[-self._settings.tag_size:]

        direction, counter = self._settings.nonce_layout.parse(nonce)

        # ---- 2. Direction -------------------------------------------------------
        if direction != self._receive_direction:
            raise ReplayError(
                "Direccion de nonce inesperada (" + str(direction) + "): posible mensaje reflejado."
            )

        # ---- 3. Sequence number -------------------------------------------------
        if counter <= self._last_received_counter:
            raise ReplayError(
                "Numero de secuencia " + str(counter) + " repetido o antiguo (ultimo aceptado: "
                + str(self._last_received_counter) + "): posible repeticion."
            )

        # ---- 4. AES-GCM authentication + decryption -----------------------------
        associated_data = self._build_associated_data(message_type, nonce)
        try:
            plaintext = self._cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            raise MessageAuthenticationError(
                "Tag de autenticacion invalido: el mensaje fue alterado o no pertenece a esta sesion."
            )

        # Only an authentic record moves the window forward.
        self._last_received_counter = counter
        return OpenedRecord(nonce, counter, ciphertext, tag, plaintext)

    # =========================================================================
    # Status and cleanup (Paso 5)
    # =========================================================================
    def get_last_sent_counter(self):
        return self._send_sequence.get_last_issued_counter()

    def get_last_received_counter(self):
        return self._last_received_counter

    def close(self):
        """
        Drop this object's reference to the AES-GCM key object.

        Python cannot GUARANTEE that the key bytes disappear from memory:
        bytes objects are immutable, the garbage collector decides when to
        free them, and OpenSSL keeps its own copy inside the cipher context.
        What we can do is make sure no SecureChat object keeps a reference
        after the session, so nothing can use the key again.
        """
        self._cipher = None

    # =========================================================================
    # Associated data
    # =========================================================================
    def _build_associated_data(self, message_type, nonce):
        type_byte = bytes([int(message_type)])
        return self._settings.protocol_label_bytes + type_byte + self._session_id + nonce