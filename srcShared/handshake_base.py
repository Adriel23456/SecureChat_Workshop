# =============================================================================
# handshake_base.py
# -----------------------------------------------------------------------------
# Everything the two handshake roles have in common. The role-specific steps
# live in the participant folders:
#
#   srcAlice/alice_handshake.py  -> AliceHandshake  (initiator)
#   srcBob/bob_handshake.py      -> BobHandshake    (responder)
#
# Full message sequence (-> is Alice to Bob, <- is Bob to Alice):
#
#   1. ->  HELLO        [ "Alice", client_random ]
#   2. <-  HELLO        [ "Bob",   server_random ]
#   3. <-  PUBLIC_KEY   Bob's public key (DER)
#          Alice checks its SHA-256 fingerprint against the trusted one.
#          Alice generates the session key K (256 random bits).
#   4. ->  SESSION_KEY  [ Alice public key DER,
#                         RSA-OAEP_BobPublic(K),
#                         RSA-PSS_AlicePrivate(transcript || AlicePub || OAEP(K)) ]
#          Bob checks Alice's fingerprint and signature, then decrypts K.
#   5. <-  CONFIRM      [ nonce, AES-GCM_K("...responder", aad = transcript) ]
#   6. ->  CONFIRM      [ nonce, AES-GCM_K("...iniciador", aad = transcript) ]
#
# Any failure raises HandshakeError; the caller sends ABORT and closes the
# connection. The chat never starts without a completed handshake.
# =============================================================================

import threading
from abc import ABC
from abc import abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aes_gcm_cipher import AesGcmCipher
from errors import ConnectionClosedError
from errors import HandshakeError
from errors import ProtocolError
from handshake_transcript import HandshakeTranscript
from key_fingerprint import KeyFingerprint
from message import Message
from message import MessageType
from session_material import SessionMaterial


class HandshakeSettings:
    """Constants and options used by both handshake roles (injected from main.py)."""

    def __init__(self, protocol_label, random_size, session_key_size_bits, field_length_format,
                 confirmation_label_responder, confirmation_label_initiator, session_id_size,
                 nonce_size, fingerprint_size, fingerprint_short_size, minimum_rsa_key_size,
                 hex_preview_size, receive_timeout, show_details, text_encoding):
        self.protocol_label = protocol_label
        self.random_size = random_size
        self.session_key_size_bits = session_key_size_bits
        self.field_length_format = field_length_format
        self.confirmation_label_responder = confirmation_label_responder
        self.confirmation_label_initiator = confirmation_label_initiator
        self.session_id_size = session_id_size
        self.nonce_size = nonce_size
        self.fingerprint_size = fingerprint_size
        self.fingerprint_short_size = fingerprint_short_size
        self.minimum_rsa_key_size = minimum_rsa_key_size
        self.hex_preview_size = hex_preview_size
        self.receive_timeout = receive_timeout
        self.show_details = show_details
        self.text_encoding = text_encoding

    @staticmethod
    def from_shared_config(shared_config_module, receive_timeout, show_details):
        """Build the settings from srcShared/shared_config.py plus two per-side values."""
        return HandshakeSettings(
            shared_config_module.PROTOCOL_LABEL,
            shared_config_module.HANDSHAKE_RANDOM_SIZE_BYTES,
            shared_config_module.SESSION_KEY_SIZE_BITS,
            shared_config_module.FIELD_LENGTH_FORMAT,
            shared_config_module.CONFIRMATION_LABEL_RESPONDER,
            shared_config_module.CONFIRMATION_LABEL_INITIATOR,
            shared_config_module.SESSION_ID_SIZE_BYTES,
            shared_config_module.AES_GCM_NONCE_SIZE_BYTES,
            shared_config_module.FINGERPRINT_SIZE_BYTES,
            shared_config_module.FINGERPRINT_SHORT_SIZE_BYTES,
            shared_config_module.RSA_MINIMUM_KEY_SIZE,
            shared_config_module.HEX_PREVIEW_SIZE_BYTES,
            receive_timeout,
            show_details,
            shared_config_module.TEXT_ENCODING,
        )


class HandshakeBase(ABC):
    """Shared helpers for AliceHandshake and BobHandshake."""

    def __init__(self, connection, codec, view, fields, rsa_operations, identity,
                 expected_peer_name, settings):
        # Collaborators.
        self._connection = connection
        self._codec = codec
        self._view = view
        self._fields = fields
        self._rsa = rsa_operations
        self._identity = identity

        # Settings.
        self._expected_peer_name = expected_peer_name
        self._settings = settings

        # Running hash of every handshake message.
        protocol_label_bytes = settings.protocol_label.encode(settings.text_encoding)
        self._transcript = HandshakeTranscript(protocol_label_bytes, settings.field_length_format)

        # The handshake is never interrupted by another thread, so this event
        # is never set; receive_frame() requires one.
        self._never_stop_event = threading.Event()

        # True when the peer already sent ABORT (we must not answer with another).
        self._peer_aborted = False

        # Name announced by the peer in its HELLO.
        self._peer_name = expected_peer_name

    # =========================================================================
    # Public API
    # =========================================================================
    @abstractmethod
    def perform(self):
        """Run the role-specific steps and return a SessionMaterial."""

    def send_abort(self, reason):
        """Tell the peer why the handshake failed (best effort, plain text)."""
        if self._peer_aborted:
            return
        abort_message = Message(MessageType.ABORT, self._codec.text_to_body(reason))
        try:
            self._connection.send_frame(self._codec.encode(abort_message))
        except OSError:
            pass

    # =========================================================================
    # Sending and receiving handshake messages
    # =========================================================================
    def _send(self, message_type, body, description):
        """Send one handshake message and add it to the transcript."""
        message = Message(message_type, body)
        payload = self._codec.encode(message)
        self._connection.send_frame(payload)
        self._transcript.add_message(payload)

        self._view.show_handshake_step(
            "->", message_type.name + " enviado: " + description + " (" + str(len(payload)) + " bytes)"
        )

    def _receive(self, expected_type, add_to_transcript):
        """
        Wait for the next handshake message, which must be expected_type.

        add_to_transcript=False lets the caller first use the transcript hash
        as it was BEFORE this message (needed to verify signatures and
        confirmations); the caller then calls _add_to_transcript(message).
        """
        try:
            payload = self._connection.receive_frame(self._never_stop_event, self._settings.receive_timeout)
        except ConnectionClosedError:
            raise HandshakeError("El par cerro la conexion durante el handshake.")
        except ProtocolError as error:
            raise HandshakeError(str(error))

        message = self._codec.decode(payload)

        if message.message_type == MessageType.ABORT:
            self._peer_aborted = True
            reason = self._codec.body_to_text(message.body)
            raise HandshakeError("El par aborto el handshake: " + reason)

        if message.message_type != expected_type:
            raise HandshakeError(
                "Se esperaba " + expected_type.name + " y llego " + message.message_type.name + "."
            )

        if add_to_transcript:
            self._add_to_transcript(message)

        self._view.show_handshake_step(
            "<-", message.message_type.name + " recibido (" + str(len(payload)) + " bytes)"
        )
        return message

    def _add_to_transcript(self, message):
        self._transcript.add_message(self._codec.encode(message))

    def _unpack_fields(self, body, expected_count, message_name):
        """Split a body into fields; a malformed body aborts the handshake."""
        try:
            return self._fields.unpack(body, expected_count)
        except ProtocolError as error:
            raise HandshakeError(message_name + " mal formado: " + str(error))

    # =========================================================================
    # HELLO
    # =========================================================================
    def _build_hello_body(self, random_bytes):
        name_bytes = self._codec.text_to_body(self._identity.local_name)
        return self._fields.pack([name_bytes, random_bytes])

    def _read_hello(self, message):
        """Return (peer_name, peer_random) from a HELLO message."""
        hello_fields = self._unpack_fields(message.body, 2, "HELLO")
        peer_name = self._codec.body_to_text(hello_fields[0]).strip()
        peer_random = hello_fields[1]

        if peer_name == "":
            raise HandshakeError("El par envio un HELLO sin nombre.")

        if len(peer_random) != self._settings.random_size:
            raise HandshakeError("El valor aleatorio del HELLO no mide " + str(self._settings.random_size) + " bytes.")

        if peer_name != self._expected_peer_name:
            self._view.show_warning(
                "Se esperaba a '" + self._expected_peer_name + "' y el par se presento como '" + peer_name + "'."
            )

        self._peer_name = peer_name
        return peer_name, peer_random

    # =========================================================================
    # Public keys
    # =========================================================================
    def _encode_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _load_peer_public_key(self, der_bytes):
        """DER bytes -> RSA public key object. Bad data aborts the handshake."""
        try:
            public_key = serialization.load_der_public_key(der_bytes)
        except ValueError:
            raise HandshakeError("La llave publica recibida esta mal formada.")

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise HandshakeError("La llave publica recibida no es RSA.")

        if public_key.key_size < self._settings.minimum_rsa_key_size:
            raise HandshakeError(
                "La llave publica recibida mide " + str(public_key.key_size) + " bits; minimo "
                + str(self._settings.minimum_rsa_key_size) + "."
            )

        return public_key

    def _authenticate_peer_public_key(self, public_key):
        """
        Compare the received key's fingerprint with the one registered out-of-band.

        This is the defense against a man in the middle who replaces the key.
        """
        received_fingerprint = KeyFingerprint.from_public_key(public_key, self._settings.fingerprint_size)
        trusted_fingerprint = self._identity.trusted_peer_fingerprint

        if not received_fingerprint.matches(trusted_fingerprint):
            self._view.show_error("Huella recibida : " + received_fingerprint.to_display_text())
            self._view.show_error("Huella confiable: " + trusted_fingerprint.to_display_text())
            raise HandshakeError(
                "La llave publica de " + self._peer_name + " NO coincide con la huella de confianza "
                "(posible ataque de intermediario). Se aborta."
            )

        self._view.show_success(
            "Huella de " + self._peer_name + " verificada: "
            + received_fingerprint.to_short_text(self._settings.fingerprint_short_size)
        )
        return received_fingerprint

    def _build_local_fingerprint(self):
        return KeyFingerprint.from_public_key(self._identity.public_key, self._settings.fingerprint_size)

    # =========================================================================
    # Signed data of the SESSION_KEY message
    # =========================================================================
    def _build_session_key_signed_data(self, transcript_digest, initiator_public_der, encrypted_session_key):
        """
        Bytes that Alice signs and Bob verifies.

        Including the transcript digest binds the signature to THIS handshake
        (both random values and Bob's public key), so it cannot be replayed in
        another session.
        """
        return self._fields.pack([transcript_digest, initiator_public_der, encrypted_session_key])

    # =========================================================================
    # Key confirmation (AES-GCM with the new session key)
    # =========================================================================
    def _send_confirmation(self, session_key, label):
        """Encrypt our confirmation label with K, using the transcript hash as AAD."""
        associated_data = self._transcript.current_digest()
        cipher = AesGcmCipher(session_key, self._settings.nonce_size)
        label_bytes = label.encode(self._settings.text_encoding)

        nonce, ciphertext_with_tag = cipher.encrypt(label_bytes, associated_data)

        self._show_bytes("nonce de confirmacion", nonce)
        self._show_bytes("confirmacion cifrada (AES-GCM, incluye tag)", ciphertext_with_tag)

        body = self._fields.pack([nonce, ciphertext_with_tag])
        self._send(MessageType.CONFIRM, body, "confirmacion cifrada con la clave de sesion")

    def _receive_and_check_confirmation(self, session_key, expected_label):
        """Receive the peer's CONFIRM and check it decrypts to the expected label."""
        message = self._receive(MessageType.CONFIRM, False)

        # The peer encrypted using the transcript as it was before this message.
        associated_data = self._transcript.current_digest()

        confirm_fields = self._unpack_fields(message.body, 2, "CONFIRM")
        nonce = confirm_fields[0]
        ciphertext_with_tag = confirm_fields[1]

        if len(nonce) != self._settings.nonce_size:
            raise HandshakeError("El nonce de la confirmacion no mide " + str(self._settings.nonce_size) + " bytes.")

        cipher = AesGcmCipher(session_key, self._settings.nonce_size)
        try:
            recovered_label = cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            raise HandshakeError(
                "La confirmacion de " + self._peer_name + " no se pudo verificar (tag invalido): "
                "las claves de sesion o los transcripts no coinciden."
            )

        if recovered_label != expected_label.encode(self._settings.text_encoding):
            raise HandshakeError("La confirmacion de " + self._peer_name + " tiene un contenido inesperado.")

        self._add_to_transcript(message)
        self._view.show_success("Confirmacion de " + self._peer_name + " verificada con la clave de sesion.")

    # =========================================================================
    # Result
    # =========================================================================
    def _build_session_material(self, session_key, peer_fingerprint):
        final_digest = self._transcript.current_digest()
        session_id = final_digest[:self._settings.session_id_size]
        return SessionMaterial(
            session_key,
            session_id,
            self._peer_name,
            peer_fingerprint,
            self._build_local_fingerprint(),
        )

    # =========================================================================
    # Evidence on screen
    # =========================================================================
    def _show_bytes(self, label, data_bytes):
        """Show the size and the first bytes in hex. Never used for secrets."""
        if not self._settings.show_details:
            return
        self._view.show_bytes_preview(label, data_bytes, self._settings.hex_preview_size)