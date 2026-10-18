# =============================================================================
# alice_handshake.py (Alice only)
# -----------------------------------------------------------------------------
# Alice is the INITIATOR of the handshake. She:
#
#   1. sends HELLO with her name and a fresh client_random,
#   2. receives Bob's HELLO and Bob's PUBLIC_KEY,
#   3. checks Bob's public key against the trusted fingerprint (anti-MitM),
#   4. generates the session key K with the CSPRNG (never hard-coded),
#   5. encrypts K with Bob's public key (RSA-OAEP) and signs the message with
#      her own private key (RSA-PSS), then sends SESSION_KEY,
#   6. receives and verifies Bob's CONFIRM (encrypted with K),
#   7. sends her own CONFIRM (encrypted with K).
#
# K itself never travels in clear: only RSA-OAEP(K) goes on the wire.
# =============================================================================

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from errors import HandshakeError
from handshake_base import HandshakeBase
from message import MessageType


class AliceHandshake(HandshakeBase):
    """Initiator side of the SecureChat handshake."""

    def _get_send_direction(self):
        return self._settings.direction_initiator

    def _get_receive_direction(self):
        return self._settings.direction_responder

    def perform(self):
        self._view.show_handshake_title("Handshake (Alice inicia)")

        # ---- 1. HELLO -> ---------------------------------------------------------
        client_random = os.urandom(self._settings.random_size)
        self._show_bytes("client_random (publico)", client_random)
        self._send(MessageType.HELLO, self._build_hello_body(client_random), "nombre + client_random")

        # ---- 2. <- HELLO ---------------------------------------------------------
        bob_hello = self._receive(MessageType.HELLO, True)
        peer_name, server_random = self._read_hello(bob_hello)
        self._show_bytes("server_random (publico)", server_random)

        # ---- 3. <- PUBLIC_KEY and authentication -------------------------------
        public_key_message = self._receive(MessageType.PUBLIC_KEY, True)
        bob_public_key = self._load_peer_public_key(public_key_message.body)
        self._view.show_info("Llave publica de " + peer_name + ": RSA-" + str(bob_public_key.key_size))
        bob_fingerprint = self._authenticate_peer_public_key(bob_public_key)

        # ---- 4. Generate the session key ---------------------------------------
        # AESGCM.generate_key uses os.urandom (the operating system CSPRNG).
        session_key = AESGCM.generate_key(bit_length=self._settings.session_key_size_bits)
        self._view.show_success(
            "Clave de sesion generada: " + str(len(session_key) * 8) + " bits aleatorios (no se muestra)."
        )

        # ---- 5. SESSION_KEY -> ---------------------------------------------------
        encrypted_session_key = self._rsa.encrypt(bob_public_key, session_key)
        self._show_bytes("RSA-OAEP(clave de sesion)", encrypted_session_key)

        alice_public_der = self._encode_public_key(self._identity.public_key)

        transcript_before_session_key = self._transcript.current_digest()
        signed_data = self._build_session_key_signed_data(
            transcript_before_session_key, alice_public_der, encrypted_session_key
        )
        signature = self._rsa.sign(self._identity.private_key, signed_data)
        self._show_bytes("firma RSA-PSS de Alice", signature)

        session_key_body = self._fields.pack([alice_public_der, encrypted_session_key, signature])
        self._check_session_key_not_in_clear(session_key, session_key_body)
        self._send(MessageType.SESSION_KEY, session_key_body, "llave publica de Alice + clave cifrada + firma")

        # ---- 6. <- CONFIRM (Bob proves he recovered K) --------------------------
        self._receive_and_check_confirmation(session_key, self._settings.confirmation_label_responder)

        # ---- 7. CONFIRM -> (Alice proves she has K) ------------------------------
        self._send_confirmation(session_key, self._settings.confirmation_label_initiator)

        return self._build_session_material(session_key, bob_fingerprint)

    def _check_session_key_not_in_clear(self, session_key, outgoing_body):
        """
        Evidence for the report: the 32 bytes of K must not appear anywhere in
        the bytes that are about to be sent. If they did, sending is refused.
        """
        if session_key in outgoing_body:
            raise HandshakeError("La clave de sesion apareceria en claro en el mensaje; envio cancelado.")
        self._view.show_success("Comprobado: los bytes de la clave de sesion NO aparecen en el mensaje enviado.")