# =============================================================================
# bob_handshake.py (Bob only)
# -----------------------------------------------------------------------------
# Bob is the RESPONDER of the handshake. He:
#
#   1. receives Alice's HELLO,
#   2. sends HELLO with his name and a fresh server_random,
#   3. sends his PUBLIC_KEY (the private key never leaves his process),
#   4. receives SESSION_KEY and:
#        a. checks Alice's public key against the trusted fingerprint,
#        b. verifies Alice's RSA-PSS signature,
#        c. decrypts the session key with his PRIVATE key (RSA-OAEP),
#   5. sends CONFIRM (encrypted with K) to prove he recovered K,
#   6. receives and verifies Alice's CONFIRM.
# =============================================================================

import os

from errors import HandshakeError
from handshake_base import HandshakeBase
from message import MessageType


class BobHandshake(HandshakeBase):
    """Responder side of the SecureChat handshake."""

    def perform(self):
        self._view.show_handshake_title("Handshake (Bob responde)")

        # ---- 1. <- HELLO ---------------------------------------------------------
        alice_hello = self._receive(MessageType.HELLO, True)
        peer_name, client_random = self._read_hello(alice_hello)
        self._show_bytes("client_random (publico)", client_random)

        # ---- 2. HELLO -> ---------------------------------------------------------
        server_random = os.urandom(self._settings.random_size)
        self._show_bytes("server_random (publico)", server_random)
        self._send(MessageType.HELLO, self._build_hello_body(server_random), "nombre + server_random")

        # ---- 3. PUBLIC_KEY -> ----------------------------------------------------
        bob_public_der = self._encode_public_key(self._identity.public_key)
        self._send(
            MessageType.PUBLIC_KEY,
            bob_public_der,
            "llave publica RSA-" + str(self._identity.public_key.key_size) + " (la privada no sale de aqui)",
        )

        # ---- 4. <- SESSION_KEY ---------------------------------------------------
        transcript_before_session_key = self._transcript.current_digest()
        session_key_message = self._receive(MessageType.SESSION_KEY, False)

        session_key_fields = self._unpack_fields(session_key_message.body, 3, "SESSION_KEY")
        alice_public_der = session_key_fields[0]
        encrypted_session_key = session_key_fields[1]
        signature = session_key_fields[2]
        self._show_bytes("RSA-OAEP(clave de sesion) recibido", encrypted_session_key)

        # 4a. Is this really Alice's public key?
        alice_public_key = self._load_peer_public_key(alice_public_der)
        alice_fingerprint = self._authenticate_peer_public_key(alice_public_key)

        # 4b. Did Alice really produce this message, for THIS handshake?
        signed_data = self._build_session_key_signed_data(
            transcript_before_session_key, alice_public_der, encrypted_session_key
        )
        signature_is_valid = self._rsa.verify(alice_public_key, signature, signed_data)
        if not signature_is_valid:
            raise HandshakeError("La firma de " + peer_name + " sobre la clave de sesion NO es valida.")
        self._view.show_success("Firma RSA-PSS de " + peer_name + " verificada.")

        # 4c. Recover K with Bob's private key.
        try:
            session_key = self._rsa.decrypt(self._identity.private_key, encrypted_session_key)
        except ValueError:
            raise HandshakeError("No se pudo descifrar la clave de sesion con la llave privada de Bob.")

        expected_key_size = self._settings.session_key_size_bits // 8
        if len(session_key) != expected_key_size:
            raise HandshakeError("La clave de sesion recibida no mide " + str(expected_key_size) + " bytes.")

        self._add_to_transcript(session_key_message)
        self._view.show_success(
            "Clave de sesion recuperada con la llave privada: " + str(len(session_key) * 8) + " bits (no se muestra)."
        )

        # ---- 5. CONFIRM -> (Bob proves he recovered K) ----------------------------
        self._send_confirmation(session_key, self._settings.confirmation_label_responder)

        # ---- 6. <- CONFIRM (Alice proves she has K) -------------------------------
        self._receive_and_check_confirmation(session_key, self._settings.confirmation_label_initiator)

        return self._build_session_material(session_key, alice_fingerprint)