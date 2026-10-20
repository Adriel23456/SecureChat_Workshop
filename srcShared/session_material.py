# =============================================================================
# session_material.py
# -----------------------------------------------------------------------------
# The result of a SUCCESSFUL handshake. Only exists after both confirmations
# were verified, so holding one of these objects means: "both sides have the
# same session key and the peer's public key was authenticated".
#
# The session key is used by SecureChannel (Paso 4) to protect every message.
# It is never printed; only its SIZE is shown on screen.
# =============================================================================


class SessionMaterial:
    """Session key and public facts about the established session."""

    def __init__(self, session_key, session_id, peer_name, peer_fingerprint, local_fingerprint,
                 send_direction, receive_direction):
        # 32 secret bytes (AES-256). Never printed, never sent in clear.
        self.session_key = session_key

        # First bytes of the final transcript hash (public, shown on screen).
        self.session_id = session_id

        # Name the peer announced in its HELLO.
        self.peer_name = peer_name

        # KeyFingerprint of the peer's authenticated public key.
        self.peer_fingerprint = peer_fingerprint

        # KeyFingerprint of our own public key.
        self.local_fingerprint = local_fingerprint

        # Direction byte placed in the nonces WE send, and the one we expect
        # in the nonces we RECEIVE (Alice: 1 / 2, Bob: 2 / 1).
        self.send_direction = send_direction
        self.receive_direction = receive_direction

    def forget_session_key(self):
        """
        Drop the reference to the session key when the session ends (Paso 5).

        In Python this cannot guarantee the bytes are wiped from memory (bytes
        objects are immutable and freed whenever the garbage collector
        decides), but no object of the program can use the key afterwards.
        """
        self.session_key = None

    def get_session_key_size_bits(self):
        return len(self.session_key) * 8

    def get_session_id_text(self):
        return self.session_id.hex()