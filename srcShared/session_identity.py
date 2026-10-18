# =============================================================================
# session_identity.py
# -----------------------------------------------------------------------------
# Everything the local participant needs BEFORE starting a handshake:
#
#   - its own private key (already decrypted with the passphrase, in memory)
#   - its own public key
#   - the trusted fingerprint of the peer's public key (registered out-of-band)
#
# Loaded once per chat, right before connecting, so the handshake never has to
# stop and wait for the user to type a passphrase.
# =============================================================================


class SessionIdentity:
    """Local key material for one chat session."""

    def __init__(self, local_name, private_key, trusted_peer_fingerprint):
        self.local_name = local_name

        # Never printed and never sent anywhere.
        self.private_key = private_key

        # Derived from the private key, so both are guaranteed to match.
        self.public_key = private_key.public_key()

        # KeyFingerprint the peer's public key must match.
        self.trusted_peer_fingerprint = trusted_peer_fingerprint