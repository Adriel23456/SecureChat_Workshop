# =============================================================================
# errors.py
# -----------------------------------------------------------------------------
# Custom exceptions of SecureChat. Having our own exception types lets each
# layer report *what* went wrong without the upper layers having to inspect
# low-level socket errors.
# =============================================================================


class SecureChatError(Exception):
    """Base class for every error raised by SecureChat itself."""


class ConnectionClosedError(SecureChatError):
    """The peer closed the TCP connection (recv returned b"")."""


class FrameTooLargeError(SecureChatError):
    """A frame announced or attempted a size above MAX_FRAME_SIZE."""


class ProtocolError(SecureChatError):
    """The peer sent something that does not follow the protocol."""


class PeerNotAvailableError(SecureChatError):
    """The peer could not be reached (for example, nobody is listening)."""


class KeyMaterialError(SecureChatError):
    """A key file is missing, damaged, too weak or the passphrase is wrong."""


class HandshakeError(SecureChatError):
    """The handshake failed; the connection must be closed without chatting."""