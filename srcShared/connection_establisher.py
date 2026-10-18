# =============================================================================
# connection_establisher.py
# -----------------------------------------------------------------------------
# Abstract "how do I get a connection?" interface.
#
#   - Bob implements it with TcpServer  (bind + listen + accept).
#   - Alice implements it with TcpClient (connect).
#
# The chat logic (ChatSession) never cares which one was used; it only
# receives the resulting FramedConnection. This is the Dependency Inversion
# principle: high-level code depends on an abstraction, not on sockets.
# =============================================================================

from abc import ABC
from abc import abstractmethod


class ConnectionEstablisher(ABC):
    """Something that can produce a connected FramedConnection."""

    @abstractmethod
    def establish(self):
        """Block until a connection exists and return a FramedConnection."""

    @abstractmethod
    def describe(self):
        """Short text explaining what establish() will do (for the console)."""