# =============================================================================
# tcp_client.py (Alice only)
# -----------------------------------------------------------------------------
# Alice is the side that STARTS the connection:
#     socket() -> connect()
# =============================================================================

import socket

from connection_establisher import ConnectionEstablisher
from errors import PeerNotAvailableError
from framed_connection import FramedConnection


class TcpClient(ConnectionEstablisher):
    """Connects to host:port where the peer is listening."""

    def __init__(self, host, port, connect_timeout, poll_timeout, max_frame_size):
        self._host = host
        self._port = port
        self._connect_timeout = connect_timeout
        self._poll_timeout = poll_timeout
        self._max_frame_size = max_frame_size

    def describe(self):
        return "Conectando con el par en " + self._host + ":" + str(self._port) + " ..."

    def establish(self):
        """
        Open the TCP connection and return it as a FramedConnection.

        Raises PeerNotAvailableError if nobody is listening or it takes too long.
        """
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Limit how long connect() may block.
        client_socket.settimeout(self._connect_timeout)

        try:
            client_socket.connect((self._host, self._port))
        except ConnectionRefusedError:
            # On Windows: WinError 10061. Nothing is listening on that port.
            client_socket.close()
            raise PeerNotAvailableError(
                "Nadie esta escuchando en " + self._host + ":" + str(self._port)
                + ". Inicie primero a Bob y elija la opcion 1 en su menu."
            )
        except socket.timeout:
            client_socket.close()
            raise PeerNotAvailableError(
                "El par no respondio en " + str(self._connect_timeout) + " segundos."
            )
        except OSError as error:
            client_socket.close()
            raise PeerNotAvailableError("No se pudo conectar: " + str(error))

        # getpeername() returns the (ip, port) of Bob as seen by this socket.
        peer_address = client_socket.getpeername()

        return FramedConnection(client_socket, peer_address, self._max_frame_size, self._poll_timeout)