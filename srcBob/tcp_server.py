# =============================================================================
# tcp_server.py (Bob only)
# -----------------------------------------------------------------------------
# Bob is the side that WAITS for the connection:
#     socket() -> setsockopt() -> bind() -> listen() -> accept()
# =============================================================================

import os
import socket

from connection_establisher import ConnectionEstablisher
from framed_connection import FramedConnection


class TcpServer(ConnectionEstablisher):
    """Listens on host:port and accepts exactly one client."""

    def __init__(self, host, port, backlog, poll_timeout, max_frame_size):
        self._host = host
        self._port = port
        self._backlog = backlog
        self._poll_timeout = poll_timeout
        self._max_frame_size = max_frame_size

    def describe(self):
        return "Esperando a que el par se conecte en " + self._host + ":" + str(self._port) + " ..."

    def establish(self):
        """
        Wait for one incoming connection and return it as a FramedConnection.

        Raises OSError if the port cannot be opened (for example, it is in use).
        Raises KeyboardInterrupt if the user presses Ctrl+C while waiting.
        """
        listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self._configure_address_reuse(listening_socket)

            listening_socket.bind((self._host, self._port))
            listening_socket.listen(self._backlog)

            # Without a timeout, accept() blocks forever and, on Windows,
            # Ctrl+C is not delivered until it returns. With a timeout,
            # accept() wakes up periodically and Ctrl+C can take effect.
            listening_socket.settimeout(self._poll_timeout)

            client_socket = None
            client_address = None
            while client_socket is None:
                try:
                    client_socket, client_address = listening_socket.accept()
                except socket.timeout:
                    continue
        finally:
            # Bob serves a single peer, so the listening socket is no longer
            # needed once accept() returned (or if anything failed).
            listening_socket.close()

        return FramedConnection(client_socket, client_address, self._max_frame_size, self._poll_timeout)

    def _configure_address_reuse(self, listening_socket):
        """
        Let Bob be restarted immediately on the same port.

        - Linux/macOS: SO_REUSEADDR allows binding while old connections on the
          port are still in TIME_WAIT.
        - Windows: SO_REUSEADDR has a different and unsafe meaning (another
          program could bind the SAME port at the same time). Windows already
          allows re-binding during TIME_WAIT, so the right option there is
          SO_EXCLUSIVEADDRUSE, which forbids anyone else from sharing the port.
        """
        if os.name == "nt":
            listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)