# =============================================================================
# framed_connection.py
# -----------------------------------------------------------------------------
# TCP is a byte *stream*: one send() on one side does not necessarily arrive
# as one recv() on the other side. Two messages can arrive glued together, or
# one message can arrive split in pieces.
#
# This class solves that with length-prefix framing:
#
#     +----------------------+---------------------------+
#     | length (4 bytes, BE) | payload (length bytes)    |
#     +----------------------+---------------------------+
#
# The receiver first reads exactly 4 bytes, learns the payload size, and then
# reads exactly that many bytes. That is one frame.
#
# Single responsibility: this class only knows how to move whole frames of
# bytes. It does not know what the bytes mean (that is message.py).
# =============================================================================

import socket
import struct
import threading
import time

import shared_config
from errors import ConnectionClosedError
from errors import FrameTooLargeError
from errors import ProtocolError


class FramedConnection:
    """Wraps a connected TCP socket and sends/receives whole frames."""

    def __init__(self, connected_socket, peer_address, max_frame_size, poll_timeout):
        # The already connected socket (from accept() on Bob, connect() on Alice).
        self._socket = connected_socket

        # (ip, port) tuple of the other end, used only for display.
        self._peer_address = peer_address

        # Largest payload size we accept or send.
        self._max_frame_size = max_frame_size

        # The socket wakes up from recv() every poll_timeout seconds so the
        # receiver can check whether it was asked to stop.
        self._socket.settimeout(poll_timeout)

        # Two threads may want to send at the same time (the keyboard thread
        # and, in later steps, protocol replies). The lock keeps every frame
        # in one piece on the wire.
        self._send_lock = threading.Lock()

        # Protects the "closed" flag so close() is safe to call twice.
        self._close_lock = threading.Lock()
        self._closed = False

    # -------------------------------------------------------------------------
    # Public information
    # -------------------------------------------------------------------------
    def get_peer_address_text(self):
        """Return the peer address as "ip:port"."""
        peer_ip = self._peer_address[0]
        peer_port = self._peer_address[1]
        return peer_ip + ":" + str(peer_port)

    def is_closed(self):
        """Return True once close() has been called."""
        with self._close_lock:
            return self._closed

    # -------------------------------------------------------------------------
    # Sending
    # -------------------------------------------------------------------------
    def send_frame(self, payload):
        """Send one frame: 4-byte length prefix followed by the payload."""
        payload_size = len(payload)

        # Refuse to send something the other side would reject anyway.
        if payload_size > self._max_frame_size:
            raise FrameTooLargeError(
                "El mensaje mide " + str(payload_size)
                + " bytes y el maximo es " + str(self._max_frame_size) + " bytes."
            )

        # struct.pack("!I", n) turns the integer n into 4 big-endian bytes.
        length_prefix = struct.pack(shared_config.LENGTH_PREFIX_FORMAT, payload_size)
        frame = length_prefix + payload

        # sendall() keeps calling send() until every byte left the process.
        with self._send_lock:
            self._socket.sendall(frame)

    # -------------------------------------------------------------------------
    # Receiving
    # -------------------------------------------------------------------------
    def receive_frame(self, stop_event, timeout_seconds=None):
        """
        Receive one whole frame and return its payload as bytes.

        Returns None if stop_event was set while waiting.
        Raises ProtocolError if timeout_seconds is given and expires.
        Raises ConnectionClosedError if the peer closed the connection.
        Raises FrameTooLargeError if the announced size is above the limit.
        """
        # Convert the optional relative timeout into an absolute deadline.
        deadline = None
        if timeout_seconds is not None:
            deadline = time.monotonic() + timeout_seconds

        # Step 1: read exactly the 4-byte length prefix.
        length_prefix = self._receive_exact(shared_config.LENGTH_PREFIX_SIZE, stop_event, deadline)
        if length_prefix is None:
            return None

        # struct.unpack always returns a tuple, even for a single value.
        unpacked_values = struct.unpack(shared_config.LENGTH_PREFIX_FORMAT, length_prefix)
        payload_size = unpacked_values[0]

        # Step 2: validate the size BEFORE reading the payload, so a bogus
        # prefix cannot make us wait for (or allocate) gigabytes.
        if payload_size > self._max_frame_size:
            raise FrameTooLargeError(
                "El par anuncio una trama de " + str(payload_size)
                + " bytes; el maximo permitido es " + str(self._max_frame_size) + " bytes."
            )

        # An empty payload is a valid (if useless) frame.
        if payload_size == 0:
            return b""

        # Step 3: read exactly payload_size bytes.
        payload = self._receive_exact(payload_size, stop_event, deadline)
        return payload

    def _receive_exact(self, byte_count, stop_event, deadline):
        """
        Keep calling recv() until exactly byte_count bytes were received.

        recv(n) may return FEWER than n bytes, so a single call is not enough.
        """
        received_chunks = []
        received_total = 0

        while received_total < byte_count:
            # Someone asked us to stop (for example, the user typed /salir).
            if stop_event.is_set():
                return None

            # A deadline was given (handshake) and it already passed.
            if deadline is not None:
                if time.monotonic() > deadline:
                    raise ProtocolError("Se agoto el tiempo de espera de datos del par.")

            bytes_still_missing = byte_count - received_total

            try:
                chunk = self._socket.recv(bytes_still_missing)
            except socket.timeout:
                # Nothing arrived during SOCKET_POLL_TIMEOUT; loop again so we
                # can re-check stop_event and the deadline.
                continue

            # recv() returning an empty bytes object means the peer closed
            # its side of the connection in an orderly way.
            if chunk == b"":
                raise ConnectionClosedError("El par cerro la conexion.")

            received_chunks.append(chunk)
            received_total = received_total + len(chunk)

        # Glue all pieces together into one bytes object.
        complete_data = b"".join(received_chunks)
        return complete_data

    # -------------------------------------------------------------------------
    # Closing
    # -------------------------------------------------------------------------
    def close(self):
        """Shut down both directions and release the socket. Safe to call twice."""
        with self._close_lock:
            if self._closed:
                return
            self._closed = True

        # shutdown() tells the peer "no more data in either direction";
        # its recv() will then return b"". It can fail if the peer already
        # vanished, which is fine at this point.
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        # close() releases the operating-system handle.
        try:
            self._socket.close()
        except OSError:
            pass