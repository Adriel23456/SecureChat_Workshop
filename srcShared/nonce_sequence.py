# =============================================================================
# nonce_sequence.py
# -----------------------------------------------------------------------------
# Builds and reads the 96-bit AES-GCM nonces used by SecureChat:
#
#     +------------------+-------------------------------------------+
#     | direction (1 B)  | counter (11 B, big-endian)                |
#     +------------------+-------------------------------------------+
#
#   direction 1 = Alice -> Bob, direction 2 = Bob -> Alice.
#
# NonceLayout  : converts (direction, counter) <-> 12 bytes.
# NonceSequence: hands out the nonces of ONE sending direction, in order:
#                counter 1, 2, 3, ... It never goes backwards and refuses to
#                continue when the counter would overflow, so a nonce is never
#                repeated under the same key.
#
# The counter also works as the message SEQUENCE NUMBER: the receiver uses it
# to reject replayed (repeated) records.
# =============================================================================

from errors import NonceExhaustedError
from errors import ProtocolError


class NonceLayout:
    """Packs and unpacks direction || counter."""

    def __init__(self, direction_size, counter_size):
        self._direction_size = direction_size
        self._counter_size = counter_size

    def get_nonce_size(self):
        return self._direction_size + self._counter_size

    def build(self, direction, counter):
        direction_bytes = direction.to_bytes(self._direction_size, "big")
        counter_bytes = counter.to_bytes(self._counter_size, "big")
        return direction_bytes + counter_bytes

    def parse(self, nonce):
        """Return (direction, counter). Raises ProtocolError if the size is wrong."""
        if len(nonce) != self.get_nonce_size():
            raise ProtocolError("El nonce debe medir " + str(self.get_nonce_size()) + " bytes.")

        direction_bytes = nonce[:self._direction_size]
        counter_bytes = nonce[self._direction_size:]

        direction = int.from_bytes(direction_bytes, "big")
        counter = int.from_bytes(counter_bytes, "big")
        return direction, counter


class NonceSequence:
    """Nonces for ONE sending direction: first_counter, first_counter + 1, ..."""

    def __init__(self, layout, direction, first_counter, max_counter):
        self._layout = layout
        self._direction = direction
        self._next_counter = first_counter
        self._max_counter = max_counter

    def next_nonce(self):
        """Return (nonce, counter) and advance. Raises NonceExhaustedError at the limit."""
        if self._next_counter > self._max_counter:
            raise NonceExhaustedError(
                "Se agoto el contador de nonces de esta direccion; la sesion debe terminar."
            )

        counter = self._next_counter
        nonce = self._layout.build(self._direction, counter)
        self._next_counter = self._next_counter + 1
        return nonce, counter