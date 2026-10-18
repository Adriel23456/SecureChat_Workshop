# =============================================================================
# binary_fields.py
# -----------------------------------------------------------------------------
# Some handshake messages carry SEVERAL binary values in one body (for
# example: public key + encrypted session key + signature). Because the values
# are raw bytes, no separator character is safe. Each field is therefore
# written with its own length in front:
#
#     +-------------+-----------+-------------+-----------+----
#     | len1 (4 B)  | field 1   | len2 (4 B)  | field 2   | ...
#     +-------------+-----------+-------------+-----------+----
#
# unpack() checks that the body contains EXACTLY the expected number of
# fields and nothing else, so a malformed or truncated body is rejected.
# =============================================================================

import struct

from errors import ProtocolError


class BinaryFields:
    """Packs a list of byte strings into one body and unpacks it again."""

    def __init__(self, length_format):
        self._length_format = length_format
        self._length_size = struct.calcsize(length_format)

    def pack(self, field_list):
        """[bytes, bytes, ...] -> one bytes object."""
        packed_parts = []
        for field in field_list:
            length_prefix = struct.pack(self._length_format, len(field))
            packed_parts.append(length_prefix)
            packed_parts.append(field)
        return b"".join(packed_parts)

    def unpack(self, body, expected_field_count):
        """One bytes object -> [bytes, bytes, ...] with exactly expected_field_count items."""
        fields = []
        position = 0
        body_size = len(body)

        while position < body_size:
            # ---- Read the length prefix --------------------------------------
            prefix_end = position + self._length_size
            if prefix_end > body_size:
                raise ProtocolError("Mensaje truncado: falta el largo de un campo.")

            length_prefix = body[position:prefix_end]
            unpacked_values = struct.unpack(self._length_format, length_prefix)
            field_size = unpacked_values[0]

            # ---- Read the field itself ---------------------------------------
            field_end = prefix_end + field_size
            if field_end > body_size:
                raise ProtocolError("Mensaje truncado: un campo es mas corto que su largo anunciado.")

            fields.append(body[prefix_end:field_end])
            position = field_end

        if len(fields) != expected_field_count:
            raise ProtocolError(
                "Se esperaban " + str(expected_field_count) + " campos y llegaron " + str(len(fields)) + "."
            )

        return fields