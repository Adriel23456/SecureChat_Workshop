# =============================================================================
# rejection_policy.py
# -----------------------------------------------------------------------------
# What to do after a record is rejected (Paso 6).
#
# Decision: DISCARD the record and continue, but END the session if several
# records in a row are rejected.
#
#   - A single rejected record is discarded: it shows no plaintext, it does
#     not move the sequence window forward, and the next authentic message is
#     still accepted. This also lets the demo show the rejection and then
#     keep chatting.
#   - If max_consecutive rejections happen in a row, the channel is treated
#     as compromised (someone is actively manipulating it) and the session
#     ends without trusting anything else that arrives.
#
# Any authentic record resets the count.
# =============================================================================


class RejectionPolicy:
    """Counts consecutive rejections and decides when the session must end."""

    def __init__(self, max_consecutive):
        self._max_consecutive = max_consecutive
        self._consecutive = 0

    def record_rejection(self):
        """Register a rejected record. Returns True if the session must end."""
        self._consecutive = self._consecutive + 1
        if self._consecutive >= self._max_consecutive:
            return True
        return False

    def record_acceptance(self):
        """An authentic record arrived: start counting again from zero."""
        self._consecutive = 0

    def get_consecutive(self):
        return self._consecutive

    def get_max_consecutive(self):
        return self._max_consecutive