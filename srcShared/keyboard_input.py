# =============================================================================
# keyboard_input.py
# -----------------------------------------------------------------------------
# Low-level access to the keyboard for the CHAT prompt (Paso 5).
#
# Problem with input():
#   - It blocks until Enter and cannot be interrupted by another thread, so
#     when the peer leaves, the user had to press Enter to get back.
#   - We never know what the user has typed so far, so an incoming message
#     erases the half-written line from the screen.
#
# Solution on Windows: read the console KEY BY KEY with msvcrt.
#   - msvcrt.kbhit()  -> True if a key is waiting (does not block)
#   - msvcrt.getwch() -> returns that key as a Unicode character
# ConsoleView builds the line itself, so it always knows the text typed so
# far and can redraw it, and it can stop waiting when the session ends.
#
# When there is no Windows console (Linux, or input redirected from a file),
# create_key_source() returns None and ConsoleView uses another strategy.
# =============================================================================

import os
import sys


class WindowsConsoleKeySource:
    """Reads single keys from the Windows console without blocking."""

    def __init__(self):
        # Imported here because msvcrt only exists on Windows.
        import msvcrt
        self._msvcrt = msvcrt

    def has_key(self):
        """True if at least one key is waiting to be read."""
        return self._msvcrt.kbhit()

    def read_key(self):
        """Return the next key as a one-character string."""
        return self._msvcrt.getwch()


def create_key_source():
    """
    Return a WindowsConsoleKeySource when running in a real Windows console,
    or None in any other situation.
    """
    if os.name != "nt":
        return None

    # If the input is redirected (a file or a pipe), kbhit() does not work.
    if not sys.stdin.isatty():
        return None

    try:
        key_source = WindowsConsoleKeySource()
    except ImportError:
        return None

    return key_source