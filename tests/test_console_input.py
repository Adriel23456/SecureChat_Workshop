# =============================================================================
# tests/test_console_input.py
# -----------------------------------------------------------------------------
# Automated tests of the interruptible chat prompt (Paso 5). Run from the
# repo root:
#
#     python -m pytest tests -v
#
# The Windows key-by-key reader is tested with a FAKE key source that replays
# a scripted list of keys, so these tests also run on Linux. They check that:
#
#   - typed characters, Backspace and ignored keys build the right line
#   - accents and "ñ" are kept
#   - the prompt stops by itself when the session ends (stop_event)
#   - Ctrl+C raises KeyboardInterrupt
#   - a message printed while the user is typing does NOT erase the
#     half-written text: the prompt is printed again with it
# =============================================================================

import os
import sys
import threading

TESTS_FOLDER = os.path.dirname(os.path.abspath(__file__))
REPOSITORY_ROOT = os.path.dirname(TESTS_FOLDER)
SHARED_FOLDER = os.path.join(REPOSITORY_ROOT, "srcShared")
if SHARED_FOLDER not in sys.path:
    sys.path.append(SHARED_FOLDER)

import pytest

from console_view import ConsoleView

POLL_INTERVAL = 0.001
PROMPT = "[TU] > "


class FakeKeySource:
    """
    Replays a list of keys like msvcrt would.

    An item of the list may also be a function: it is called (to simulate
    something happening while the user types) instead of producing a key.
    """

    def __init__(self, scripted_items):
        # Keep the SAME list (not a copy) so a test can add items after
        # creating the view.
        self._items = scripted_items

    def has_key(self):
        while len(self._items) > 0 and callable(self._items[0]):
            action = self._items.pop(0)
            action()
        return len(self._items) > 0

    def read_key(self):
        return self._items.pop(0)


def build_view(scripted_items):
    return ConsoleView(False, FakeKeySource(scripted_items), POLL_INTERVAL)


def test_typed_characters_build_the_line():
    view = build_view(["h", "o", "l", "a", "\r"])
    typed_line = view.read_chat_line(PROMPT, threading.Event())
    assert typed_line == "hola"


def test_backspace_removes_the_last_character():
    view = build_view(["h", "o", "l", "x", "\x08", "a", "\r"])
    typed_line = view.read_chat_line(PROMPT, threading.Event())
    assert typed_line == "hola"


def test_backspace_on_empty_line_does_nothing():
    view = build_view(["\x08", "\x08", "o", "k", "\r"])
    typed_line = view.read_chat_line(PROMPT, threading.Event())
    assert typed_line == "ok"


def test_arrow_and_function_keys_are_ignored():
    # "\xe0" + "K" is the left arrow; "\x00" + ";" is F1; "\x1b" is Escape.
    view = build_view(["a", "\xe0", "K", "\x00", ";", "\x1b", "b", "\r"])
    typed_line = view.read_chat_line(PROMPT, threading.Event())
    assert typed_line == "ab"


def test_accents_and_enie_are_kept():
    view = build_view(["¿", "q", "u", "é", " ", "ñ", "?", "\r"])
    typed_line = view.read_chat_line(PROMPT, threading.Event())
    assert typed_line == "¿qué ñ?"


def test_prompt_returns_none_when_the_session_ends():
    stop_event = threading.Event()
    stop_event.set()
    view = build_view([])
    typed_line = view.read_chat_line(PROMPT, stop_event)
    assert typed_line is None


def test_prompt_wakes_up_when_the_peer_leaves_while_waiting():
    stop_event = threading.Event()
    # No keys at all; another thread ends the session shortly after.
    timer = threading.Timer(0.05, stop_event.set)
    timer.start()
    view = build_view([])
    typed_line = view.read_chat_line(PROMPT, stop_event)
    timer.join()
    assert typed_line is None


def test_ctrl_c_raises_keyboard_interrupt():
    view = build_view(["a", "\x03"])
    with pytest.raises(KeyboardInterrupt):
        view.read_chat_line(PROMPT, threading.Event())


def test_incoming_message_keeps_the_half_written_text(capsys):
    items = []
    view = ConsoleView(False, FakeKeySource(items), POLL_INTERVAL)

    def peer_message_arrives():
        view.show_info("mensaje del par")

    items.append("h")
    items.append("o")
    items.append(peer_message_arrives)
    items.append("l")
    items.append("a")
    items.append("\r")

    typed_line = view.read_chat_line(PROMPT, threading.Event())
    printed_text = capsys.readouterr().out

    assert typed_line == "hola"
    # After the incoming message the prompt is printed again WITH "ho".
    message_position = printed_text.find("mensaje del par")
    assert message_position >= 0
    text_after_message = printed_text[message_position:]
    assert (PROMPT + "ho") in text_after_message