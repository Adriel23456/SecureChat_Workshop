# =============================================================================
# tests/test_secure_channel.py
# -----------------------------------------------------------------------------
# Automated tests of the message protection (Paso 4). Run from the repo root:
#
#     python -m pytest tests -v
#
# They build two SecureChannel objects (one for Alice, one for Bob) that share
# the same random session key, exactly like after a real handshake, and check:
#
#   - the plaintext never appears inside the bytes that would go to the socket
#   - 10 000 consecutive encryptions never repeat a nonce
#   - messages decrypt correctly in both directions (UTF-8 included)
#   - altering ANY byte is detected and no plaintext is returned
#   - replayed, reflected and type-swapped records are rejected
#   - the counter limit ends the session instead of reusing a nonce
# =============================================================================

import os
import sys

# -----------------------------------------------------------------------------
# Make srcShared importable (same idea as in main.py; no __init__.py needed)
# -----------------------------------------------------------------------------
TESTS_FOLDER = os.path.dirname(os.path.abspath(__file__))
REPOSITORY_ROOT = os.path.dirname(TESTS_FOLDER)
SHARED_FOLDER = os.path.join(REPOSITORY_ROOT, "srcShared")
if SHARED_FOLDER not in sys.path:
    sys.path.append(SHARED_FOLDER)

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import shared_config
from errors import MessageAuthenticationError
from errors import NonceExhaustedError
from errors import ReplayError
from message import Message
from message import MessageCodec
from message import MessageType
from nonce_sequence import NonceLayout
from secure_channel import SecureChannel
from secure_channel import SecureChannelSettings
from session_material import SessionMaterial


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
NUMBER_OF_NONCES_TO_CHECK = 10000
TEXT_ENCODING = shared_config.TEXT_ENCODING


def build_layout():
    return NonceLayout(shared_config.NONCE_DIRECTION_SIZE_BYTES, shared_config.NONCE_COUNTER_SIZE_BYTES)


def build_settings(max_counter):
    layout = build_layout()
    return SecureChannelSettings(
        shared_config.PROTOCOL_LABEL.encode(TEXT_ENCODING),
        layout,
        shared_config.AES_GCM_TAG_SIZE_BYTES,
        shared_config.FIRST_MESSAGE_COUNTER,
        max_counter,
    )


def build_channel_pair(max_counter=shared_config.MAX_MESSAGE_COUNTER):
    """Return (alice_channel, bob_channel) sharing one random session key."""
    session_key = AESGCM.generate_key(bit_length=shared_config.SESSION_KEY_SIZE_BITS)
    session_id = os.urandom(shared_config.SESSION_ID_SIZE_BYTES)
    to_bob = shared_config.DIRECTION_INITIATOR_TO_RESPONDER
    to_alice = shared_config.DIRECTION_RESPONDER_TO_INITIATOR

    alice_material = SessionMaterial(session_key, session_id, "Bob", None, None, to_bob, to_alice)
    bob_material = SessionMaterial(session_key, session_id, "Alice", None, None, to_alice, to_bob)

    settings = build_settings(max_counter)
    return SecureChannel(alice_material, settings), SecureChannel(bob_material, settings)


def build_frame(codec, message_type, body):
    """Exactly the bytes ChatSession hands to FramedConnection.send_frame()."""
    return codec.encode(Message(message_type, body))


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
def test_plaintext_never_appears_in_sent_bytes():
    alice_channel, bob_channel = build_channel_pair()
    codec = MessageCodec(TEXT_ENCODING)
    sample_texts = [
        "Hola Bob",
        "mensaje secreto 123",
        "¿Cómo estás? Ñandú, acción, pingüino",
        "a" * 200,
    ]

    for text in sample_texts:
        plaintext = text.encode(TEXT_ENCODING)
        sealed_record = alice_channel.seal(MessageType.CHAT, plaintext)
        frame = build_frame(codec, MessageType.CHAT, sealed_record.body)

        assert plaintext not in frame
        assert len(sealed_record.ciphertext) == len(plaintext)
        assert len(sealed_record.tag) == shared_config.AES_GCM_TAG_SIZE_BYTES


def test_ten_thousand_nonces_never_repeat():
    alice_channel, bob_channel = build_channel_pair()
    seen_nonces = set()
    previous_counter = 0

    index = 0
    while index < NUMBER_OF_NONCES_TO_CHECK:
        sealed_record = alice_channel.seal(MessageType.CHAT, b"x")
        assert sealed_record.nonce not in seen_nonces
        assert sealed_record.counter == previous_counter + 1
        seen_nonces.add(sealed_record.nonce)
        previous_counter = sealed_record.counter
        index = index + 1

    assert len(seen_nonces) == NUMBER_OF_NONCES_TO_CHECK


def test_directions_use_disjoint_nonces():
    alice_channel, bob_channel = build_channel_pair()
    alice_record = alice_channel.seal(MessageType.CHAT, b"hola")
    bob_record = bob_channel.seal(MessageType.CHAT, b"hola")

    # Same counter (1) on both sides, but different direction byte.
    assert alice_record.counter == bob_record.counter
    assert alice_record.nonce != bob_record.nonce
    assert alice_record.nonce[0] == shared_config.DIRECTION_INITIATOR_TO_RESPONDER
    assert bob_record.nonce[0] == shared_config.DIRECTION_RESPONDER_TO_INITIATOR


def test_chat_nonces_never_collide_with_handshake_confirmation_nonces():
    layout = build_layout()
    confirmation_nonce = layout.build(
        shared_config.DIRECTION_INITIATOR_TO_RESPONDER, shared_config.HANDSHAKE_CONFIRMATION_COUNTER
    )
    alice_channel, bob_channel = build_channel_pair()

    index = 0
    while index < 100:
        sealed_record = alice_channel.seal(MessageType.CHAT, b"x")
        assert sealed_record.nonce != confirmation_nonce
        index = index + 1


def test_round_trip_both_directions_with_utf8():
    alice_channel, bob_channel = build_channel_pair()
    text = "¿Qué tal? Ñ á é í ó ú"

    sealed_by_alice = alice_channel.seal(MessageType.CHAT, text.encode(TEXT_ENCODING))
    opened_by_bob = bob_channel.open(MessageType.CHAT, sealed_by_alice.body)
    assert opened_by_bob.plaintext.decode(TEXT_ENCODING) == text

    sealed_by_bob = bob_channel.seal(MessageType.CHAT, b"respuesta")
    opened_by_alice = alice_channel.open(MessageType.CHAT, sealed_by_bob.body)
    assert opened_by_alice.plaintext == b"respuesta"


def test_any_altered_byte_is_rejected():
    alice_channel, bob_channel = build_channel_pair()
    sealed_record = alice_channel.seal(MessageType.CHAT, b"no me modifiques")
    nonce_size = build_layout().get_nonce_size()

    # Try every byte AFTER the nonce (ciphertext and tag). Bytes of the nonce
    # are covered by test_altered_nonce_is_rejected.
    position = nonce_size
    while position < len(sealed_record.body):
        altered_body = bytearray(sealed_record.body)
        altered_body[position] = altered_body[position] ^ 0x01
        with pytest.raises(MessageAuthenticationError):
            bob_channel.open(MessageType.CHAT, bytes(altered_body))
        position = position + 1

    # The original is still accepted afterwards: rejections do not advance the counter.
    opened_record = bob_channel.open(MessageType.CHAT, sealed_record.body)
    assert opened_record.plaintext == b"no me modifiques"


def test_altered_nonce_is_rejected():
    alice_channel, bob_channel = build_channel_pair()
    sealed_record = alice_channel.seal(MessageType.CHAT, b"hola")

    # Changing the counter from 1 to 3 passes the sequence check, but the nonce
    # is authenticated (it is part of the AAD and of the GCM computation).
    altered_body = bytearray(sealed_record.body)
    last_nonce_byte = build_layout().get_nonce_size() - 1
    altered_body[last_nonce_byte] = altered_body[last_nonce_byte] ^ 0x02

    with pytest.raises(MessageAuthenticationError):
        bob_channel.open(MessageType.CHAT, bytes(altered_body))


def test_replayed_record_is_rejected():
    alice_channel, bob_channel = build_channel_pair()
    sealed_record = alice_channel.seal(MessageType.CHAT, b"pagar 100")

    bob_channel.open(MessageType.CHAT, sealed_record.body)
    with pytest.raises(ReplayError):
        bob_channel.open(MessageType.CHAT, sealed_record.body)


def test_older_record_is_rejected():
    alice_channel, bob_channel = build_channel_pair()
    first_record = alice_channel.seal(MessageType.CHAT, b"primero")
    second_record = alice_channel.seal(MessageType.CHAT, b"segundo")

    bob_channel.open(MessageType.CHAT, second_record.body)
    with pytest.raises(ReplayError):
        bob_channel.open(MessageType.CHAT, first_record.body)


def test_reflected_record_is_rejected():
    alice_channel, bob_channel = build_channel_pair()
    sealed_by_alice = alice_channel.seal(MessageType.CHAT, b"hola")

    # An attacker sends Alice's own record back to Alice.
    with pytest.raises(ReplayError):
        alice_channel.open(MessageType.CHAT, sealed_by_alice.body)


def test_chat_record_cannot_be_used_as_bye():
    alice_channel, bob_channel = build_channel_pair()
    sealed_record = alice_channel.seal(MessageType.CHAT, b"")

    # Same bytes, different type in the frame: the AAD no longer matches.
    with pytest.raises(MessageAuthenticationError):
        bob_channel.open(MessageType.BYE, sealed_record.body)


def test_record_from_another_session_is_rejected():
    alice_channel, bob_channel = build_channel_pair()
    other_alice_channel, other_bob_channel = build_channel_pair()
    sealed_record = other_alice_channel.seal(MessageType.CHAT, b"de otra sesion")

    with pytest.raises(MessageAuthenticationError):
        bob_channel.open(MessageType.CHAT, sealed_record.body)


def test_counter_exhaustion_stops_instead_of_reusing_nonces():
    alice_channel, bob_channel = build_channel_pair(max_counter=3)

    alice_channel.seal(MessageType.CHAT, b"1")
    alice_channel.seal(MessageType.CHAT, b"2")
    alice_channel.seal(MessageType.CHAT, b"3")
    with pytest.raises(NonceExhaustedError):
        alice_channel.seal(MessageType.CHAT, b"4")