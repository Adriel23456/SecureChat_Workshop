# =============================================================================
# tests/test_tampering.py
# -----------------------------------------------------------------------------
# Automated tests of Paso 6 (integrity). Run from the repo root:
#
#     python -m pytest tests -v
#
# They check that:
#   - altering 1 byte of the ciphertext, the tag, the nonce or the AAD makes
#     AES-GCM raise InvalidTag (checked both with the raw AESGCM class and
#     through SecureChannel, which turns it into MessageAuthenticationError)
#   - RecordTamperer (the /alterar command) changes exactly one byte, never
#     the size, and every one of its targets is rejected by the receiver
#   - a captured valid frame sent again is rejected by its sequence number
#   - after a rejection the next authentic message is still accepted
#   - RejectionPolicy ends the session only after N rejections IN A ROW
# =============================================================================

import os
import sys

TESTS_FOLDER = os.path.dirname(os.path.abspath(__file__))
REPOSITORY_ROOT = os.path.dirname(TESTS_FOLDER)
SHARED_FOLDER = os.path.join(REPOSITORY_ROOT, "srcShared")
if SHARED_FOLDER not in sys.path:
    sys.path.append(SHARED_FOLDER)

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import shared_config
from errors import MessageAuthenticationError
from errors import ReplayError
from message import Message
from message import MessageCodec
from message import MessageType
from nonce_sequence import NonceLayout
from record_tamperer import RecordTamperer
from rejection_policy import RejectionPolicy
from secure_channel import SecureChannel
from secure_channel import SecureChannelSettings
from session_material import SessionMaterial

TEXT_ENCODING = shared_config.TEXT_ENCODING
NONCE_SIZE = shared_config.AES_GCM_NONCE_SIZE_BYTES
TAG_SIZE = shared_config.AES_GCM_TAG_SIZE_BYTES
SAMPLE_PLAINTEXT = "transferir 100 colones a Bob".encode(TEXT_ENCODING)
SAMPLE_AAD = b"SecureChat-v1|tipo=2|sesion=0011223344556677"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def build_layout():
    return NonceLayout(shared_config.NONCE_DIRECTION_SIZE_BYTES, shared_config.NONCE_COUNTER_SIZE_BYTES)


def build_channel_pair():
    """Return (alice_channel, bob_channel) sharing one random session key."""
    session_key = AESGCM.generate_key(bit_length=shared_config.SESSION_KEY_SIZE_BITS)
    session_id = os.urandom(shared_config.SESSION_ID_SIZE_BYTES)
    to_bob = shared_config.DIRECTION_INITIATOR_TO_RESPONDER
    to_alice = shared_config.DIRECTION_RESPONDER_TO_INITIATOR
    alice_material = SessionMaterial(session_key, session_id, "Bob", None, None, to_bob, to_alice)
    bob_material = SessionMaterial(session_key, session_id, "Alice", None, None, to_alice, to_bob)
    settings = SecureChannelSettings.from_shared_config(shared_config, build_layout())
    return SecureChannel(alice_material, settings), SecureChannel(bob_material, settings)


def build_tamperer():
    return RecordTamperer(
        MessageCodec.TYPE_FIELD_SIZE,
        shared_config.NONCE_DIRECTION_SIZE_BYTES,
        NONCE_SIZE,
        TAG_SIZE,
        int(MessageType.CHAT),
        int(MessageType.BYE),
    )


def raw_encrypt():
    """Encrypt SAMPLE_PLAINTEXT directly with AESGCM. Returns (aesgcm, nonce, ct_with_tag)."""
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext_with_tag = aesgcm.encrypt(nonce, SAMPLE_PLAINTEXT, SAMPLE_AAD)
    return aesgcm, nonce, ciphertext_with_tag


def flip(data, position):
    altered = bytearray(data)
    altered[position] = altered[position] ^ 0x01
    return bytes(altered)


def receive_like_chat_session(codec, bob_channel, frame_payload):
    """Decode a frame payload and open it with the type it claims to be."""
    received_message = codec.decode(frame_payload)
    return bob_channel.open(received_message.message_type, received_message.body)


# -----------------------------------------------------------------------------
# 1. Raw AES-GCM: one altered byte -> InvalidTag (ciphertext, tag, nonce, AAD)
# -----------------------------------------------------------------------------
def test_raw_gcm_untouched_record_decrypts():
    aesgcm, nonce, ciphertext_with_tag = raw_encrypt()
    assert aesgcm.decrypt(nonce, ciphertext_with_tag, SAMPLE_AAD) == SAMPLE_PLAINTEXT


def test_raw_gcm_altered_ciphertext_raises_invalid_tag():
    aesgcm, nonce, ciphertext_with_tag = raw_encrypt()
    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, flip(ciphertext_with_tag, 0), SAMPLE_AAD)


def test_raw_gcm_altered_tag_raises_invalid_tag():
    aesgcm, nonce, ciphertext_with_tag = raw_encrypt()
    last_position = len(ciphertext_with_tag) - 1
    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, flip(ciphertext_with_tag, last_position), SAMPLE_AAD)


def test_raw_gcm_altered_nonce_raises_invalid_tag():
    aesgcm, nonce, ciphertext_with_tag = raw_encrypt()
    with pytest.raises(InvalidTag):
        aesgcm.decrypt(flip(nonce, 5), ciphertext_with_tag, SAMPLE_AAD)


def test_raw_gcm_altered_aad_raises_invalid_tag():
    aesgcm, nonce, ciphertext_with_tag = raw_encrypt()
    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, ciphertext_with_tag, flip(SAMPLE_AAD, 0))


def test_raw_gcm_every_single_byte_alteration_raises_invalid_tag():
    aesgcm, nonce, ciphertext_with_tag = raw_encrypt()
    position = 0
    while position < len(ciphertext_with_tag):
        with pytest.raises(InvalidTag):
            aesgcm.decrypt(nonce, flip(ciphertext_with_tag, position), SAMPLE_AAD)
        position = position + 1


# -----------------------------------------------------------------------------
# 2. RecordTamperer (/alterar) and the real receiver path
# -----------------------------------------------------------------------------
def test_tamperer_changes_exactly_one_byte_and_never_the_size():
    alice_channel, bob_channel = build_channel_pair()
    codec = MessageCodec(TEXT_ENCODING)
    tamperer = build_tamperer()
    sealed_record = alice_channel.seal(MessageType.CHAT, SAMPLE_PLAINTEXT)
    payload = codec.encode(Message(MessageType.CHAT, sealed_record.body))

    for target in tamperer.get_targets():
        result = tamperer.tamper(payload, target)
        assert len(result.payload) == len(payload)

        differences = 0
        position = 0
        while position < len(payload):
            if result.payload[position] != payload[position]:
                differences = differences + 1
            position = position + 1
        assert differences == 1
        assert result.original_value != result.altered_value


def test_tamperer_targets_the_expected_field():
    alice_channel, bob_channel = build_channel_pair()
    codec = MessageCodec(TEXT_ENCODING)
    tamperer = build_tamperer()
    sealed_record = alice_channel.seal(MessageType.CHAT, SAMPLE_PLAINTEXT)
    payload = codec.encode(Message(MessageType.CHAT, sealed_record.body))

    type_size = MessageCodec.TYPE_FIELD_SIZE
    ciphertext_start = type_size + NONCE_SIZE
    tag_start = len(payload) - TAG_SIZE

    ciphertext_result = tamperer.tamper(payload, RecordTamperer.TARGET_CIPHERTEXT)
    assert ciphertext_start <= ciphertext_result.position < tag_start

    tag_result = tamperer.tamper(payload, RecordTamperer.TARGET_TAG)
    assert tag_result.position >= tag_start

    nonce_result = tamperer.tamper(payload, RecordTamperer.TARGET_NONCE)
    assert type_size < nonce_result.position < ciphertext_start

    type_result = tamperer.tamper(payload, RecordTamperer.TARGET_TYPE)
    assert type_result.position == 0
    assert type_result.altered_value == int(MessageType.BYE)


@pytest.mark.parametrize("target", ["ct", "tag", "nonce", "tipo"])
def test_every_tamper_target_is_rejected_with_authentication_error(target):
    alice_channel, bob_channel = build_channel_pair()
    codec = MessageCodec(TEXT_ENCODING)
    sealed_record = alice_channel.seal(MessageType.CHAT, SAMPLE_PLAINTEXT)
    payload = codec.encode(Message(MessageType.CHAT, sealed_record.body))

    altered_payload = build_tamperer().tamper(payload, target).payload

    # The real reason is InvalidTag; SecureChannel reports it as
    # MessageAuthenticationError and returns NO plaintext.
    with pytest.raises(MessageAuthenticationError):
        receive_like_chat_session(codec, bob_channel, altered_payload)


def test_invalid_tag_is_the_underlying_cause():
    alice_channel, bob_channel = build_channel_pair()
    sealed_record = alice_channel.seal(MessageType.CHAT, SAMPLE_PLAINTEXT)
    altered_body = flip(sealed_record.body, len(sealed_record.body) - 1)

    with pytest.raises(MessageAuthenticationError) as error_info:
        bob_channel.open(MessageType.CHAT, altered_body)
    assert isinstance(error_info.value.__context__, InvalidTag)


def test_next_authentic_message_is_accepted_after_a_rejection():
    alice_channel, bob_channel = build_channel_pair()
    codec = MessageCodec(TEXT_ENCODING)
    tamperer = build_tamperer()

    first_record = alice_channel.seal(MessageType.CHAT, b"mensaje alterado")
    first_payload = codec.encode(Message(MessageType.CHAT, first_record.body))
    with pytest.raises(MessageAuthenticationError):
        receive_like_chat_session(codec, bob_channel, tamperer.tamper(first_payload, "nonce").payload)

    second_record = alice_channel.seal(MessageType.CHAT, b"mensaje legitimo")
    second_payload = codec.encode(Message(MessageType.CHAT, second_record.body))
    opened_record = receive_like_chat_session(codec, bob_channel, second_payload)
    assert opened_record.plaintext == b"mensaje legitimo"


# -----------------------------------------------------------------------------
# 3. Replay of a captured valid frame
# -----------------------------------------------------------------------------
def test_captured_valid_frame_sent_again_is_rejected_by_sequence_number():
    alice_channel, bob_channel = build_channel_pair()
    codec = MessageCodec(TEXT_ENCODING)
    sealed_record = alice_channel.seal(MessageType.CHAT, SAMPLE_PLAINTEXT)
    captured_payload = codec.encode(Message(MessageType.CHAT, sealed_record.body))

    first_copy = receive_like_chat_session(codec, bob_channel, captured_payload)
    assert first_copy.plaintext == SAMPLE_PLAINTEXT

    with pytest.raises(ReplayError):
        receive_like_chat_session(codec, bob_channel, captured_payload)


def test_replayed_frame_is_rejected_even_after_newer_messages():
    alice_channel, bob_channel = build_channel_pair()
    codec = MessageCodec(TEXT_ENCODING)
    old_record = alice_channel.seal(MessageType.CHAT, b"viejo")
    old_payload = codec.encode(Message(MessageType.CHAT, old_record.body))
    receive_like_chat_session(codec, bob_channel, old_payload)

    newer_record = alice_channel.seal(MessageType.CHAT, b"nuevo")
    receive_like_chat_session(codec, bob_channel, codec.encode(Message(MessageType.CHAT, newer_record.body)))

    with pytest.raises(ReplayError):
        receive_like_chat_session(codec, bob_channel, old_payload)


# -----------------------------------------------------------------------------
# 4. Rejection policy
# -----------------------------------------------------------------------------
def test_policy_closes_only_after_max_consecutive_rejections():
    policy = RejectionPolicy(3)
    assert policy.record_rejection() is False
    assert policy.record_rejection() is False
    assert policy.record_rejection() is True


def test_policy_resets_after_an_authentic_message():
    policy = RejectionPolicy(3)
    policy.record_rejection()
    policy.record_rejection()
    policy.record_acceptance()
    assert policy.get_consecutive() == 0
    assert policy.record_rejection() is False


def test_configured_policy_tolerates_a_single_rejection():
    assert shared_config.MAX_CONSECUTIVE_REJECTIONS > 1