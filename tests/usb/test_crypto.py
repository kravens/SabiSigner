import os

import pytest
from embit import ec

from seedsigner.usb import crypto
from seedsigner.usb.crypto import ChannelError


# RFC 5869 test case 1. HKDF is the one primitive here that is assembled rather than
# called, so it is checked against the spec's own vectors instead of against itself.
RFC5869_IKM = bytes.fromhex("0b" * 22)
RFC5869_SALT = bytes.fromhex("000102030405060708090a0b0c")
RFC5869_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
RFC5869_OKM = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)


def test_hkdf_matches_rfc5869_case_1():
    assert crypto.hkdf(RFC5869_IKM, RFC5869_SALT, RFC5869_INFO, 42) == RFC5869_OKM


def test_hkdf_is_a_prefix_at_shorter_lengths():
    assert crypto.hkdf(RFC5869_IKM, RFC5869_SALT, RFC5869_INFO, 16) == RFC5869_OKM[:16]


def paired_channels():
    host_priv = ec.PrivateKey(os.urandom(32))
    host_pub = host_priv.get_public_key().sec()
    device, device_pub = crypto.handshake_responder(host_pub)
    host = crypto.handshake_initiator(device_pub, host_priv)
    return host, device


def test_handshake_agrees_on_keys_and_sas():
    host, device = paired_channels()
    assert host.sas == device.sas
    assert len(host.sas) == 6 and host.sas.isdigit()


def test_records_round_trip_in_both_directions():
    host, device = paired_channels()
    assert device.open(host.seal(b"ping")) == b"ping"
    assert host.open(device.seal(b"pong")) == b"pong"


def test_multiple_records_keep_their_order():
    host, device = paired_channels()
    frames = [host.seal(f"message {i}".encode()) for i in range(10)]
    for i, frame in enumerate(frames):
        assert device.open(frame) == f"message {i}".encode()


def test_empty_payload_round_trips():
    host, device = paired_channels()
    assert device.open(host.seal(b"")) == b""


def test_tampering_with_the_ciphertext_is_caught():
    host, device = paired_channels()
    frame = bytearray(host.seal(b"pay me"))
    frame[10] ^= 0x01
    with pytest.raises(ChannelError, match="authentication failed"):
        device.open(bytes(frame))


def test_tampering_with_the_tag_is_caught():
    host, device = paired_channels()
    frame = bytearray(host.seal(b"pay me"))
    frame[-1] ^= 0x01
    with pytest.raises(ChannelError, match="authentication failed"):
        device.open(bytes(frame))


def test_replaying_a_record_is_rejected():
    host, device = paired_channels()
    frame = host.seal(b"round one")
    assert device.open(frame) == b"round one"
    with pytest.raises(ChannelError, match="record counter"):
        device.open(frame)


def test_reordering_records_is_rejected():
    host, device = paired_channels()
    first = host.seal(b"first")
    second = host.seal(b"second")
    with pytest.raises(ChannelError, match="record counter"):
        device.open(second)
    # The rejected frame must not have advanced the counter.
    assert device.open(first) == b"first"


def test_a_frame_from_the_wrong_direction_is_rejected():
    """
    Reflecting the device's own record back at it must fail: the directions use
    different keys precisely so that a wire attacker cannot echo traffic.
    """
    host, device = paired_channels()
    device_frame = device.seal(b"from the device")
    with pytest.raises(ChannelError, match="authentication failed"):
        device.open(device_frame)


def test_a_frame_from_a_different_session_is_rejected():
    host_a, device_a = paired_channels()
    host_b, _device_b = paired_channels()
    with pytest.raises(ChannelError, match="authentication failed"):
        device_a.open(host_b.seal(b"cross session"))


def test_truncated_frames_are_rejected():
    host, device = paired_channels()
    with pytest.raises(ChannelError, match="shorter than"):
        device.open(b"\x00" * (crypto.MIN_FRAME_SIZE - 1))


def test_an_interposer_cannot_match_the_pairing_digits():
    """
    The man in the middle runs one handshake with the host and another with the device.
    Both halves work; the two short authentication strings do not match, which is the
    whole point of showing them to the user.
    """
    real_host_priv = ec.PrivateKey(os.urandom(32))
    attacker_priv = ec.PrivateKey(os.urandom(32))

    # Attacker <-> device
    device_channel, device_pub = crypto.handshake_responder(attacker_priv.get_public_key().sec())
    attacker_to_device = crypto.handshake_initiator(device_pub, attacker_priv)
    assert attacker_to_device.sas == device_channel.sas

    # Attacker <-> host, pretending to be the device
    attacker_device_channel, attacker_pub = crypto.handshake_responder(
        real_host_priv.get_public_key().sec()
    )
    host_channel = crypto.handshake_initiator(attacker_pub, real_host_priv)

    assert host_channel.sas != device_channel.sas


def test_non_curve_public_keys_are_refused():
    with pytest.raises(ChannelError):
        crypto.handshake_responder(b"\x02" + b"\xff" * 32)   # x is not on the curve
    with pytest.raises(ChannelError, match="compressed"):
        crypto.handshake_responder(b"\x04" + b"\x00" * 64)   # uncompressed
    with pytest.raises(ChannelError, match="compressed"):
        crypto.handshake_responder(b"\x02" * 10)             # wrong length


def test_keystream_differs_per_record():
    """
    A repeated keystream would let an observer xor two records together. Sealing the same
    plaintext twice must not produce the same ciphertext.
    """
    host, _device = paired_channels()
    first = host.seal(b"same plaintext")
    second = host.seal(b"same plaintext")
    assert first[crypto.NONCE_SIZE:] != second[crypto.NONCE_SIZE:]
