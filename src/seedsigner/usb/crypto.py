"""
The SabiSigner USB session channel.

What this defends against, and what it does not, stated plainly because the difference
decides how much the code below is worth:

  Defended: a passive tap or an active interposer on the cable. A USB analyzer between
  the device and the host sees only ciphertext, and cannot substitute its own handshake
  without changing the short authentication string the user reads off the device screen.

  Not defended: the host itself. Wasabi is a legitimate endpoint of this channel and
  sees every plaintext it is sent. Encryption is not what stops a compromised host from
  misusing the device -- on-device confirmation and policy.py do that. Nothing here
  should be read as protecting the user from their own PC.

Primitive choice is deliberately boring. SeedSigner OS ships CPython with hashlib/hmac
(OpenSSL-backed) and libsecp256k1 behind embit, and ships no AEAD library. Rather than
vendor a ChaCha20-Poly1305 into a signing device and hand-review it, the channel is
built only from those two: ECDH on secp256k1 for the key agreement, HKDF-SHA256 for
derivation, and an HMAC-SHA256 counter-mode keystream with an HMAC-SHA256 tag for the
record layer. That is slower than a real AEAD and nobody should pretend otherwise -- but
the records here are a few kilobytes at most, and every construction is one an ordinary
reviewer can check against a published spec.

Encrypt-then-MAC, separate keys per direction, nonce is a strictly increasing counter
that must arrive in order.
"""
import hashlib
import hmac
import os
import struct

from embit import ec


PROTOCOL_LABEL = b"SabiSigner-usb-v1"
KEY_SIZE = 32
NONCE_SIZE = 8
TAG_SIZE = 16
MIN_FRAME_SIZE = NONCE_SIZE + TAG_SIZE

# 2**64 nonces is not a limit anyone reaches, but the counter is checked rather than
# assumed: an overflowing counter would repeat a keystream, which is the one failure
# this construction cannot survive.
MAX_COUNTER = (1 << 64) - 1


class ChannelError(Exception):
    """Authentication failed, the counter went backwards, or a frame was malformed."""
    pass


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256, RFC 5869. Extract-then-expand."""
    if length > 255 * hashlib.sha256().digest_size:
        raise ValueError("hkdf: requested length too long")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """
    Counter-mode keystream from HMAC-SHA256.

    Block i is HMAC(key, nonce || uint32_be(i)). The nonce is unique per record and the
    key is unique per direction per session, so no block input ever repeats.
    """
    out = bytearray()
    block_index = 0
    while len(out) < length:
        out += hmac.new(key, nonce + struct.pack(">I", block_index), hashlib.sha256).digest()
        block_index += 1
    return bytes(out[:length])


class DirectionKeys:
    """One direction's encryption key, MAC key, and record counter."""

    def __init__(self, enc_key: bytes, mac_key: bytes):
        self.enc_key = enc_key
        self.mac_key = mac_key
        self.counter = 0

    def next_nonce(self) -> bytes:
        if self.counter > MAX_COUNTER:
            raise ChannelError("record counter exhausted")
        nonce = struct.pack(">Q", self.counter)
        self.counter += 1
        return nonce


class SessionChannel:
    """
    An established channel. Construct via `handshake_responder`; the device is always the
    responder because the host initiates when it wants to talk.
    """

    def __init__(self, send: DirectionKeys, recv: DirectionKeys, sas: str):
        self._send = send
        self._recv = recv
        self.sas = sas

    def seal(self, plaintext: bytes) -> bytes:
        nonce = self._send.next_nonce()
        ciphertext = bytes(
            a ^ b for a, b in zip(plaintext, _keystream(self._send.enc_key, nonce, len(plaintext)))
        )
        tag = hmac.new(self._send.mac_key, nonce + ciphertext, hashlib.sha256).digest()[:TAG_SIZE]
        return nonce + ciphertext + tag

    def open(self, frame: bytes) -> bytes:
        if len(frame) < MIN_FRAME_SIZE:
            raise ChannelError("frame shorter than nonce+tag")

        nonce = frame[:NONCE_SIZE]
        ciphertext = frame[NONCE_SIZE:-TAG_SIZE]
        tag = frame[-TAG_SIZE:]

        # Authenticate before anything else looks at the ciphertext, and before the
        # counter is checked: an attacker should not be able to probe the expected
        # counter with unauthenticated frames.
        expected_tag = hmac.new(
            self._recv.mac_key, nonce + ciphertext, hashlib.sha256
        ).digest()[:TAG_SIZE]
        if not hmac.compare_digest(tag, expected_tag):
            raise ChannelError("frame authentication failed")

        # In-order delivery only. USB interrupt transfers on a single endpoint do not
        # reorder, so a gap or a repeat is either corruption or a replay; both end the
        # session rather than being tolerated.
        expected_nonce = struct.pack(">Q", self._recv.counter)
        if not hmac.compare_digest(nonce, expected_nonce):
            raise ChannelError("unexpected record counter (replay or reorder)")
        self._recv.counter += 1

        return bytes(
            a ^ b for a, b in zip(ciphertext, _keystream(self._recv.enc_key, nonce, len(ciphertext)))
        )


def _derive(shared: bytes, host_pub: bytes, device_pub: bytes) -> tuple[DirectionKeys, DirectionKeys, str]:
    """
    Bind the derived keys to both public keys.

    The transcript is what makes the short authentication string worth showing: an
    interposer that runs one handshake with the host and another with the device ends up
    with two different transcripts, so the digits on the device screen cannot match the
    digits the host displays.
    """
    transcript = PROTOCOL_LABEL + host_pub + device_pub
    okm = hkdf(ikm=shared, salt=transcript, info=b"channel", length=4 * KEY_SIZE + 4)

    h2d = DirectionKeys(enc_key=okm[0:32], mac_key=okm[32:64])
    d2h = DirectionKeys(enc_key=okm[64:96], mac_key=okm[96:128])

    # Six digits: short enough to read off a 240x240 screen and compare without
    # frustration, long enough that an interposer has a 1-in-a-million shot at matching
    # it, and it only gets the one shot because a wrong guess ends the session.
    sas = f"{struct.unpack('>I', okm[128:132])[0] % 1_000_000:06d}"
    return h2d, d2h, sas


def handshake_responder(host_pub_sec: bytes) -> tuple[SessionChannel, bytes]:
    """
    Complete the device side of the handshake.

    Takes the host's ephemeral public key (33-byte compressed sec) and returns the
    established channel plus the device's own ephemeral public key to send back.

    The caller must show `channel.sas` to the user and get a confirmation before acting
    on anything that arrives. Nothing here enforces that, because this module has no
    screen -- see views.usb_views.
    """
    if len(host_pub_sec) != 33 or host_pub_sec[0] not in (0x02, 0x03):
        raise ChannelError("host public key is not a compressed secp256k1 point")

    try:
        host_pub = ec.PublicKey.parse(host_pub_sec)
    except Exception as e:
        raise ChannelError(f"host public key is not on the curve: {e}")

    device_priv = ec.PrivateKey(os.urandom(32))
    device_pub_sec = device_priv.get_public_key().sec()

    # embit's ecdh hashes the shared point with sha256 rather than handing back a raw
    # x-coordinate, so the output is already a uniform 32 bytes.
    shared = device_priv.ecdh(host_pub)

    h2d, d2h, sas = _derive(shared, host_pub_sec, device_pub_sec)
    # From the device's point of view host-to-device is the receive direction.
    return SessionChannel(send=d2h, recv=h2d, sas=sas), device_pub_sec


def handshake_initiator(device_pub_sec: bytes, host_priv: "ec.PrivateKey") -> SessionChannel:
    """
    The host side, provided so the test suite (and a reference host implementation) can
    drive a real handshake against the responder rather than a mock of one.
    """
    device_pub = ec.PublicKey.parse(device_pub_sec)
    shared = host_priv.ecdh(device_pub)
    h2d, d2h, sas = _derive(shared, host_priv.get_public_key().sec(), device_pub_sec)
    return SessionChannel(send=h2d, recv=d2h, sas=sas)
