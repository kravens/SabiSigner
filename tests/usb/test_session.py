"""
End-to-end over a socketpair: handshake, pairing, encrypted requests.

No USB gadget and no gateway process. The socketpair stands in for the link the gateway
would carry, which is exactly the gateway's job -- it is a byte pipe and nothing else, so
replacing it here changes nothing the session can observe.
"""
import base64
import json
import os
import socket

import pytest
from embit import ec

from seedsigner.usb import crypto, gateway
from seedsigner.usb.session import SessionState, UsbSessionRunner

from usb.coinjoin_util import make_seed, standard_round


class FakeHost:
    """The other end of the cable."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.priv = ec.PrivateKey(os.urandom(32))
        self.channel: crypto.SessionChannel | None = None

    def send_hello(self):
        gateway.send_message(self.sock, json.dumps({
            "t": "hello",
            "pk": base64.b64encode(self.priv.get_public_key().sec()).decode(),
        }).encode())

    def read_hello(self):
        message = gateway.recv_message(self.sock)
        body = json.loads(message)
        assert body["t"] == "hello"
        self.channel = crypto.handshake_initiator(base64.b64decode(body["pk"]), self.priv)
        return self.channel.sas

    def request(self, body: dict):
        gateway.send_message(self.sock, self.channel.seal(json.dumps(body).encode()))

    def response(self) -> dict:
        return json.loads(self.channel.open(gateway.recv_message(self.sock)))


@pytest.fixture
def linked():
    host_sock, device_sock = socket.socketpair()
    runner = UsbSessionRunner(
        seed=make_seed(),
        confirm=lambda kind, details: True,
        on_pairing=lambda sas: True,
    )
    runner.attach(device_sock)
    host = FakeHost(host_sock)
    yield runner, host
    runner.stop()
    host_sock.close()


def pair(runner, host):
    host.send_hello()
    assert runner.pump(timeout=1.0)
    device_sas = host.read_hello()
    assert runner.state == SessionState.AWAITING_PAIRING
    assert runner.channel.sas == device_sas
    assert runner.complete_pairing()
    assert runner.state == SessionState.READY
    return device_sas


def test_a_full_session_pairs_and_answers(linked):
    runner, host = linked
    pair(runner, host)

    host.request({"t": "get_version"})
    assert runner.pump(timeout=1.0)
    assert host.response()["model"] == "SabiSigner"


def test_pairing_digits_are_six_matching_decimal_digits(linked):
    runner, host = linked
    sas = pair(runner, host)
    assert len(sas) == 6 and sas.isdigit()


def test_nothing_is_answered_before_the_user_confirms_pairing(linked):
    """
    The device must not start serving a host the user has not vouched for. Requests that
    arrive during pairing are dropped, not queued.
    """
    runner, host = linked
    host.send_hello()
    runner.pump(timeout=1.0)
    host.read_hello()
    assert runner.state == SessionState.AWAITING_PAIRING

    host.request({"t": "get_version"})
    assert runner.pump(timeout=1.0)
    host.sock.settimeout(0.2)
    with pytest.raises(socket.timeout):
        gateway.recv_message(host.sock)


def test_declining_pairing_ends_the_session(linked):
    runner, host = linked
    runner.on_pairing = lambda sas: False
    host.send_hello()
    runner.pump(timeout=1.0)
    host.read_hello()

    assert not runner.complete_pairing()
    assert runner.state == SessionState.ENDED
    assert "pairing rejected" in runner.last_error


def test_a_forged_record_ends_the_session(linked):
    """Someone on the wire is not a protocol hiccup to recover from."""
    runner, host = linked
    pair(runner, host)

    gateway.send_message(host.sock, b"\x00" * 40)
    assert runner.pump(timeout=1.0)
    assert runner.state == SessionState.ENDED
    assert "secure channel failed" in runner.last_error


def test_a_replayed_record_ends_the_session(linked):
    runner, host = linked
    pair(runner, host)

    host.request({"t": "get_version"})
    runner.pump(timeout=1.0)
    host.response()

    replay = host.channel.seal(json.dumps({"t": "get_version"}).encode())
    # Rewind so the same nonce goes out twice.
    host.channel._send.counter -= 1
    gateway.send_message(host.sock, replay)
    runner.pump(timeout=1.0)
    gateway.send_message(host.sock, replay)
    runner.pump(timeout=1.0)
    assert runner.state == SessionState.ENDED


def test_a_junk_handshake_ends_the_session(linked):
    runner, host = linked
    gateway.send_message(host.sock, b"not a hello")
    assert runner.pump(timeout=1.0)
    assert runner.state == SessionState.ENDED


def test_the_host_disconnecting_ends_the_session(linked):
    runner, host = linked
    pair(runner, host)
    host.sock.close()
    assert runner.pump(timeout=1.0)
    assert runner.state == SessionState.ENDED


def test_a_coinjoin_session_signs_rounds_unattended(linked):
    """The feature the whole design exists for, driven the way Wasabi would drive it."""
    runner, host = linked
    pair(runner, host)

    host.request({
        "t": "authorize_coinjoin",
        "coordinator": "wasabi.test",
        "account_path": "m/84'/0'/0'",
        "max_rounds": 3,
        "max_fee_per_round_sat": 5_000,
        "max_total_fee_sat": 20_000,
    })
    runner.pump(timeout=1.0)
    assert host.response()["authorized"] is True

    # From here the user is not touching the device: refuse everything they might be asked.
    runner.confirm = lambda kind, details: False

    for expected_remaining in (2, 1, 0):
        host.request({"t": "sign_coinjoin", "psbt": standard_round(runner.session.seed).to_base64()})
        runner.pump(timeout=1.0)
        response = host.response()
        assert response["t"] == "ok"
        assert response["rounds_remaining"] == expected_remaining

    host.request({"t": "sign_coinjoin", "psbt": standard_round(runner.session.seed).to_base64()})
    runner.pump(timeout=1.0)
    assert host.response()["t"] == "error"


def test_stopping_the_session_drops_the_authorization(linked):
    runner, host = linked
    pair(runner, host)
    host.request({
        "t": "authorize_coinjoin",
        "coordinator": "wasabi.test",
        "account_path": "m/84'/0'/0'",
        "max_rounds": 3,
        "max_fee_per_round_sat": 5_000,
        "max_total_fee_sat": 20_000,
    })
    runner.pump(timeout=1.0)
    host.response()
    assert runner.authorization is not None

    runner.stop()
    assert runner.authorization is None
