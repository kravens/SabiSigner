"""
Tests for the USB gateway child process.

The point of these is the process boundary itself. The security story says the process
that touches host-chosen bytes is a separate program that never held a seed, so the test
starts a real child over real file descriptors rather than calling gateway_main() in
process, where the boundary would not exist to be checked.
"""
import os
import socket
import struct
import subprocess
import sys

import pytest

from seedsigner.usb import gateway
from seedsigner.usb.hidframe import Decoder, encode


SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "src")


def _start_gateway(hid_child: socket.socket, app_child: socket.socket) -> subprocess.Popen:
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR
    return subprocess.Popen(
        [sys.executable, "-m", "seedsigner.usb.gateway",
         str(hid_child.fileno()), str(app_child.fileno())],
        pass_fds=(hid_child.fileno(), app_child.fileno()),
        env=env,
    )


@pytest.fixture
def gateway_child():
    """A running gateway plus the host side and app side of its two links."""
    hid_host, hid_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    app, app_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    process = _start_gateway(hid_child, app_child)
    hid_child.close()
    app_child.close()

    hid_host.settimeout(10)
    app.settimeout(10)

    yield process, hid_host, app

    hid_host.close()
    gateway.stop(app, process)


def _recv_app_message(app: socket.socket) -> bytes:
    header = app.recv(4)
    assert len(header) == 4
    (length,) = struct.unpack(">I", header)
    payload = b""
    while len(payload) < length:
        payload += app.recv(length - len(payload))
    return payload


def test_the_gateway_is_a_separate_program(gateway_child):
    """
    Not a fork of the app: a fresh interpreter, whose memory has never held a seed.
    """
    process, _, _ = gateway_child
    assert process.pid != os.getpid()

    with open(f"/proc/{process.pid}/cmdline", "rb") as f:
        cmdline = f.read().split(b"\0")
    assert b"seedsigner.usb.gateway" in cmdline


def test_reports_from_the_host_arrive_as_one_message(gateway_child):
    """
    The gateway's actual job: reassemble 64-byte reports and hand the app a whole message.
    """
    _, hid_host, app = gateway_child

    message = b"x" * 200  # spans four reports
    for report in encode(message):
        hid_host.sendall(report)

    assert _recv_app_message(app) == message


def test_the_app_response_goes_back_out_as_reports(gateway_child):
    _, hid_host, app = gateway_child

    for report in encode(b"ping"):
        hid_host.sendall(report)
    assert _recv_app_message(app) == b"ping"

    response = b"pong" * 40  # more than one report's worth
    gateway.send_message(app, response)

    decoder = Decoder()
    received = None
    while received is None:
        report = hid_host.recv(64)
        assert len(report) == 64
        received = decoder.push(report)
    assert received == response


def test_a_framing_error_ends_the_gateway(gateway_child):
    """
    A desynchronized peer and a hostile one look identical from inside the gateway, so it
    stops rather than trying to recover.
    """
    process, hid_host, app = gateway_child

    # A continuation report with no start report before it.
    hid_host.sendall(b"\x00" + b"\x00" * 63)

    # The child exits, which the app sees as end-of-file on its side of the socketpair.
    # That is how the session learns the link is gone.
    process.wait(timeout=10)
    assert app.recv(4) == b""


def test_short_reports_are_rejected(gateway_child):
    """
    The endpoint delivers whole 64-byte reports; anything else means something is wrong on
    the wire, and the gateway must not try to interpret it.
    """
    process, hid_host, app = gateway_child

    hid_host.sendall(b"\x01\x00\x00\x00\x04ab")  # a start report, truncated
    hid_host.close()

    process.wait(timeout=10)
    assert app.recv(4) == b""
