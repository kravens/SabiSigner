"""
Drives one USB session: gateway process, handshake, pairing, request loop.

Runs in the caller's thread. The view layer calls pump() in a loop between screen
updates, so confirmations render from the same thread that owns the display and there is
no lock to negotiate with the renderer. That is the whole reason this is not a
BaseThread: SeedSigner's UI is single-threaded, and the alternative was a background
thread asking a foreground one for permission to draw.

Session lifetime is the screen's lifetime. Leaving the USB screen unbinds the gadget, so
the device stops being a USB device at all until the user asks again. Nothing survives:
no keys, no authorization, no record counters.
"""
import base64
import json
import logging
import select
import socket
import subprocess

from seedsigner.models.settings import SettingsConstants
from seedsigner.usb import crypto, gateway
from seedsigner.usb.protocol import UsbSession


logger = logging.getLogger(__name__)


class SessionState:
    AWAITING_HELLO = "awaiting_hello"
    AWAITING_PAIRING = "awaiting_pairing"
    READY = "ready"
    ENDED = "ended"


class UsbSessionRunner:
    """
    One session. Construct, start(), pump() until done, then stop().

    `confirm(kind, details) -> bool` is supplied by the view and renders the on-device
    prompt for anything that reveals wallet data or signs. `on_pairing(sas) -> bool`
    renders the six pairing digits and returns whether the user says they match what the
    host is showing.
    """

    def __init__(self, seed=None, network: str = SettingsConstants.MAINNET,
                 confirm=None, on_pairing=None):
        self.session = UsbSession(seed=seed, network=network)
        self.confirm = confirm or (lambda kind, details: False)
        self.on_pairing = on_pairing or (lambda sas: False)

        self.state = SessionState.AWAITING_HELLO
        self.channel: crypto.SessionChannel | None = None
        self.last_error: str | None = None

        self._sock: socket.socket | None = None
        self._gateway = None
        self._bound = False

    @property
    def authorization(self):
        return self.session.authorization

    GADGET_CONTROL = "/usr/bin/sabi-usb-gadget"

    def start(self, hidg_device: str = gateway.HIDG_DEVICE) -> None:
        """
        Bind the gadget, then hand its endpoint to a gateway process.

        Binding is what makes the device appear on the host's bus at all. Until this runs
        the port is electrically live but enumerates nothing, so a SabiSigner left plugged
        into a laptop is not a USB device -- it becomes one only while the user is looking
        at the USB screen.
        """
        self._bind_gadget()
        try:
            self._sock, self._gateway = gateway.spawn(hidg_device)
        except OSError:
            # The endpoint did not open. Take the gadget back off the bus rather than
            # leaving the device enumerated with nothing listening.
            self._unbind_gadget()
            raise

    def _bind_gadget(self) -> None:
        subprocess.run([self.GADGET_CONTROL, "bind"], check=True)
        self._bound = True

    def _unbind_gadget(self) -> None:
        if not self._bound:
            return
        self._bound = False
        try:
            subprocess.run([self.GADGET_CONTROL, "unbind"], check=False)
        except OSError as e:
            logger.warning("could not unbind the USB gadget: %s", e)

    def attach(self, sock: socket.socket) -> None:
        """
        Use an already-connected socket instead of spawning a gateway.

        Exists so the test suite can drive a whole session over a socketpair without a
        USB gadget, and so a developer can point the session at a host emulator.
        """
        self._sock = sock
        self._gateway = None

    def stop(self) -> None:
        if self._sock is not None and self._gateway is not None:
            gateway.stop(self._sock, self._gateway)
        elif self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._gateway = None
        self._unbind_gadget()
        self.channel = None
        self.state = SessionState.ENDED
        # The seed reference goes with the session object; the storage still owns the
        # actual seed, which the user clears by powering the device off.
        self.session.authorization = None

    def pump(self, timeout: float = 0.2) -> bool:
        """
        Handle at most one message. Returns True if something was processed.

        Errors do not raise out of here. A session that dies on a malformed frame would
        hand a hostile host a way to close the user's screen; instead the state goes to
        ENDED and the view shows why.
        """
        if self.state == SessionState.ENDED or self._sock is None:
            return False

        readable, _, _ = select.select([self._sock], [], [], timeout)
        if not readable:
            return False

        try:
            message = gateway.recv_message(self._sock)
        except (OSError, ValueError) as e:
            self._end(f"link error: {e}")
            return True

        if message is None:
            self._end("host disconnected")
            return True

        try:
            response = self._process(message)
        except crypto.ChannelError as e:
            # A bad tag or a replayed counter is not a protocol hiccup, it is someone on
            # the wire. End the session rather than letting them retry.
            self._end(f"secure channel failed: {e}")
            return True
        except Exception as e:
            logger.exception("usb session: unhandled error")
            self._end(f"internal error: {e}")
            return True

        if response is not None:
            try:
                gateway.send_message(self._sock, response)
            except OSError as e:
                self._end(f"link error: {e}")
        return True

    def _end(self, reason: str) -> None:
        logger.info("usb session ending: %s", reason)
        self.last_error = reason
        self.stop()

    def _process(self, message: bytes) -> bytes | None:
        if self.state == SessionState.AWAITING_HELLO:
            return self._handle_hello(message)

        if self.state == SessionState.AWAITING_PAIRING:
            # Nothing is answered until the user has compared the digits. Dropping the
            # message rather than queueing it keeps an impatient host from filling memory
            # while the device waits on a human.
            return None

        plaintext = self.channel.open(message)
        reply = self.session.handle_message(plaintext, self.confirm)
        return self.channel.seal(reply)

    def _handle_hello(self, message: bytes) -> bytes | None:
        try:
            request = json.loads(message.decode("utf-8"))
            if request.get("t") != "hello":
                raise ValueError("expected a hello")
            host_pub = base64.b64decode(request["pk"], validate=True)
        except Exception as e:
            self._end(f"bad handshake: {e}")
            return None

        self.channel, device_pub = crypto.handshake_responder(host_pub)
        self.state = SessionState.AWAITING_PAIRING

        # Reply before asking the user, so the host can show its digits while the device
        # shows the same ones.
        return json.dumps({
            "t": "hello",
            "pk": base64.b64encode(device_pub).decode("ascii"),
        }).encode("utf-8")

    def complete_pairing(self) -> bool:
        """
        Show the pairing digits and record the answer. Called by the view once the state
        reaches AWAITING_PAIRING.
        """
        if self.state != SessionState.AWAITING_PAIRING:
            return False
        if self.on_pairing(self.channel.sas):
            self.state = SessionState.READY
            return True
        self._end("pairing rejected on the device")
        return False
