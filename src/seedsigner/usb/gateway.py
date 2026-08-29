"""
The USB gateway process.

This is the half of the USB stack that touches bytes an attacker chose, and it is
deliberately the half that holds nothing worth stealing.

    parent (the SabiSigner app)          child (this gateway)
    ------------------------------       ---------------------------------
    holds the seed                       holds no key material at all
    holds the session keys               holds one HID fd and one socket
    renders the screen                   cannot open a new file: it is nobody
    parses JSON requests                 reassembles HID reports

The split matters because the framing code is the first thing a hostile host reaches, and
a memory-safety-adjacent bug there should land somewhere that has nothing to give up. The
gateway sees only ciphertext: key agreement and record decryption happen in the app, so a
compromised gateway cannot read traffic, cannot forge the pairing digits the user checks,
and cannot ask the app for anything the host could not have asked for anyway.

Confinement is done with what a buildroot image without libseccomp actually has:

  * The HID device is opened by the parent, while it is still root, and inherited. The
    child never needs the privilege to open it, so it can drop everything.
  * The child `exec`s rather than merely forking. This is the load-bearing detail: a plain
    fork would hand the gateway a copy of the parent's entire address space, seed included,
    and the table above would be a lie. After exec the child's memory is a fresh Python
    interpreter that has never seen a seed.
  * setgid/setuid to nobody, groups cleared, before a single byte is read.
  * No filesystem socket: the channel is a socketpair, so there is no path to have
    permissions wrong on and nothing for another process to connect to.

seccomp would be the next thing to add and is not here; see docs/usb_security.md.
"""
import logging
import os
import pwd
import socket
import struct
import subprocess
import sys

from seedsigner.usb.hidframe import Decoder, FramingError, REPORT_SIZE, encode


logger = logging.getLogger(__name__)


HIDG_DEVICE = "/dev/hidg0"
UNPRIVILEGED_USER = "nobody"

# Length prefix on the socket between gateway and app. The app already refuses oversized
# messages at the framing layer; this bound just keeps a confused gateway from asking the
# app to allocate.
MAX_SOCKET_MESSAGE = 128 * 1024


def _drop_privileges(username: str = UNPRIVILEGED_USER) -> None:
    """
    Become `username` irreversibly. Raises rather than continuing as root: a gateway that
    silently stayed privileged would be worse than no gateway.
    """
    if os.getuid() != 0:
        # Already unprivileged (dev machine, test suite). Nothing to drop.
        return

    entry = pwd.getpwnam(username)
    os.setgroups([])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)

    if os.getuid() == 0 or os.geteuid() == 0:
        raise RuntimeError("failed to drop privileges; refusing to run the USB gateway as root")


def send_message(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_exactly(sock: socket.socket, count: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def recv_message(sock: socket.socket) -> bytes | None:
    header = _recv_exactly(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length > MAX_SOCKET_MESSAGE:
        raise ValueError(f"socket message of {length} bytes exceeds {MAX_SOCKET_MESSAGE}")
    return _recv_exactly(sock, length)


def gateway_main(hid_fd: int, sock: socket.socket) -> None:
    """
    The child's whole life: HID reports in, whole messages to the app; messages from the
    app out, HID reports to the host.

    Single-threaded and blocking on purpose. The device talks to exactly one host over
    exactly one endpoint, so there is no concurrency to model, and a select loop here
    would be state to get wrong for no gain.
    """
    decoder = Decoder()

    while True:
        try:
            report = os.read(hid_fd, REPORT_SIZE)
        except OSError as e:
            logger.info("gateway: HID read ended (%s)", e)
            return
        if not report:
            logger.info("gateway: HID endpoint closed")
            return

        try:
            message = decoder.push(report)
        except FramingError as e:
            # Framing errors are fatal to the session by design: a desynchronized peer and
            # a hostile one are indistinguishable from in here, so the gateway stops and
            # lets the app tear the session down.
            logger.warning("gateway: framing error, ending session: %s", e)
            return

        if message is None:
            continue

        try:
            send_message(sock, message)
            response = recv_message(sock)
        except (OSError, ValueError) as e:
            logger.info("gateway: app link ended (%s)", e)
            return

        if response is None:
            logger.info("gateway: app closed the link")
            return

        try:
            for out_report in encode(response):
                os.write(hid_fd, out_report)
        except (OSError, FramingError) as e:
            logger.info("gateway: HID write failed (%s)", e)
            return


def spawn(hidg_device: str = HIDG_DEVICE) -> tuple[socket.socket, subprocess.Popen]:
    """
    Open the HID endpoint as root, then start a fresh interpreter to run the gateway.

    The endpoint and one end of a socketpair are the only things handed across; everything
    else about the parent -- the seed above all -- is left behind by the exec. Returns the
    app's end of the socketpair and the child process. The caller owns tearing it down
    (see stop()).
    """
    parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    # Opened here, while we still can. The child inherits the fd and never needs the
    # privilege that opening it required.
    hid_fd = os.open(hidg_device, os.O_RDWR)

    # `python3 -m` would normally find the package via the current directory, which on the
    # device happens to be right. Naming the directory the running package was imported
    # from removes the dependency on that coincidence: a gateway that fails to start is a
    # USB feature that silently does nothing.
    import seedsigner
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(seedsigner.__file__)))
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [package_root] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )

    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "seedsigner.usb.gateway", str(hid_fd), str(child_sock.fileno())],
            pass_fds=(hid_fd, child_sock.fileno()),
            env=env,
        )
    finally:
        # The parent has no further use for either: the child holds the endpoint, and the
        # app talks to it over parent_sock.
        child_sock.close()
        os.close(hid_fd)

    return parent_sock, process


def stop(sock: socket.socket, process: subprocess.Popen) -> None:
    """Close the link and reap the child. Safe to call twice."""
    try:
        sock.close()
    except OSError:
        pass

    if process.poll() is None:
        process.terminate()
    try:
        # The gateway's only job is a read loop on two closed fds by now, so it exits
        # immediately. The timeout is here so a wedged child cannot hold the UI thread.
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        logger.warning("gateway: child did not exit; killing it")
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.error("gateway: child could not be killed")


def main(argv: list[str]) -> int:
    """
    Entry point for the exec'd child: `python3 -m seedsigner.usb.gateway <hid_fd> <sock_fd>`.

    Both descriptors are already open and were passed across the exec. The first thing this
    does after adopting them is stop being root.
    """
    if len(argv) != 2:
        print("usage: python3 -m seedsigner.usb.gateway <hid_fd> <sock_fd>", file=sys.stderr)
        return 2

    hid_fd = int(argv[0])
    sock = socket.socket(fileno=int(argv[1]))

    _drop_privileges()

    try:
        gateway_main(hid_fd, sock)
    except BaseException:
        logger.exception("gateway: exiting on an unhandled error")
        return 1
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    sys.exit(main(sys.argv[1:]))
