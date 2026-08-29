"""
Message framing over USB HID interrupt transfers.

The gadget exposes one HID interface with a 64-byte input report and a 64-byte output
report (see the report descriptor in usb_gadget.sh). HID gives us fixed-size packets and
nothing else: no stream, no length, no message boundaries. This module adds those.

Wire format, every report exactly REPORT_SIZE bytes:

    byte 0     0x01 = first report of a message, 0x00 = continuation
    first report:      bytes 1..4  uint32 big-endian total message length
                       bytes 5..63 first 59 payload bytes
    continuation:      bytes 1..63 next 63 payload bytes

Short reports are rejected rather than zero-padded, and trailing bytes past the declared
length are ignored (the last report is padded to 64 by the sender). A message longer than
MAX_MESSAGE_SIZE is refused at the header, before anything is buffered, so a peer cannot
make the device allocate by lying about a length.

The decoder is a state machine with exactly two states because it is the first thing an
attacker reaches. Any protocol error resets it to idle and raises; the caller is expected
to tear the session down rather than try to resynchronize, since a desynchronized framer
and a hostile one look identical from here.
"""
import struct


REPORT_SIZE = 64
TAG_START = 0x01
TAG_CONT = 0x00
HEADER_SIZE_START = 5   # tag + uint32 length
HEADER_SIZE_CONT = 1    # tag
FIRST_CHUNK = REPORT_SIZE - HEADER_SIZE_START   # 59
CONT_CHUNK = REPORT_SIZE - HEADER_SIZE_CONT     # 63

# A coinjoin psbt with a few hundred inputs is tens of kilobytes; 128 KiB leaves room
# without letting a peer size an allocation on the device. Kept well under the Pi Zero's
# memory budget so that even a full-length message cannot pressure the app.
MAX_MESSAGE_SIZE = 128 * 1024


class FramingError(Exception):
    """The peer sent something that is not a valid report stream. Always fatal to the session."""
    pass


def encode(message: bytes) -> list[bytes]:
    """Split a message into REPORT_SIZE reports, zero-padding the last one."""
    if len(message) > MAX_MESSAGE_SIZE:
        raise FramingError(f"message of {len(message)} bytes exceeds {MAX_MESSAGE_SIZE}")

    reports = []
    head = message[:FIRST_CHUNK]
    reports.append(
        bytes([TAG_START]) + struct.pack(">I", len(message)) + head.ljust(FIRST_CHUNK, b"\x00")
    )
    rest = message[FIRST_CHUNK:]
    while rest:
        chunk, rest = rest[:CONT_CHUNK], rest[CONT_CHUNK:]
        reports.append(bytes([TAG_CONT]) + chunk.ljust(CONT_CHUNK, b"\x00"))
    return reports


class Decoder:
    """
    Feed reports in, get whole messages out.

    push() returns the completed message, or None while one is still being assembled.
    """

    def __init__(self, max_message_size: int = MAX_MESSAGE_SIZE):
        self.max_message_size = max_message_size
        self._reset()

    def _reset(self):
        self._buf = bytearray()
        self._expected = None

    def push(self, report: bytes) -> bytes | None:
        if len(report) != REPORT_SIZE:
            self._reset()
            raise FramingError(f"report is {len(report)} bytes, expected {REPORT_SIZE}")

        tag = report[0]
        if tag == TAG_START:
            # A start report always begins a new message. If one was in flight it is
            # abandoned: resynchronizing on a peer that restarted mid-message is the
            # only sane reading, and the alternative (erroring) would let a truncated
            # message wedge the session.
            self._reset()
            (length,) = struct.unpack(">I", report[1:5])
            if length > self.max_message_size:
                raise FramingError(f"declared length {length} exceeds {self.max_message_size}")
            self._expected = length
            self._buf.extend(report[HEADER_SIZE_START:])
        elif tag == TAG_CONT:
            if self._expected is None:
                raise FramingError("continuation report with no message in progress")
            self._buf.extend(report[HEADER_SIZE_CONT:])
        else:
            self._reset()
            raise FramingError(f"unknown report tag 0x{tag:02x}")

        if len(self._buf) >= self._expected:
            message = bytes(self._buf[: self._expected])
            self._reset()
            return message
        return None
