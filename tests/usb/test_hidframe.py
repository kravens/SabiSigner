import pytest

from seedsigner.usb import hidframe
from seedsigner.usb.hidframe import Decoder, FramingError, REPORT_SIZE


def roundtrip(payload: bytes) -> bytes:
    decoder = Decoder()
    result = None
    for report in hidframe.encode(payload):
        assert len(report) == REPORT_SIZE
        result = decoder.push(report)
    return result


@pytest.mark.parametrize("size", [0, 1, 58, 59, 60, 121, 122, 123, 1024, 60_000])
def test_roundtrip_at_and_around_chunk_boundaries(size):
    """59 and 122 are the exact fill points of the first and second report."""
    payload = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    assert roundtrip(payload) == payload


def test_message_is_only_returned_once_complete():
    decoder = Decoder()
    reports = hidframe.encode(b"x" * 200)
    for report in reports[:-1]:
        assert decoder.push(report) is None
    assert decoder.push(reports[-1]) == b"x" * 200


def test_short_report_is_rejected():
    decoder = Decoder()
    with pytest.raises(FramingError, match="expected 64"):
        decoder.push(b"\x01\x00\x00\x00\x05hello")


def test_oversized_declared_length_is_rejected_before_buffering():
    decoder = Decoder()
    huge = (hidframe.MAX_MESSAGE_SIZE + 1).to_bytes(4, "big")
    with pytest.raises(FramingError, match="exceeds"):
        decoder.push(b"\x01" + huge + b"\x00" * 59)


def test_encode_refuses_oversized_message():
    with pytest.raises(FramingError):
        hidframe.encode(b"\x00" * (hidframe.MAX_MESSAGE_SIZE + 1))


def test_continuation_without_start_is_rejected():
    decoder = Decoder()
    with pytest.raises(FramingError, match="no message in progress"):
        decoder.push(b"\x00" + b"\x00" * 63)


def test_unknown_tag_is_rejected():
    decoder = Decoder()
    with pytest.raises(FramingError, match="unknown report tag"):
        decoder.push(b"\x7f" + b"\x00" * 63)


def test_start_report_abandons_a_message_in_progress():
    """A host that restarts mid-message resynchronizes rather than wedging the session."""
    decoder = Decoder()
    decoder.push(hidframe.encode(b"a" * 500)[0])
    assert decoder.push(hidframe.encode(b"short")[0]) == b"short"


def test_decoder_recovers_state_after_a_framing_error():
    decoder = Decoder()
    with pytest.raises(FramingError):
        decoder.push(b"\x7f" + b"\x00" * 63)
    assert roundtrip(b"still works") == b"still works"
    assert decoder.push(hidframe.encode(b"ok")[0]) == b"ok"


def test_trailing_padding_is_not_included_in_the_message():
    payload = b"abc"
    reports = hidframe.encode(payload)
    assert len(reports) == 1
    assert Decoder().push(reports[0]) == payload
