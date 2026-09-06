#!/usr/bin/env python3
"""
A minimal host for the SabiSigner USB session, so the device's USB path can be exercised
without Wasabi.

This is a testing and reference tool, not a wallet. It speaks the whole protocol -- the
handshake, the pairing digits, and the request set -- in about as little code as the
protocol can be spoken in, which is also the point: a host implementation that fits on one
screen is one an integrator can read before trusting it.

Run it on Linux with the device plugged in and the USB screen open on the device:

    python3 tools/usb_host_demo.py --device /dev/hidraw0 get_version
    python3 tools/usb_host_demo.py --device /dev/hidraw0 get_xpub "m/84'/0'/0'"

The device node is whichever /dev/hidrawN appeared when the SabiSigner bound its gadget;
`ls -l /sys/class/hidraw/*/device/../..` will point at the right one. Reading and writing
it usually needs root or a udev rule.

On macOS (or anywhere without hidraw) use `--device hidapi`, which needs `pip install hidapi`
and finds the device by its USB ids; no root needed there.

Compare the six digits this prints against the six digits on the device screen before
answering yes. That comparison is the only thing standing between this session and
something sitting in the middle of the cable.
"""
import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from embit import ec

from seedsigner.usb import crypto, hidframe


class HidLink:
    """Whole messages over a /dev/hidraw node."""

    def __init__(self, path: str):
        self.fd = os.open(path, os.O_RDWR)
        self.decoder = hidframe.Decoder()

    def send(self, message: bytes) -> None:
        for report in hidframe.encode(message):
            # hidraw expects a leading report-id byte; the gadget uses report id 0.
            os.write(self.fd, b"\x00" + report)

    def receive(self) -> bytes:
        while True:
            report = os.read(self.fd, hidframe.REPORT_SIZE)
            message = self.decoder.push(report)
            if message is not None:
                return message

    def close(self) -> None:
        os.close(self.fd)


class HidapiLink:
    """Whole messages through the hidapi library, for hosts without /dev/hidraw (macOS)."""

    VENDOR_ID = 0x1209
    PRODUCT_ID = 0x0001

    def __init__(self):
        import hid  # pip install hidapi
        self.dev = hid.device()
        self.dev.open(self.VENDOR_ID, self.PRODUCT_ID)
        self.decoder = hidframe.Decoder()

    def send(self, message: bytes) -> None:
        for report in hidframe.encode(message):
            self.dev.write(b"\x00" + report)

    def receive(self) -> bytes:
        while True:
            report = bytes(self.dev.read(hidframe.REPORT_SIZE))
            message = self.decoder.push(report)
            if message is not None:
                return message

    def close(self) -> None:
        self.dev.close()


def open_session(link: HidLink) -> crypto.SessionChannel:
    host_priv = ec.PrivateKey(os.urandom(32))
    host_pub = host_priv.get_public_key().sec()

    link.send(json.dumps({
        "t": "hello",
        "pk": base64.b64encode(host_pub).decode("ascii"),
    }).encode("utf-8"))

    reply = json.loads(link.receive().decode("utf-8"))
    if reply.get("t") != "hello":
        raise SystemExit(f"device did not answer the handshake: {reply}")

    device_pub = base64.b64decode(reply["pk"], validate=True)
    channel = crypto.handshake_initiator(device_pub, host_priv)

    print(f"\n  Pairing code: {channel.sas[:3]} {channel.sas[3:]}\n")
    print("  Confirm the SAME six digits are on the device screen, then approve there.")
    input("  Press enter once you have approved it on the device: ")
    return channel


def request(link: HidLink, channel: crypto.SessionChannel, body: dict) -> dict:
    link.send(channel.seal(json.dumps(body).encode("utf-8")))
    return json.loads(channel.open(link.receive()).decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="/dev/hidraw0", help="the SabiSigner's hidraw node, or 'hidapi'")
    parser.add_argument("command", choices=["get_version", "get_xpub", "sign_psbt", "authorize_coinjoin", "get_ownership_proof"])
    parser.add_argument("argument", nargs="?", help="derivation path, or a base64 psbt")
    parser.add_argument("--coordinator", default="wasabi.example")
    parser.add_argument("--max-rounds", type=int, default=5)
    parser.add_argument("--max-fee-per-round-sat", type=int, default=1_000)
    parser.add_argument("--max-total-fee-sat", type=int, default=5_000)
    parser.add_argument("--script-type", choices=["p2wpkh", "p2tr"], default="p2wpkh")
    parser.add_argument("--commitment", default="demo", help="commitment data for get_ownership_proof (utf-8)")
    args = parser.parse_args()

    link = HidapiLink() if args.device == "hidapi" else HidLink(args.device)
    try:
        channel = open_session(link)

        authorize = {
            "t": "authorize_coinjoin",
            "coordinator": args.coordinator,
            "account_path": args.argument or "m/84'/0'/0'",
            "max_rounds": args.max_rounds,
            "max_fee_per_round_sat": args.max_fee_per_round_sat,
            "max_total_fee_sat": args.max_total_fee_sat,
        }

        if args.command == "get_version":
            body = {"t": "get_version"}
        elif args.command == "get_xpub":
            body = {"t": "get_xpub", "path": args.argument or "m/84'/0'/0'"}
        elif args.command == "sign_psbt":
            if not args.argument:
                parser.error("sign_psbt needs a base64 psbt")
            body = {"t": "sign_psbt", "psbt": args.argument}
        elif args.command == "get_ownership_proof":
            # A proof exists only inside a live authorization, so authorize the account the
            # path sits in first (m/purpose'/coin'/account'), then ask for the proof.
            path = args.argument or "m/84'/0'/0'/0/0"
            authorize["account_path"] = "/".join(path.split("/")[:4])
            print(json.dumps(request(link, channel, authorize), indent=2))
            body = {
                "t": "get_ownership_proof",
                "path": path,
                "script_type": args.script_type,
                "commitment": base64.b64encode(args.commitment.encode("utf-8")).decode("ascii"),
            }
        else:
            body = authorize

        print(json.dumps(request(link, channel, body), indent=2))
    finally:
        link.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
