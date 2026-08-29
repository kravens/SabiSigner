"""
SabiSigner's USB stack.

SeedSigner is airgapped: QR codes in, QR codes out, and a kernel with the USB stack
compiled out entirely. SabiSigner re-enables USB, which means re-introducing the one
attack surface the parent project removed on purpose. Everything in this package exists
to keep that surface as small as the feature allows:

  hidframe.py  reassembles 64-byte HID reports into messages. Fixed-size reports, a hard
               length cap, no allocation driven by an attacker-supplied number beyond it.
  crypto.py    the session channel: ECDH over secp256k1 (libsecp256k1, via embit), HKDF,
               and encrypt-then-MAC built only from hmac/hashlib. No primitive is
               implemented here from scratch.
  policy.py    the coinjoin authorization and the per-round checks that let a round sign
               without a button press. This is the only code path in the product that
               signs anything without the user looking at it, so it is the code most
               worth reading twice.
  protocol.py  request dispatch. Pure functions over parsed requests; no I/O, no key
               material, no UI.

Two rules shape all of it:

1. USB can only ask for things the QR flow can already do. There is no message that
   exports a seed, because there is no such operation in the device to expose. A bug in
   this package cannot invent one.
2. The process that touches USB bytes is not the process that holds the seed. See
   gateway.py.
"""
