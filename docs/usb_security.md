# SabiSigner USB security

SeedSigner compiles USB out of the kernel entirely. SabiSigner puts a narrow piece of it
back so that Wasabi can run remote coinjoin rounds against the device, and this document
is the accounting of what that costs and what was done about it. It is deliberately
explicit about the things it does *not* defend, because a signing device whose
documentation oversells it is worse than one that has no USB at all.

## What the device will do over USB

Five requests exist. There is no sixth.

| Request | Needs a seed | Asks the user | Notes |
|---|---|---|---|
| `get_version` | no | no | Reveals nothing about the wallet |
| `get_xpub` | yes | yes | Privacy leak; prompted as one |
| `sign_psbt` | yes | yes | Same review the QR flow gives |
| `authorize_coinjoin` | yes | yes | Grants unattended signing within a budget |
| `sign_coinjoin` | yes | **no** | Checked by policy, not by a human |

There is no request that exports a seed, dumps entropy, reads an arbitrary file, or
executes anything. This is not a filter that could be bypassed: the device has no such
operation for the USB layer to reach. A bug in `protocol.py` cannot invent a capability
that the rest of the application does not implement.

## The threat model

### Defended

**A host that lies about what it wants signed.** Every signing request is checked against
the PSBT's own contents on the device. For coinjoin rounds this is `policy.py`, which
independently re-derives ownership of every input and output rather than believing the
derivation paths the host claims. A forged ownership claim fails the re-derivation and the
whole round is refused.

**The miner-fee attack** (the Trezor 1.9.1 / 2.3.1 class of bug). Pre-taproot sighashes
commit only to the amount of the input being signed, so a host can lie about the *other*
inputs' amounts and steal the difference as miner fee. Non-taproot inputs are therefore
required to carry a full `non_witness_utxo`, and the previous transaction's txid is
verified against the outpoint before anything is signed. Taproot's sighash commits to all
spent amounts, so a `witness_utxo` alone is accepted there.

**"Coinjoin authorization" used as an unattended drain.** An authorization is not a blank
cheque. Every round must have at least four foreign inputs, so a transaction that is really
just "send the user's coins somewhere" cannot be presented as a round. Every owned input
and output must sit under the single account path the user approved, so an authorization
for one account cannot be spent from another. The round count and the total fee budget both
decrement, and the device refuses once either runs out.

**Passive snooping on the cable.** The session is encrypted end to end between the host
application and the device: ephemeral ECDH on secp256k1, HKDF-SHA256 to per-direction keys,
and an encrypt-then-MAC record layer (HMAC-SHA256 keystream, HMAC-SHA256-128 tag). Records
are accepted strictly in order, so a replayed or reordered record is rejected. The tag is
verified before the counter is even looked at, so an attacker cannot use counter errors to
probe session state.

**An active interposer in the cable.** Encryption alone does not help if something in the
middle runs two handshakes. Six digits derived from a hash of both public keys are shown on
the device and on the host; an interposer that substituted either key produces different
digits on the two ends. The user compares them once per session. This is the only defense
against that attack, which is why the prompt asks the user to compare rather than merely to
continue.

**BadUSB and anything else that needs the device to be a USB *host*.** `CONFIG_USB` is not
set. The kernel has the gadget (peripheral) stack and nothing else: there is no host
controller driver, no HID driver, no mass-storage driver, no driver of any kind that could
bind to a device plugged into the port. A malicious USB device attached to a SabiSigner is
electrically connected to a kernel that cannot talk to it.

**A device that is plugged in but not in use.** The gadget is created at boot but its UDC
is bound only while the user is on the USB screen. A SabiSigner sitting in a laptop's USB
port enumerates as nothing at all. Leaving the screen unbinds it and destroys the session
keys, the authorization, and the record counters.

**A compromised USB endpoint process.** The process that reads and writes `/dev/hidg0` is
not the process that holds the seed. The parent opens the endpoint as root, forks, and the
child drops to `nobody` holding only the inherited file descriptor and one end of a
socketpair -- no filesystem socket, nothing to reconnect to. That child is a byte pipe: the
encryption and the request dispatch both live in the parent, so code execution in the
gateway yields neither plaintext nor the ability to forge the pairing digits.

### Not defended

**An attacker who replaced the image.** The build fingerprint on the splash screen is drawn
by code that is itself part of the image. On a Pi Zero or Zero 2 W there is no boot-ROM root
of trust, so software attestation there detects corruption and lazy attackers, not a
competent one. The defenses that actually work at this layer are outside the software:
verify the published `.img` checksum before flashing, and keep physical control of the card.

**A Pi 4 or CM4 can do better,** because its boot ROM supports signed boot with the key hash
fused into OTP. That is a genuine root of trust, and a user who wants tamper evidence rather
than tamper hints should use one of those boards and enable it. SabiSigner does not enable
it for the user: fusing OTP is irreversible and is the owner's decision, not the build's.

**A user who does not compare the pairing digits.** The interposer defense is a human
comparison. Nothing on the device can tell whether the user actually looked.

**Traffic analysis.** Record sizes and timing are not padded. An observer on the cable
learns roughly how large each message is and when it happened.

**seccomp confinement of the gateway process.** The image has no `libseccomp`, and adding a
hand-rolled BPF filter to a signing device to defend a process that already runs as `nobody`
with one file descriptor was not judged to be worth its own risk. This is a deliberate
deferral, not an oversight.

## Why these primitives

The record layer is built from `hmac` and `hashlib` -- both OpenSSL-backed and already in
the image -- rather than from a vendored AEAD. The choice was between an HMAC construction
assembled from primitives the image already ships and audited, or copying an unreviewed
ChaCha20-Poly1305 implementation into a bitcoin signing device. No primitive here is
hand-rolled; only the composition is, and the composition is the conservative one
(encrypt-then-MAC, separate keys per direction, in-order delivery only).

Requests are JSON. CPython's `json` is a C parser that has seen more hostile input than
anything this project could write, which is the entire argument for it over a bespoke binary
format or a new protobuf dependency at a trust boundary.

## Before shipping a signed release

The USB descriptor currently uses pid.codes VID `0x1209` with PID `0x0001`, which is the
**test** PID and must not be used on a public release. An allocated PID has to replace it
before an image is published as anything other than a prerelease for testing.
