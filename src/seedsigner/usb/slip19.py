"""
SLIP-19 ownership proofs, the second thing a coinjoin signer must produce.

A WabiSabi coordinator will not register an input until the client proves it can spend it,
with a signature over a commitment the coordinator chose (round id, coordinator name). The
signature has to come from the input's own key, so this cannot live on the host: it is the
seed proving ownership, and only the device has the seed.

The proof is the SLIP-19 construction Trezor defined and Wasabi verifies:

    body   = magic || flags || count || ownership_id...
    digest = SHA256(body || ser(scriptPubKey) || ser(commitment))
    proof  = body || scriptSig || witness      (the witness signs `digest`)

with the ownership id an HMAC over the scriptPubKey under a SLIP-21 key derived from the
seed, so the same script always yields the same id and a coordinator can spot an input it
has seen before without learning the key.

Ported from Krux's slip19.py (MIT), adapted to take an embit root key directly. Only
P2WPKH and P2TR exist because those are the only script types Wasabi coinjoins.
"""
import hashlib
import hmac
from io import BytesIO

from embit import bip32, compact, ec, script


MAGIC = b"\x53\x4c\x00\x19"
USER_CONFIRMATION = 1
RESERVED_FLAGS = 0xFE
P2WPKH = "p2wpkh"
P2TR = "p2tr"
SCRIPT_TYPES = (P2WPKH, P2TR)

_OWNERSHIP_KEY_LABELS = ("SLIP-0019", "Ownership identification key")


def _script_bytes(script_pubkey) -> bytes:
    return script_pubkey.data if hasattr(script_pubkey, "data") else script_pubkey


def _ser_string(data: bytes) -> bytes:
    return compact.to_bytes(len(data)) + data


def slip21_key(seed_bytes: bytes, labels) -> bytes:
    """SLIP-21 Key(m/label/...) from a BIP-39 binary seed."""
    node = hmac.new(b"Symmetric key seed", seed_bytes, digestmod="sha512").digest()
    for label in labels:
        if isinstance(label, str):
            label = label.encode()
        node = hmac.new(node[:32], b"\x00" + label, digestmod="sha512").digest()
    return node[32:]


def ownership_key(seed_bytes: bytes) -> bytes:
    return slip21_key(seed_bytes, _OWNERSHIP_KEY_LABELS)


def ownership_id(seed_bytes: bytes, script_pubkey) -> bytes:
    return hmac.new(ownership_key(seed_bytes), _script_bytes(script_pubkey), digestmod="sha256").digest()


def proof_body(flags: int, ownership_ids: list) -> bytes:
    if flags & RESERVED_FLAGS:
        raise ValueError("reserved SLIP-19 flags set")
    return MAGIC + bytes([flags]) + compact.to_bytes(len(ownership_ids)) + b"".join(ownership_ids)


def proof_digest(body: bytes, script_pubkey, commitment: bytes) -> bytes:
    if commitment is None:
        raise ValueError("missing commitment data")
    return hashlib.sha256(body + _ser_string(_script_bytes(script_pubkey)) + _ser_string(commitment)).digest()


def script_for(script_type: str, pubkey: ec.PublicKey) -> script.Script:
    if script_type == P2WPKH:
        return script.p2wpkh(pubkey)
    if script_type == P2TR:
        return script.p2tr(pubkey)
    raise ValueError("unsupported SLIP-19 script type")


def create_proof(root: bip32.HDKey, seed_bytes: bytes, script_type: str, path: list, commitment: bytes, flags: int = 0) -> tuple:
    """
    Build the proof for the key at `path`. Returns (proof bytes, scriptPubKey).

    The scriptPubKey is rebuilt from the derived key rather than taken from the host, so
    there is nothing for the host to lie about: the proof is for whatever script this
    path really pays, and the caller can see which that was.
    """
    if script_type not in SCRIPT_TYPES:
        raise ValueError("unsupported SLIP-19 script type")
    if commitment is None:
        raise ValueError("missing commitment data")

    child = root.derive(path)
    pubkey = child.key.get_public_key()
    script_pubkey = script_for(script_type, pubkey)

    body = proof_body(flags, [ownership_id(seed_bytes, script_pubkey)])
    digest = proof_digest(body, script_pubkey, commitment)

    if script_type == P2WPKH:
        witness = script.witness_p2wpkh(child.sign(digest), pubkey)
    else:
        # BIP-86: the output key is the internal key tweaked with an empty script tree,
        # so the signature has to come from the tweaked key, not the derived one.
        witness = script.Witness([child.taproot_tweak().schnorr_sign(digest).serialize()])

    return body + script.Script().serialize() + witness.serialize(), script_pubkey


def _parse_body(proof: bytes):
    if len(proof) < 6 or proof[:4] != MAGIC:
        raise ValueError("invalid SLIP-19 proof magic")
    flags = proof[4]
    if flags & RESERVED_FLAGS:
        raise ValueError("reserved SLIP-19 flags set")

    stream = BytesIO(proof[5:])
    count = compact.read_from(stream)
    encoded_count = compact.to_bytes(count)
    if proof[5:5 + len(encoded_count)] != encoded_count:
        raise ValueError("non-minimal SLIP-19 ownership count")

    ids = []
    for _ in range(count):
        item = stream.read(32)
        if len(item) != 32:
            raise ValueError("invalid SLIP-19 ownership id")
        ids.append(item)
    body_len = 5 + len(encoded_count) + 32 * count
    return proof[:body_len], flags, ids, proof[body_len:]


def parse_proof(proof: bytes):
    """Split a proof into (body, flags, ids, scriptSig, witness) without verifying it."""
    body, flags, ids, signature_proof = _parse_body(proof)
    stream = BytesIO(signature_proof)
    script_sig = script.Script.read_from(stream)
    witness = script.Witness.read_from(stream)
    if stream.read(1):
        raise ValueError("invalid SLIP-19 signature proof")
    return body, flags, ids, script_sig, witness


def verify_proof(proof: bytes, script_pubkey, commitment: bytes, require_confirmation: bool = False) -> bool:
    """
    Verify a P2WPKH or P2TR proof. Raises ValueError on anything wrong.

    The device never verifies a proof in production; this is the independent check the
    tests use so that create_proof is not marking its own homework.
    """
    body, flags, _, script_sig, witness = parse_proof(proof)
    if require_confirmation and not flags & USER_CONFIRMATION:
        raise ValueError("SLIP-19 proof lacks user confirmation")
    if len(script_sig.data) != 0:
        raise ValueError("unsupported SLIP-19 scriptSig")

    script_data = _script_bytes(script_pubkey)
    script_type = script.Script(script_data).script_type()
    digest = proof_digest(body, script_data, commitment)

    if script_type == P2WPKH:
        if len(witness.items) != 2 or len(witness.items[0]) < 2:
            raise ValueError("invalid P2WPKH SLIP-19 witness")
        sig_data, pub_data = witness.items
        if sig_data[-1] != 1:
            raise ValueError("invalid P2WPKH SLIP-19 sighash")
        pubkey = ec.PublicKey.parse(pub_data)
        if script.p2wpkh(pubkey).data != script_data:
            raise ValueError("P2WPKH witness does not match scriptPubKey")
        if not pubkey.verify(ec.Signature.parse(sig_data[:-1]), digest):
            raise ValueError("invalid P2WPKH SLIP-19 signature")
        return True

    if script_type == P2TR:
        if len(witness.items) != 1 or len(witness.items[0]) != 64:
            raise ValueError("invalid P2TR SLIP-19 witness")
        pubkey = ec.PublicKey.from_xonly(script_data[2:])
        if not pubkey.schnorr_verify(ec.SchnorrSig(witness.items[0]), digest):
            raise ValueError("invalid P2TR SLIP-19 signature")
        return True

    raise ValueError("unsupported SLIP-19 script type")
