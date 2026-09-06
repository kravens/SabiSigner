"""
SLIP-19 proofs against the published vectors, plus the P2TR tweak that the vectors do not
cover. The vector seed is "all all all ... all", the one the SLIP-19 spec and Trezor's own
tests use, so the expected values here are theirs, not ours.
"""
import pytest

from embit import bip32, script
from embit.networks import NETWORKS

from seedsigner.models.seed import Seed
from seedsigner.usb import slip19


VECTOR_SEED = Seed("all all all all all all all all all all all all".split())
P2WPKH_PATH = [84 + 2**31, 0 + 2**31, 0 + 2**31, 1, 0]
P2TR_PATH = [86 + 2**31, 0 + 2**31, 0 + 2**31, 1, 0]


def root(seed: Seed) -> bip32.HDKey:
    return bip32.HDKey.from_seed(seed.seed_bytes, version=NETWORKS["main"]["xprv"])


def test_slip21_ownership_key_matches_the_vector():
    assert slip19.ownership_key(VECTOR_SEED.seed_bytes).hex() == (
        "0a115a171e30f8a740bae6c4144bec5dc1099ffa79b83dfb8aa3501d094de585"
    )


def test_p2wpkh_proof_matches_the_vector():
    proof, script_pubkey = slip19.create_proof(
        root(VECTOR_SEED), VECTOR_SEED.seed_bytes, slip19.P2WPKH, P2WPKH_PATH, b"", flags=0
    )
    assert script_pubkey.data.hex() == "0014b2f771c370ccf219cd3059cda92bdf7f00cf2103"
    assert proof[:38].hex() == (
        "534c00190001"
        "a122407efc198211c81af4450f40b235d54775efd934d16b9e31c6ce9bad5707"
    )
    assert slip19.proof_digest(proof[:38], script_pubkey, b"").hex() == (
        "850dd556283b49d80fa5501035b4775e62f0c80bf36f62d1adf2f2f9f108c884"
    )
    assert slip19.verify_proof(proof, script_pubkey, b"")


def test_the_confirmation_flag_is_in_the_body_and_verified():
    proof, script_pubkey = slip19.create_proof(
        root(VECTOR_SEED), VECTOR_SEED.seed_bytes, slip19.P2WPKH, P2WPKH_PATH, b"round", flags=slip19.USER_CONFIRMATION
    )
    assert proof[4] == 1
    assert slip19.verify_proof(proof, script_pubkey, b"round", require_confirmation=True)

    unconfirmed, _ = slip19.create_proof(
        root(VECTOR_SEED), VECTOR_SEED.seed_bytes, slip19.P2WPKH, P2WPKH_PATH, b"round", flags=0
    )
    with pytest.raises(ValueError, match="confirmation"):
        slip19.verify_proof(unconfirmed, script_pubkey, b"round", require_confirmation=True)


def test_p2tr_proof_signs_with_the_tweaked_key():
    r = root(VECTOR_SEED)
    commitment = b"coinjoin-commitment"
    proof, script_pubkey = slip19.create_proof(
        r, VECTOR_SEED.seed_bytes, slip19.P2TR, P2TR_PATH, commitment, flags=slip19.USER_CONFIRMATION
    )
    assert script_pubkey.script_type() == "p2tr"
    assert slip19.verify_proof(proof, script_pubkey, commitment, require_confirmation=True)

    # A signature from the untweaked key must not verify against a BIP-86 output.
    body = proof[:38]
    digest = slip19.proof_digest(body, script_pubkey, commitment)
    untweaked = r.derive(P2TR_PATH).schnorr_sign(digest)
    bad = body + script.Script().serialize() + script.Witness([untweaked.serialize()]).serialize()
    with pytest.raises(ValueError, match="invalid P2TR"):
        slip19.verify_proof(bad, script_pubkey, commitment)


def test_a_proof_is_bound_to_its_commitment():
    proof, script_pubkey = slip19.create_proof(
        root(VECTOR_SEED), VECTOR_SEED.seed_bytes, slip19.P2WPKH, P2WPKH_PATH, b"round A"
    )
    with pytest.raises(ValueError, match="signature"):
        slip19.verify_proof(proof, script_pubkey, b"round B")


def test_create_proof_refuses_what_it_cannot_prove():
    r = root(VECTOR_SEED)
    with pytest.raises(ValueError, match="unsupported"):
        slip19.create_proof(r, VECTOR_SEED.seed_bytes, "p2sh", P2WPKH_PATH, b"")
    with pytest.raises(ValueError, match="missing commitment"):
        slip19.create_proof(r, VECTOR_SEED.seed_bytes, slip19.P2WPKH, P2WPKH_PATH, None)


def test_malformed_proofs_are_rejected():
    with pytest.raises(ValueError, match="reserved"):
        slip19.proof_body(0xFE, [])
    with pytest.raises(ValueError, match="magic"):
        slip19.parse_proof(b"bad")
    with pytest.raises(ValueError, match="non-minimal"):
        slip19.parse_proof(slip19.MAGIC + b"\x00\xfd\x00\x00")
    with pytest.raises(ValueError, match="ownership id"):
        slip19.parse_proof(slip19.MAGIC + b"\x00\x01" + b"\x00" * 31)
    trailing = slip19.proof_body(0, []) + script.Script().serialize() + script.Witness([]).serialize() + b"\x00"
    with pytest.raises(ValueError, match="signature proof"):
        slip19.parse_proof(trailing)
