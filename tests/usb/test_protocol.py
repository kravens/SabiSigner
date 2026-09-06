import base64
import json

import pytest

from seedsigner.usb import policy
from seedsigner.usb.protocol import ProtocolError, UsbSession, parse_derivation_path

from usb.coinjoin_util import ACCOUNT_PATH, make_seed, standard_round


ALLOW = lambda kind, details: True
DENY = lambda kind, details: False


@pytest.fixture
def session():
    return UsbSession(seed=make_seed())


def call(session, request: dict, confirm=ALLOW) -> dict:
    return json.loads(session.handle_message(json.dumps(request).encode(), confirm))


# -- derivation path parsing ------------------------------------------------------------

def test_derivation_paths_parse():
    assert parse_derivation_path("m/84'/0'/0'") == ACCOUNT_PATH
    assert parse_derivation_path("m/84h/0h/0h") == ACCOUNT_PATH
    assert parse_derivation_path("m") == []
    assert parse_derivation_path("m/0/1/2") == [0, 1, 2]


@pytest.mark.parametrize("bad", [
    "84'/0'/0'",          # no m
    "m/84'/x/0'",         # not a number
    "m/-1",               # negative
    "m/2147483648",       # index at the hardened boundary
    "m/" + "0/" * 20,     # deeper than the bound
    "",
])
def test_bad_derivation_paths_are_refused(bad):
    with pytest.raises(ProtocolError):
        parse_derivation_path(bad)


# -- the message set --------------------------------------------------------------------

def test_get_version_needs_no_seed_and_no_confirmation():
    response = call(UsbSession(seed=None), {"t": "get_version"}, confirm=DENY)
    assert response["t"] == "ok"
    assert response["model"] == "SabiSigner"


def test_unknown_request_types_are_refused(session):
    assert call(session, {"t": "please_export_the_seed"})["t"] == "error"
    assert call(session, {"t": "get_seed"})["t"] == "error"
    assert call(session, {})["t"] == "error"
    assert call(session, {"t": 5})["t"] == "error"


def test_malformed_json_is_an_error_not_a_crash(session):
    response = json.loads(session.handle_message(b"{not json", ALLOW))
    assert response["t"] == "error"
    response = json.loads(session.handle_message(b"\xff\xfe", ALLOW))
    assert response["t"] == "error"


def test_a_bare_json_array_is_refused(session):
    response = json.loads(session.handle_message(b"[1,2,3]", ALLOW))
    assert response["t"] == "error"


def test_requests_needing_a_seed_are_refused_without_one():
    session = UsbSession(seed=None)
    assert call(session, {"t": "get_xpub", "path": "m/84'/0'/0'"})["t"] == "error"
    assert call(session, {"t": "sign_psbt", "psbt": ""})["t"] == "error"


def test_get_xpub_requires_confirmation(session):
    denied = call(session, {"t": "get_xpub", "path": "m/84'/0'/0'"}, confirm=DENY)
    assert denied["t"] == "error"

    allowed = call(session, {"t": "get_xpub", "path": "m/84'/0'/0'"}, confirm=ALLOW)
    assert allowed["t"] == "ok"
    assert allowed["xpub"].startswith("xpub")
    assert allowed["fingerprint"] == session.seed.get_fingerprint()


def test_get_xpub_canonicalizes_the_path(session):
    response = call(session, {"t": "get_xpub", "path": "m/84h/0h/0h"})
    assert response["path"] == "m/84h/0h/0h"


def test_sign_psbt_requires_confirmation(session):
    psbt_b64 = standard_round(make_seed()).to_base64()
    assert call(session, {"t": "sign_psbt", "psbt": psbt_b64}, confirm=DENY)["t"] == "error"
    assert call(session, {"t": "sign_psbt", "psbt": psbt_b64}, confirm=ALLOW)["t"] == "ok"


def test_a_psbt_that_is_not_base64_is_refused(session):
    assert call(session, {"t": "sign_psbt", "psbt": "not base64!!"})["t"] == "error"


def test_a_psbt_that_is_base64_but_not_a_psbt_is_refused(session):
    assert call(session, {"t": "sign_psbt", "psbt": base64.b64encode(b"nope").decode()})["t"] == "error"


def test_an_oversized_psbt_field_is_refused_before_decoding(session):
    huge = "A" * (200 * 1024)
    assert call(session, {"t": "sign_psbt", "psbt": huge})["t"] == "error"


# -- coinjoin authorization -------------------------------------------------------------

AUTH_REQUEST = {
    "t": "authorize_coinjoin",
    "coordinator": "wasabi.test",
    "account_path": "m/84'/0'/0'",
    "max_rounds": 5,
    "max_fee_per_round_sat": 5_000,
    "max_total_fee_sat": 20_000,
}


def test_coinjoin_signing_needs_an_authorization_first(session):
    psbt_b64 = standard_round(session.seed).to_base64()
    assert call(session, {"t": "sign_coinjoin", "psbt": psbt_b64})["t"] == "error"


def test_authorization_requires_confirmation(session):
    assert call(session, dict(AUTH_REQUEST), confirm=DENY)["t"] == "error"
    assert session.authorization is None


def test_authorized_rounds_sign_without_further_confirmation(session):
    authorized = call(session, dict(AUTH_REQUEST))
    assert authorized["t"] == "ok"
    # The master fingerprint, 4 bytes as hex; a bridge identifies the wallet to Wasabi by it.
    assert authorized["fingerprint"] == session.seed.get_fingerprint()
    assert len(authorized["fingerprint"]) == 8

    psbt_b64 = standard_round(session.seed).to_base64()
    # DENY: after the authorization the device must not be asking again, so a confirm
    # callable that refuses everything has to make no difference.
    response = call(session, {"t": "sign_coinjoin", "psbt": psbt_b64}, confirm=DENY)
    assert response["t"] == "ok"
    assert response["fee_sat"] == 1_000
    assert response["rounds_remaining"] == 4


def test_a_round_that_fails_policy_is_an_error_even_when_authorized(session):
    call(session, dict(AUTH_REQUEST))
    bad = standard_round(session.seed, our_in=100_000, our_out=10_000).to_base64()
    assert call(session, {"t": "sign_coinjoin", "psbt": bad}, confirm=DENY)["t"] == "error"


def test_ownership_proofs_need_a_live_authorization(session):
    request = {"t": "get_ownership_proof", "path": "m/84'/0'/0'/0/0", "script_type": "p2wpkh", "commitment": ""}
    assert call(session, request)["t"] == "error"

    call(session, {**AUTH_REQUEST, "max_rounds": 1})
    assert call(session, request)["t"] == "ok"

    # Spend the only round; the authorization is used up and proofs stop with it.
    call(session, {"t": "sign_coinjoin", "psbt": standard_round(session.seed).to_base64()}, confirm=DENY)
    assert call(session, request)["t"] == "error"


def test_ownership_proofs_are_unattended_and_verify(session):
    from embit import script
    from seedsigner.usb import slip19
    from usb.coinjoin_util import make_root

    call(session, dict(AUTH_REQUEST))
    commitment = b"round-id||coordinator"
    # The taproot key lives in the BIP-86 sibling account, which the 84' authorization covers.
    taproot_account = [86 + 2**31] + ACCOUNT_PATH[1:]
    for script_type, path in [("p2wpkh", ACCOUNT_PATH + [0, 3]), ("p2tr", taproot_account + [1, 7])]:
        request = {
            "t": "get_ownership_proof",
            "path": "m/" + "/".join(str(i - 2**31) + "'" if i >= 2**31 else str(i) for i in path),
            "script_type": script_type,
            "commitment": base64.b64encode(commitment).decode(),
        }
        # DENY: inside an authorization nothing may ask the user again.
        response = call(session, request, confirm=DENY)
        assert response["t"] == "ok", response

        pubkey = make_root(session.seed).derive(path).key.get_public_key()
        expected = script.p2wpkh(pubkey) if script_type == "p2wpkh" else script.p2tr(pubkey)
        assert response["script_pubkey"] == expected.data.hex()
        proof = base64.b64decode(response["proof"])
        assert slip19.verify_proof(proof, expected, commitment, require_confirmation=True)


def test_ownership_proofs_stay_inside_the_authorized_account(session):
    from usb.coinjoin_util import OTHER_ACCOUNT_PATH

    call(session, dict(AUTH_REQUEST))
    outside = "m/84'/0'/1'/0/0"
    response = call(session, {"t": "get_ownership_proof", "path": outside, "script_type": "p2wpkh", "commitment": ""})
    assert response["t"] == "error"
    assert "account" in response["message"]


def test_ownership_proof_fields_are_checked(session):
    call(session, dict(AUTH_REQUEST))
    good = {"t": "get_ownership_proof", "path": "m/84'/0'/0'/0/0", "script_type": "p2wpkh", "commitment": ""}
    for bad in [
        {**good, "script_type": "p2sh"},
        {**good, "script_type": 1},
        {**good, "commitment": "not base64!"},
        {**good, "commitment": "A" * 5000},
        {**good, "path": "84'/0'/0'/0/0"},
    ]:
        assert call(session, bad)["t"] == "error", bad


def test_authorization_fields_are_type_checked(session):
    for bad in [
        {**AUTH_REQUEST, "max_rounds": "5"},
        {**AUTH_REQUEST, "max_rounds": True},
        {**AUTH_REQUEST, "max_rounds": 0},
        {**AUTH_REQUEST, "max_fee_per_round_sat": -1},
        {**AUTH_REQUEST, "account_path": 84},
        {**AUTH_REQUEST, "coordinator": "x" * 100},
        {**AUTH_REQUEST, "max_fee_per_round_sat": 30_000},  # over the total budget
    ]:
        assert call(session, bad)["t"] == "error", bad


def test_an_internal_error_does_not_leak_a_traceback(session, monkeypatch):
    """
    A traceback sent over the wire is a description of the device's internals, handed to
    whoever is on the other end of the cable.
    """
    def explode(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setitem(UsbSession._HANDLERS, "get_version", explode)
    response = call(session, {"t": "get_version"})
    assert response["t"] == "error"
    assert "secret internal detail" not in response["message"]
    assert response["message"] == "internal error"
