"""
Request dispatch for the USB session.

The message set is deliberately a subset of what the QR flow already does. There is no
"export seed" request, no "dump entropy", no "read arbitrary path" -- not because they are
filtered out here, but because the device has no such operation for this module to reach.
A bug in this file cannot invent a capability the rest of the app does not have.

Everything is JSON over the encrypted channel. json is a C parser in CPython that has seen
more hostile input than anything this project could write, which is the whole argument for
choosing it over a hand-rolled binary format or a protobuf dependency. Binary payloads
(psbts, public keys) travel base64-encoded inside it.

Confirmation is injected, not performed. `handle()` takes a `confirm` callable supplied by
the view layer, so this module stays free of the renderer and the test suite can drive
every path by passing a stub. The rule the callable enforces is simple: everything that
reveals wallet data or produces a signature asks the user, except a coinjoin round, which
asks policy.py instead.
"""
import base64
import binascii
import json
import logging

from embit.psbt import PSBT

from seedsigner.helpers.version import Version
from seedsigner.models.settings import SettingsConstants
from seedsigner.usb import policy, slip19


logger = logging.getLogger(__name__)


PROTOCOL_VERSION = 1

# Bounds applied before anything is decoded. The framing layer already caps the total
# message, but a request that fits in 128 KiB can still be a 128 KiB derivation path.
MAX_PSBT_B64 = 120 * 1024
MAX_STRING_FIELD = 256
MAX_DERIVATION_DEPTH = 16


class ProtocolError(Exception):
    """A malformed or unauthorized request. Returned to the host as an error response."""
    pass


class UserDeclined(ProtocolError):
    """The user pressed no. Distinct from a malformed request so the host can say so."""
    pass


def _require_str(request: dict, key: str, max_len: int = MAX_STRING_FIELD) -> str:
    value = request.get(key)
    if not isinstance(value, str):
        raise ProtocolError(f"'{key}' must be a string")
    if len(value) > max_len:
        raise ProtocolError(f"'{key}' is too long")
    return value


def _require_int(request: dict, key: str, minimum: int = 0, maximum: int = 2**53) -> int:
    value = request.get(key)
    # bool is an int subclass in Python and would sail through an isinstance check.
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProtocolError(f"'{key}' must be an integer")
    if not (minimum <= value <= maximum):
        raise ProtocolError(f"'{key}' is out of range")
    return value


def parse_derivation_path(path_str: str) -> list[int]:
    """
    Parse "m/84'/0'/0'" into a list of indexes.

    Written here rather than borrowed from embit's parser so the depth bound and the
    rejection of oversized indexes are visible at the trust boundary where they matter.
    """
    parts = path_str.strip().split("/")
    if not parts or parts[0] not in ("m", "M"):
        raise ProtocolError("derivation path must start with 'm'")
    parts = parts[1:]
    if len(parts) > MAX_DERIVATION_DEPTH:
        raise ProtocolError(f"derivation path deeper than {MAX_DERIVATION_DEPTH}")

    path = []
    for part in parts:
        hardened = part.endswith("'") or part.endswith("h") or part.endswith("H")
        digits = part[:-1] if hardened else part
        if not digits.isdigit():
            raise ProtocolError(f"bad derivation path element: {part!r}")
        index = int(digits)
        if index >= 2**31:
            raise ProtocolError(f"derivation index out of range: {part!r}")
        path.append(index + 2**31 if hardened else index)
    return path


def _decode_base64(request: dict, key: str, max_len: int) -> bytes:
    raw = _require_str(request, key, max_len=max_len)
    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ProtocolError(f"{key} is not valid base64: {e}")


def _decode_psbt(request: dict) -> PSBT:
    decoded = _decode_base64(request, "psbt", max_len=MAX_PSBT_B64)
    try:
        return PSBT.parse(decoded)
    except Exception as e:
        raise ProtocolError(f"psbt did not parse: {e}")


class UsbSession:
    """
    One USB session's state. Created when the user opens the USB screen, destroyed when
    they leave it. Nothing here is written to disk, because there is no writable disk.

    `seed` is the seed the user selected for this session. It is held by the process that
    owns the screen, never by the process that owns the USB endpoint (see gateway.py).
    """

    def __init__(self, seed=None, network: str = SettingsConstants.MAINNET):
        self.seed = seed
        self.network = network
        self.authorization: policy.CoinjoinAuthorization | None = None

    # -- request handlers --------------------------------------------------------------

    def _handle_get_version(self, request: dict, confirm) -> dict:
        """
        Free of charge and free of confirmation: it reveals nothing about the wallet, and
        a host needs it before it knows what else it may ask for.
        """
        return {
            "protocol": PROTOCOL_VERSION,
            "version": Version.get_version_name(),
            "build": Version.get_short_commit_hash(),
            "model": "SabiSigner",
        }

    def _handle_get_xpub(self, request: dict, confirm) -> dict:
        self._require_seed()
        path_str = _require_str(request, "path")
        path = parse_derivation_path(path_str)

        if not confirm("export_xpub", {"path": path_str, "network": self.network}):
            raise UserDeclined("Export declined on the device")

        from embit import bip32
        from seedsigner.helpers import embit_utils

        # Hand embit the path this module parsed, re-serialized, rather than the string
        # the host sent. embit's own parser accepts forms mine rejects, and only one of
        # the two should decide what gets derived.
        canonical_path = bip32.path_to_str(path)
        xpub = embit_utils.get_xpub(
            seed_bytes=self.seed.seed_bytes,
            derivation_path=canonical_path,
            embit_network=SettingsConstants.map_network_to_embit(self.network),
        )
        # The master fingerprint is what a wallet file keys the xpub by; the user has just
        # approved exporting a public key of this seed, and the fingerprint reveals less.
        return {
            "xpub": xpub.to_base58(),
            "path": canonical_path,
            "fingerprint": self.seed.get_fingerprint(self.network),
        }

    def _handle_sign_psbt(self, request: dict, confirm) -> dict:
        """
        The ordinary signing path. The user sees the same review screens the QR flow shows;
        USB only changed how the bytes arrived.
        """
        self._require_seed()
        psbt = _decode_psbt(request)

        if not confirm("sign_psbt", {"psbt": psbt}):
            raise UserDeclined("Signing declined on the device")

        from embit import bip32
        from embit.networks import NETWORKS
        root = bip32.HDKey.from_seed(
            self.seed.seed_bytes,
            version=NETWORKS[SettingsConstants.map_network_to_embit(self.network)]["xprv"],
        )
        if psbt.sign_with(root) == 0:
            raise ProtocolError("Nothing in this psbt could be signed by the selected seed")
        return {"psbt": psbt.to_base64()}

    def _handle_authorize_coinjoin(self, request: dict, confirm) -> dict:
        self._require_seed()
        coordinator = _require_str(request, "coordinator", max_len=64)
        account_path_str = _require_str(request, "account_path")
        account_path = parse_derivation_path(account_path_str)
        max_rounds = _require_int(request, "max_rounds", minimum=1, maximum=1000)
        max_fee_per_round_sat = _require_int(request, "max_fee_per_round_sat")
        max_total_fee_sat = _require_int(request, "max_total_fee_sat")

        if max_fee_per_round_sat > max_total_fee_sat:
            raise ProtocolError("per-round fee limit exceeds the total budget")

        details = {
            "coordinator": coordinator,
            # Shown with its BIP-84/86 sibling when the scope includes one (see policy).
            "account_path": policy.describe_account_scope(account_path),
            "max_rounds": max_rounds,
            "max_fee_per_round_sat": max_fee_per_round_sat,
            "max_total_fee_sat": max_total_fee_sat,
        }
        # The single most important confirmation in the product: after this the device
        # signs without asking again, so the screen has to show the whole budget.
        if not confirm("authorize_coinjoin", details):
            raise UserDeclined("Coinjoin authorization declined on the device")

        self.authorization = policy.CoinjoinAuthorization(
            coordinator=coordinator,
            account_path=account_path,
            max_rounds=max_rounds,
            max_fee_per_round_sat=max_fee_per_round_sat,
            max_total_fee_sat=max_total_fee_sat,
            network=self.network,
        )
        # The master fingerprint rides along so a bridge can tell Wasabi which wallet this
        # device serves without a second prompt: the user just approved this seed for
        # coinjoin, and the fingerprint is the identity of the wallet Wasabi already holds.
        return {
            "authorized": True,
            "rounds_remaining": self.authorization.rounds_remaining,
            "fingerprint": self.seed.get_fingerprint(self.network),
        }

    def _handle_sign_coinjoin(self, request: dict, confirm) -> dict:
        self._require_seed()
        if self.authorization is None:
            raise ProtocolError("No coinjoin authorization in this session")

        psbt = _decode_psbt(request)
        try:
            signed, summary = policy.sign_coinjoin_round(psbt, self.seed, self.authorization)
        except policy.CoinjoinPolicyError as e:
            raise ProtocolError(str(e))

        return {
            "psbt": signed.to_base64(),
            "fee_sat": summary.our_fee_sat,
            "rounds_remaining": self.authorization.rounds_remaining,
            "fee_remaining_sat": self.authorization.fee_remaining_sat,
        }

    def _handle_get_ownership_proof(self, request: dict, confirm) -> dict:
        """
        A SLIP-19 proof that one of our keys owns its scriptPubKey, over a commitment the
        coordinator chose. Wasabi needs one per input before a round will register it.

        Unattended, like sign_coinjoin, and for the same reason: a round asks for one per
        input, minutes before signing, while the user is elsewhere. What keeps it from being
        a free oracle is that it exists only inside a live coinjoin authorization and only
        for keys under the account the user approved -- the same scope the round may spend.
        A proof reveals that a script is ours, to a coordinator that is about to see us
        spend it anyway; it reveals nothing about any other key.

        The scriptPubKey is not taken from the host. The device derives the key and rebuilds
        the script itself, so the proof is for what the path really pays. The flag says the
        user confirmed, because they did: the authorization prompt is that confirmation, and
        Wasabi's coordinator refuses proofs without it.
        """
        self._require_seed()
        if self.authorization is None or not self.authorization.is_live:
            raise ProtocolError("No live coinjoin authorization in this session")

        path = parse_derivation_path(_require_str(request, "path"))
        script_type = _require_str(request, "script_type", max_len=16)
        if script_type not in slip19.SCRIPT_TYPES:
            raise ProtocolError(f"script_type must be one of {', '.join(slip19.SCRIPT_TYPES)}")
        commitment = _decode_base64(request, "commitment", max_len=4 * 1024)

        if not policy.is_under_account(path, self.authorization.account_path):
            raise ProtocolError("Path is outside the authorized coinjoin account")

        from embit import bip32
        from embit.networks import NETWORKS
        root = bip32.HDKey.from_seed(
            self.seed.seed_bytes,
            version=NETWORKS[SettingsConstants.map_network_to_embit(self.network)]["xprv"],
        )
        proof, script_pubkey = slip19.create_proof(
            root, self.seed.seed_bytes, script_type, path, commitment, flags=slip19.USER_CONFIRMATION
        )
        return {
            "proof": base64.b64encode(proof).decode("ascii"),
            "script_pubkey": script_pubkey.data.hex(),
        }

    _HANDLERS = {
        "get_version": _handle_get_version,
        "get_xpub": _handle_get_xpub,
        "sign_psbt": _handle_sign_psbt,
        "authorize_coinjoin": _handle_authorize_coinjoin,
        "sign_coinjoin": _handle_sign_coinjoin,
        "get_ownership_proof": _handle_get_ownership_proof,
    }

    # -- entry point -------------------------------------------------------------------

    def _require_seed(self):
        if self.seed is None:
            raise ProtocolError("No seed loaded in this session")

    def handle(self, request: dict, confirm) -> dict:
        """
        Dispatch one parsed request. Returns the response body; never raises for an
        ordinary refusal, because handle_message() turns those into error responses.
        """
        if not isinstance(request, dict):
            raise ProtocolError("request must be a JSON object")
        request_type = request.get("t")
        handler = self._HANDLERS.get(request_type) if isinstance(request_type, str) else None
        if handler is None:
            raise ProtocolError(f"unknown request type: {request_type!r}")
        return handler(self, request, confirm)

    def handle_message(self, message: bytes, confirm) -> bytes:
        """
        Full round trip on one decrypted message: parse, dispatch, encode.

        Errors become error responses rather than propagating, so that a hostile or buggy
        host cannot end the session by sending nonsense -- the user decides when the
        session ends, by leaving the screen.
        """
        try:
            request = json.loads(message.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return self._error(f"malformed request: {e}")

        request_type = request.get("t") if isinstance(request, dict) else None
        try:
            body = self.handle(request, confirm)
        except ProtocolError as e:
            return self._error(str(e))
        except Exception as e:
            # Anything unexpected is logged for the developer and reduced to a flat message
            # for the host: a traceback over the wire is a description of the device's
            # internals, sent to whoever is on the other end of the cable.
            logger.exception("unhandled error while processing %r", request_type)
            return self._error("internal error")

        body["t"] = "ok"
        if request_type:
            body["re"] = request_type
        return json.dumps(body).encode("utf-8")

    @staticmethod
    def _error(message: str) -> bytes:
        return json.dumps({"t": "error", "message": message}).encode("utf-8")
