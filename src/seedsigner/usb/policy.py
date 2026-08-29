"""
Coinjoin authorization: the only path in SabiSigner that signs without a button press.

Why it exists. A WabiSabi round has a signing phase measured in minutes and rounds repeat
for as long as the user is remixing. Asking for a physical confirmation per round would
not be a security feature, it would be the reason nobody uses the device for coinjoin and
goes back to a hot wallet. So the confirmation moves: the user approves a *policy* once,
at the start of the session, and each round is then checked against that policy by the
device instead of by the user.

That trade only holds if the checks are strong enough to make an unattended signature
uninteresting to an attacker. The model is Trezor's AuthorizeCoinJoin. The user approves a
coordinator, an account, a round count and a fee budget; every round must then prove, on
the device, that:

  - it is actually a mix (enough inputs the device does not own),
  - every input it would sign belongs to the authorized account and no other,
  - the value coming back is at least the value going out minus the approved fee,
  - the approved budget has not run out.

A round that fails any of these is refused outright rather than escalated to the user: the
user has already left the device unattended, so "ask them" is not an available answer.

No wall-clock expiry. A Raspberry Pi has no battery-backed clock, so any time the device
believes came from the host, which makes a time-limited authorization something the
attacker sets. The budget is counted in rounds and satoshis, both of which the device can
count for itself.

The authorization lives in RAM inside the session and dies with it, like the seed.
"""
import logging

from embit import bip32, script
from embit.psbt import PSBT
from embit.networks import NETWORKS
from embit.transaction import SIGHASH

from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants


logger = logging.getLogger(__name__)


# Bounds on the shape of a round. These are the tuning knobs of this module: a coordinator
# with different round sizes needs them adjusted, and getting them wrong costs either
# compatibility (too strict) or the anonymity guarantee the checks exist for (too loose).
#
# MIN_FOREIGN_INPUTS is the one that matters. Without it, "authorize coinjoin" would also
# authorize a transaction that spends the user's inputs and nothing else, which is just an
# unattended drain wearing a coinjoin label.
MIN_FOREIGN_INPUTS = 4
MIN_TOTAL_INPUTS = 5
MIN_TOTAL_OUTPUTS = 5

# Upper bounds so a hostile psbt cannot turn per-input derivation into a denial of service
# on a 1GHz single core.
MAX_TOTAL_INPUTS = 800
MAX_TOTAL_OUTPUTS = 800

ACCEPTABLE_SIGHASHES = (None, SIGHASH.ALL, SIGHASH.DEFAULT)


class CoinjoinPolicyError(Exception):
    """A round was refused. The message is written to be shown on the device screen."""
    pass


class CoinjoinAuthorization:
    """
    What the user approved, and what is left of it.

    `account_path` is the derivation prefix the user authorized (e.g. m/84'/0'/0'). Every
    input the device signs in this session must sit under it. This is what keeps a
    coinjoin authorization from reaching the rest of the wallet: cold storage under the
    same seed but a different account is out of scope by construction, not by hoping the
    coordinator does not ask.
    """

    def __init__(
        self,
        coordinator: str,
        account_path: list[int],
        max_rounds: int,
        max_fee_per_round_sat: int,
        max_total_fee_sat: int,
        network: str = SettingsConstants.MAINNET,
    ):
        if max_rounds <= 0:
            raise ValueError("max_rounds must be positive")
        if max_fee_per_round_sat < 0 or max_total_fee_sat < 0:
            raise ValueError("fee budgets cannot be negative")
        if not account_path:
            raise ValueError("account_path is required")

        self.coordinator = coordinator
        self.account_path = list(account_path)
        self.max_rounds = max_rounds
        self.max_fee_per_round_sat = max_fee_per_round_sat
        self.max_total_fee_sat = max_total_fee_sat
        self.network = network

        self.rounds_used = 0
        self.total_fee_spent_sat = 0

    @property
    def rounds_remaining(self) -> int:
        return self.max_rounds - self.rounds_used

    @property
    def fee_remaining_sat(self) -> int:
        return self.max_total_fee_sat - self.total_fee_spent_sat

    @property
    def is_live(self) -> bool:
        return self.rounds_remaining > 0 and self.fee_remaining_sat >= 0

    def consume(self, fee_sat: int) -> None:
        """
        Charge a completed round against the budget.

        Called only after a signature has actually been produced. Charging on validation
        instead would let a coordinator burn the budget with rounds it never signs.
        """
        self.rounds_used += 1
        self.total_fee_spent_sat += max(0, fee_sat)

    def describe(self) -> str:
        return (
            f"{self.coordinator}: {self.rounds_remaining}/{self.max_rounds} rounds, "
            f"{self.fee_remaining_sat} sats left"
        )


class CoinjoinRoundSummary:
    """The device's own reading of a round, produced by validate()."""

    def __init__(self, our_input_sat: int, our_output_sat: int, our_input_indexes: list[int],
                 our_output_indexes: list[int], foreign_input_count: int):
        self.our_input_sat = our_input_sat
        self.our_output_sat = our_output_sat
        self.our_input_indexes = our_input_indexes
        self.our_output_indexes = our_output_indexes
        self.foreign_input_count = foreign_input_count

    @property
    def our_fee_sat(self) -> int:
        """What this round costs us: value in minus value back. Negative means we gained."""
        return self.our_input_sat - self.our_output_sat


def _is_under_account(path: list[int], account_path: list[int]) -> bool:
    return len(path) >= len(account_path) and list(path[: len(account_path)]) == list(account_path)


def _script_for_key(script_type: str, key) -> "script.Script | None":
    """Rebuild the scriptPubKey a given key would be paid through, for the single-sig types."""
    if script_type == "p2wpkh":
        return script.p2wpkh(key)
    if script_type == "p2sh":
        # The only p2sh shape a single-sig coinjoin wallet uses is a wrapped p2wpkh.
        return script.p2sh(script.p2wpkh(key))
    if script_type == "p2pkh":
        return script.p2pkh(key)
    if script_type == "p2tr":
        return script.p2tr(key)
    return None


def _pays_our_key(script_pubkey, path: list[int], root: bip32.HDKey, cache: dict) -> bool:
    """
    Check that `script_pubkey` is actually built from the key at `path`.

    This is the check that makes an ownership claim mean something. A psbt scope's
    derivation entries say "this key belongs to your seed" -- and re-deriving the key
    proves that much -- but they say nothing about whether the output being paid has
    anything to do with that key. A coordinator can attach a genuine claim of ours to an
    output whose scriptPubKey pays a stranger. A device that stopped at the claim would
    count that stranger's output as its own money coming back, compute a tiny fee, and
    sign the round away. So the claim is only accepted once the script it is attached to
    has been rebuilt from the key and compared byte for byte.

    Anything that is not one of the single-sig shapes above returns False: a coinjoin the
    device cannot reconstruct is one it will not sign unattended.
    """
    key = PSBTParser._derive_with_cache(root, path, cache)
    expected = _script_for_key(script_pubkey.script_type(), key)
    return expected is not None and expected.data == script_pubkey.data


def validate_coinjoin_psbt(
    psbt: PSBT,
    seed: Seed,
    authorization: CoinjoinAuthorization,
) -> CoinjoinRoundSummary:
    """
    Decide whether this round may be signed unattended. Raises CoinjoinPolicyError if not.

    Every value used in a decision here is one the device re-derived or read out of a
    previous transaction it hashed itself. Nothing the coordinator merely asserts is
    allowed to move a number.
    """
    if not authorization.is_live:
        raise CoinjoinPolicyError("Coinjoin authorization is used up")

    inputs = psbt.inputs
    outputs = psbt.outputs
    vout = psbt.tx.vout

    if not (MIN_TOTAL_INPUTS <= len(inputs) <= MAX_TOTAL_INPUTS):
        raise CoinjoinPolicyError(
            f"Round has {len(inputs)} inputs; expected {MIN_TOTAL_INPUTS}-{MAX_TOTAL_INPUTS}"
        )
    if not (MIN_TOTAL_OUTPUTS <= len(outputs) <= MAX_TOTAL_OUTPUTS):
        raise CoinjoinPolicyError(
            f"Round has {len(outputs)} outputs; expected {MIN_TOTAL_OUTPUTS}-{MAX_TOTAL_OUTPUTS}"
        )
    if len(outputs) != len(vout):
        raise CoinjoinPolicyError("psbt output count does not match its transaction")

    # A repeated outpoint would let the same value be counted twice on the way in.
    outpoints = [(bytes(inp.txid), inp.vout) for inp in inputs]
    if len(set(outpoints)) != len(outpoints):
        raise CoinjoinPolicyError("Round spends the same outpoint twice")

    root = bip32.HDKey.from_seed(
        seed.seed_bytes,
        version=NETWORKS[
            SettingsConstants.map_network_to_embit(authorization.network)
        ]["xprv"],
    )
    derivation_cache: dict = {}

    # Ownership. _get_seed_derivation_path re-derives every key that claims this seed's
    # fingerprint and raises if the claim does not hold, so a coordinator cannot dress a
    # foreign output up as ours to make the value check balance.
    our_input_indexes: list[int] = []
    our_input_sat = 0
    for i, inp in enumerate(inputs):
        path = PSBTParser._get_seed_derivation_path(inp, root, derivation_cache)
        if path is None:
            continue

        if not _is_under_account(path, authorization.account_path):
            raise CoinjoinPolicyError(
                f"Input {i} at {bip32.path_to_str(path)} is outside the authorized account "
                f"{bip32.path_to_str(authorization.account_path)}"
            )

        utxo = inp.utxo
        if utxo is None:
            raise CoinjoinPolicyError(f"Input {i} carries no utxo to read its value from")

        if not _pays_our_key(utxo.script_pubkey, path, root, derivation_cache):
            raise CoinjoinPolicyError(
                f"Input {i} claims one of our keys but is not paid to it"
            )

        if inp.sighash_type not in ACCEPTABLE_SIGHASHES:
            raise CoinjoinPolicyError(f"Input {i} requests a non-standard sighash")

        # The miner-fee attack: for pre-taproot inputs the sighash commits only to the
        # amount of the input being signed, so a coordinator that lies about our input
        # values can steer the difference into the fee. embit's inp.verify() re-hashes the
        # supplied previous transaction and checks it against the outpoint, which is what
        # makes the amount real. Taproot's sighash commits to every spent amount, so a lie
        # there simply produces an invalid signature and witness_utxo alone is safe.
        if utxo.script_pubkey.script_type() != "p2tr":
            if inp.non_witness_utxo is None:
                raise CoinjoinPolicyError(
                    f"Input {i} is missing its previous transaction; "
                    "SabiSigner requires it to trust the amount"
                )
            inp.verify()  # raises PSBTError on a txid mismatch

        our_input_indexes.append(i)
        our_input_sat += utxo.value

    if not our_input_indexes:
        raise CoinjoinPolicyError("Round contains none of this wallet's inputs")

    foreign_input_count = len(inputs) - len(our_input_indexes)
    if foreign_input_count < MIN_FOREIGN_INPUTS:
        raise CoinjoinPolicyError(
            f"Only {foreign_input_count} other participants' inputs; "
            f"a mix needs at least {MIN_FOREIGN_INPUTS}"
        )

    our_output_indexes: list[int] = []
    our_output_sat = 0
    for i, out in enumerate(outputs):
        path = PSBTParser._get_seed_derivation_path(out, root, derivation_cache)
        if path is None:
            continue
        if not _is_under_account(path, authorization.account_path):
            raise CoinjoinPolicyError(
                f"Output {i} at {bip32.path_to_str(path)} is outside the authorized account"
            )
        if not _pays_our_key(vout[i].script_pubkey, path, root, derivation_cache):
            raise CoinjoinPolicyError(
                f"Output {i} claims one of our keys but pays a different script"
            )
        our_output_indexes.append(i)
        our_output_sat += vout[i].value

    summary = CoinjoinRoundSummary(
        our_input_sat=our_input_sat,
        our_output_sat=our_output_sat,
        our_input_indexes=our_input_indexes,
        our_output_indexes=our_output_indexes,
        foreign_input_count=foreign_input_count,
    )

    # The value test. Everything above exists so that these two numbers mean something.
    if summary.our_fee_sat > authorization.max_fee_per_round_sat:
        raise CoinjoinPolicyError(
            f"Round costs {summary.our_fee_sat} sats, over the "
            f"{authorization.max_fee_per_round_sat} sats/round limit"
        )
    if summary.our_fee_sat > authorization.fee_remaining_sat:
        raise CoinjoinPolicyError(
            f"Round costs {summary.our_fee_sat} sats, over the "
            f"{authorization.fee_remaining_sat} sats left in this session's budget"
        )

    return summary


def _signature_keys(inp) -> set:
    """The set of public keys this input already carries a signature for."""
    return set(inp.partial_sigs.keys()) | set(inp.taproot_sigs.keys())


def sign_coinjoin_round(psbt: PSBT, seed: Seed, authorization: CoinjoinAuthorization) -> tuple[PSBT, CoinjoinRoundSummary]:
    """
    Validate and sign one round, then charge it against the budget.

    The post-signing check is not redundant with validate(). embit's sign_with decides
    what to sign on its own, and its ownership test is looser than ours in one corner
    (it compares ecdsa keys x-only). Rather than reason about whether that gap is
    reachable, the signed result is checked against the set of inputs the policy actually
    approved, and a *new* signature anywhere else discards the whole round.

    "New" is the load-bearing word. By the time a round reaches the device the coordinator
    has usually collected other participants' signatures already, so the psbt arrives with
    signatures on inputs that are not ours and never will be. Rejecting on their mere
    presence would refuse every real round.
    """
    summary = validate_coinjoin_psbt(psbt, seed, authorization)

    root = bip32.HDKey.from_seed(
        seed.seed_bytes,
        version=NETWORKS[
            SettingsConstants.map_network_to_embit(authorization.network)
        ]["xprv"],
    )
    # embit resolves the sighash per input type from its default: DEFAULT for taproot,
    # ALL for everything else. Forcing ALL here would make taproot signatures carry an
    # explicit sighash byte for no reason.
    signatures_before = [_signature_keys(inp) for inp in psbt.inputs]

    psbt.sign_with(root)

    approved = set(summary.our_input_indexes)
    for i, inp in enumerate(psbt.inputs):
        if i in approved:
            continue
        if _signature_keys(inp) - signatures_before[i]:
            raise CoinjoinPolicyError(
                f"Refusing round: a signature landed on input {i}, which the policy did not approve"
            )

    if not any(_signature_keys(psbt.inputs[i]) - signatures_before[i] for i in approved):
        raise CoinjoinPolicyError("Round produced no signatures")

    authorization.consume(summary.our_fee_sat)
    logger.info(
        "coinjoin round signed: %d sats fee, %s",
        summary.our_fee_sat,
        authorization.describe(),
    )
    return psbt, summary
