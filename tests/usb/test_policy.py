"""
The checks that decide whether a round signs without a human looking at it.

Each test bends exactly one thing about an otherwise-valid round, so a failure here names
the check that stopped working rather than "coinjoin broke".
"""
import pytest

from seedsigner.usb import policy
from seedsigner.usb.policy import CoinjoinAuthorization, CoinjoinPolicyError

from usb.coinjoin_util import ACCOUNT_PATH, OTHER_ACCOUNT_PATH, RoundBuilder, make_seed, standard_round


@pytest.fixture
def seed():
    return make_seed()


@pytest.fixture
def auth():
    return CoinjoinAuthorization(
        coordinator="wasabi.test",
        account_path=ACCOUNT_PATH,
        max_rounds=10,
        max_fee_per_round_sat=5_000,
        max_total_fee_sat=20_000,
    )


# -- the happy path ---------------------------------------------------------------------

def test_a_normal_round_validates(seed, auth):
    summary = policy.validate_coinjoin_psbt(standard_round(seed), seed, auth)
    assert summary.our_input_sat == 100_000
    assert summary.our_output_sat == 99_000
    assert summary.our_fee_sat == 1_000
    assert summary.foreign_input_count == 5


def test_a_normal_round_signs_and_charges_the_budget(seed, auth):
    _signed, summary = policy.sign_coinjoin_round(standard_round(seed), seed, auth)
    assert summary.our_fee_sat == 1_000
    assert auth.rounds_used == 1
    assert auth.rounds_remaining == 9
    assert auth.fee_remaining_sat == 19_000


def test_signing_actually_produces_a_signature(seed, auth):
    signed, summary = policy.sign_coinjoin_round(standard_round(seed), seed, auth)
    for i in summary.our_input_indexes:
        assert signed.inputs[i].partial_sigs, f"input {i} was not signed"
    for i in range(len(signed.inputs)):
        if i not in summary.our_input_indexes:
            assert not signed.inputs[i].partial_sigs, f"input {i} should not have been signed"


def test_multiple_of_our_inputs_are_all_counted(seed, auth):
    builder = RoundBuilder(seed)
    builder.add_our_input(50_000, index=0)
    builder.add_our_input(50_000, index=1)
    for _ in range(5):
        builder.add_foreign_input()
    builder.add_our_output(99_000)
    for _ in range(5):
        builder.add_foreign_output()

    summary = policy.validate_coinjoin_psbt(builder.build(), seed, auth)
    assert summary.our_input_sat == 100_000
    assert len(summary.our_input_indexes) == 2


# -- the value check --------------------------------------------------------------------

def test_a_round_that_costs_more_than_the_per_round_limit_is_refused(seed, auth):
    # 100k in, 90k back: a 10k fee against a 5k limit.
    psbt = standard_round(seed, our_in=100_000, our_out=90_000)
    with pytest.raises(CoinjoinPolicyError, match="sats/round limit"):
        policy.validate_coinjoin_psbt(psbt, seed, auth)


def test_a_round_that_returns_nothing_to_us_is_refused(seed, auth):
    """The bare drain: our input goes in, nothing comes back."""
    builder = RoundBuilder(seed)
    builder.add_our_input(100_000)
    for _ in range(5):
        builder.add_foreign_input()
    for _ in range(6):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="sats/round limit"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


def test_the_session_budget_stops_a_slow_drain(seed):
    """
    Each round is individually within the per-round limit, but the session budget is what
    bounds the total. Without it a coordinator could bleed the wallet a legal round at a
    time for as many rounds as were authorized.
    """
    auth = CoinjoinAuthorization(
        coordinator="wasabi.test",
        account_path=ACCOUNT_PATH,
        max_rounds=100,
        max_fee_per_round_sat=1_000,
        max_total_fee_sat=2_500,
    )
    for _ in range(2):
        policy.sign_coinjoin_round(standard_round(seed), seed, auth)
    assert auth.fee_remaining_sat == 500

    with pytest.raises(CoinjoinPolicyError, match="left in this session's budget"):
        policy.validate_coinjoin_psbt(standard_round(seed), seed, auth)


def test_a_round_where_we_gain_value_is_allowed(seed, auth):
    summary = policy.validate_coinjoin_psbt(
        standard_round(seed, our_in=100_000, our_out=101_000), seed, auth
    )
    assert summary.our_fee_sat == -1_000


def test_the_budget_is_never_credited_by_a_gaining_round(seed, auth):
    """A negative fee must not top the budget back up."""
    policy.sign_coinjoin_round(standard_round(seed, our_in=100_000, our_out=101_000), seed, auth)
    assert auth.fee_remaining_sat == 20_000


# -- account scoping --------------------------------------------------------------------

def test_an_input_outside_the_authorized_account_refuses_the_whole_round(seed, auth):
    """
    The reason account_path exists. Authorizing coinjoin on one account must not become
    authorization to spend cold storage held under the same seed.
    """
    builder = RoundBuilder(seed)
    builder.add_our_input(100_000, path=OTHER_ACCOUNT_PATH + [0, 0])
    for _ in range(5):
        builder.add_foreign_input()
    builder.add_our_output(99_000)
    for _ in range(5):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="outside the authorized account"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


def test_a_mixed_round_touching_another_account_is_refused_entirely(seed, auth):
    """Not partially signed: refused. One bad input poisons the round."""
    builder = RoundBuilder(seed)
    builder.add_our_input(50_000, index=0)
    builder.add_our_input(50_000, path=OTHER_ACCOUNT_PATH + [0, 0])
    for _ in range(5):
        builder.add_foreign_input()
    builder.add_our_output(99_000)
    for _ in range(5):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="outside the authorized account"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


def test_an_output_outside_the_authorized_account_is_refused(seed, auth):
    builder = RoundBuilder(seed)
    builder.add_our_input(100_000)
    for _ in range(5):
        builder.add_foreign_input()
    builder.add_our_output(99_000, path=OTHER_ACCOUNT_PATH + [1, 0])
    for _ in range(5):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="outside the authorized account"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


# -- it has to actually be a mix --------------------------------------------------------

def test_a_round_with_too_few_other_participants_is_refused(seed, auth):
    """
    Enough inputs in total to clear the size floor, but not enough of them belong to
    anyone else. Padding a round with the user's own coins does not make it a mix.
    """
    builder = RoundBuilder(seed)
    builder.add_our_input(50_000, index=0)
    builder.add_our_input(50_000, index=1)
    for _ in range(policy.MIN_FOREIGN_INPUTS - 1):
        builder.add_foreign_input()
    builder.add_our_output(99_000)
    for _ in range(5):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="other participants"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


def test_a_solo_spend_dressed_as_a_coinjoin_is_refused(seed, auth):
    """
    All inputs ours, enough of them to clear the total-input floor. Only the foreign-input
    check stands between this and an unattended signature on a transaction the user never
    saw.
    """
    builder = RoundBuilder(seed)
    for i in range(6):
        builder.add_our_input(20_000, index=i)
    builder.add_our_output(119_000)
    for _ in range(5):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="other participants"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


def test_a_round_containing_none_of_our_inputs_is_refused(seed, auth):
    builder = RoundBuilder(seed)
    for _ in range(6):
        builder.add_foreign_input()
    for _ in range(6):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="none of this wallet's inputs"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


def test_too_few_inputs_is_refused(seed, auth):
    builder = RoundBuilder(seed)
    builder.add_our_input(100_000)
    for _ in range(3):
        builder.add_foreign_input()
    builder.add_our_output(99_000)
    for _ in range(5):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="inputs; expected"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


def test_too_few_outputs_is_refused(seed, auth):
    builder = RoundBuilder(seed)
    builder.add_our_input(100_000)
    for _ in range(5):
        builder.add_foreign_input()
    builder.add_our_output(99_000)
    for _ in range(2):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="outputs; expected"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


# -- amounts have to be provable --------------------------------------------------------

def test_a_segwit_input_without_its_previous_transaction_is_refused(seed, auth):
    """
    The miner-fee attack. A pre-taproot sighash commits only to the amount of the input
    being signed, so an unverifiable amount is an amount the coordinator picks.
    """
    builder = RoundBuilder(seed)
    builder.add_our_input(100_000, include_prev_tx=False)
    for _ in range(5):
        builder.add_foreign_input()
    builder.add_our_output(99_000)
    for _ in range(5):
        builder.add_foreign_output()

    with pytest.raises(CoinjoinPolicyError, match="missing its previous transaction"):
        policy.validate_coinjoin_psbt(builder.build(), seed, auth)


def test_a_previous_transaction_that_does_not_match_the_outpoint_is_refused(seed, auth):
    from embit.psbt import PSBTError

    psbt = standard_round(seed)
    ours = next(i for i, inp in enumerate(psbt.inputs) if inp.bip32_derivations)
    # Swap in a previous transaction for a different outpoint: the amount it claims is now
    # unmoored from the input being spent.
    other = standard_round(seed)
    psbt.inputs[ours].non_witness_utxo = other.inputs[0].non_witness_utxo

    with pytest.raises(PSBTError, match="doesn't match"):
        policy.validate_coinjoin_psbt(psbt, seed, auth)


def test_a_duplicated_outpoint_is_refused(seed, auth):
    psbt = standard_round(seed)
    psbt.tx.vin[2].txid = psbt.tx.vin[1].txid
    psbt.tx.vin[2].vout = psbt.tx.vin[1].vout
    psbt.inputs[2].txid = psbt.inputs[1].txid
    psbt.inputs[2].vout = psbt.inputs[1].vout

    with pytest.raises(CoinjoinPolicyError, match="same outpoint twice"):
        policy.validate_coinjoin_psbt(psbt, seed, auth)


def test_a_forged_ownership_claim_on_an_output_is_rejected(seed, auth):
    """
    A coordinator claiming one of its own outputs is ours would make the value check
    balance on money we never receive. The claim is re-derived, so it fails.
    """
    from seedsigner.models.psbt_parser import PSBTOutputOwnershipClaimError
    from embit.psbt import DerivationPath

    from usb.coinjoin_util import make_root

    psbt = standard_round(seed)
    root = make_root(seed)
    foreign_index = next(i for i, out in enumerate(psbt.outputs) if not out.bip32_derivations)
    # Take a real foreign key and staple our fingerprint and a plausible path onto it.
    real_key = root.derive(ACCOUNT_PATH + [1, 7]).get_public_key()
    wrong_key = root.derive(ACCOUNT_PATH + [1, 8]).get_public_key()
    psbt.outputs[foreign_index].bip32_derivations[wrong_key] = DerivationPath(
        root.my_fingerprint, ACCOUNT_PATH + [1, 7]
    )
    assert real_key != wrong_key

    with pytest.raises(PSBTOutputOwnershipClaimError):
        policy.validate_coinjoin_psbt(psbt, seed, auth)


# -- the authorization itself -----------------------------------------------------------

def test_rounds_run_out(seed):
    auth = CoinjoinAuthorization(
        coordinator="wasabi.test",
        account_path=ACCOUNT_PATH,
        max_rounds=2,
        max_fee_per_round_sat=5_000,
        max_total_fee_sat=50_000,
    )
    policy.sign_coinjoin_round(standard_round(seed), seed, auth)
    policy.sign_coinjoin_round(standard_round(seed), seed, auth)
    assert not auth.is_live

    with pytest.raises(CoinjoinPolicyError, match="used up"):
        policy.validate_coinjoin_psbt(standard_round(seed), seed, auth)


def test_a_refused_round_does_not_consume_the_budget(seed, auth):
    """A coordinator must not be able to burn the authorization with rounds it never signs."""
    with pytest.raises(CoinjoinPolicyError):
        policy.validate_coinjoin_psbt(standard_round(seed, our_in=100_000, our_out=1), seed, auth)
    assert auth.rounds_used == 0
    assert auth.fee_remaining_sat == 20_000


def test_authorization_rejects_nonsense_at_construction():
    with pytest.raises(ValueError):
        CoinjoinAuthorization("c", ACCOUNT_PATH, max_rounds=0, max_fee_per_round_sat=1, max_total_fee_sat=1)
    with pytest.raises(ValueError):
        CoinjoinAuthorization("c", ACCOUNT_PATH, max_rounds=1, max_fee_per_round_sat=-1, max_total_fee_sat=1)
    with pytest.raises(ValueError):
        CoinjoinAuthorization("c", [], max_rounds=1, max_fee_per_round_sat=1, max_total_fee_sat=1)


def test_account_prefix_matching_is_not_fooled_by_a_shared_prefix(seed):
    """
    m/84'/0'/0' must not authorize m/84'/0'/0 (unhardened) or a sibling that merely starts
    with the same integers.
    """
    assert policy._is_under_account(ACCOUNT_PATH + [0, 0], ACCOUNT_PATH)
    assert policy._is_under_account(ACCOUNT_PATH, ACCOUNT_PATH)
    assert not policy._is_under_account(OTHER_ACCOUNT_PATH + [0, 0], ACCOUNT_PATH)
    assert not policy._is_under_account([84 + 2**31, 0 + 2**31], ACCOUNT_PATH)
    assert not policy._is_under_account([84 + 2**31, 0 + 2**31, 0], ACCOUNT_PATH)
