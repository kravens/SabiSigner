"""
Builds synthetic coinjoin psbts for the policy tests.

Real Wasabi rounds are not available to a test suite, and a fixture captured from one
would only ever exercise the happy path. These builders construct rounds from parts so
each test can bend exactly one thing -- an amount, a derivation path, a missing previous
transaction -- and watch the policy catch it.

Every input carries a real previous transaction whose txid genuinely hashes to the
outpoint, because the checks under test depend on that being verifiable.
"""
import hashlib
import os

from embit import bip32, ec, script
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.models.seed import Seed


TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()
ACCOUNT_PATH = [84 + 2**31, 0 + 2**31, 0 + 2**31]
OTHER_ACCOUNT_PATH = [84 + 2**31, 0 + 2**31, 1 + 2**31]


def make_seed() -> Seed:
    return Seed(TEST_MNEMONIC)


def make_root(seed: Seed) -> bip32.HDKey:
    return bip32.HDKey.from_seed(seed.seed_bytes, version=NETWORKS["main"]["xprv"])


def _p2wpkh(pubkey: ec.PublicKey):
    return script.p2wpkh(pubkey)


def _funding_tx(script_pubkey, value: int) -> Transaction:
    """
    A previous transaction paying `value` to `script_pubkey`.

    Its single input spends a random outpoint that does not exist; nothing in the tests
    walks further back than one hop, and the txid is real either way because it is the
    hash of these bytes.
    """
    vin = [TransactionInput(os.urandom(32), 0)]
    vout = [TransactionOutput(value, script_pubkey)]
    return Transaction(vin=vin, vout=vout)


class RoundBuilder:
    """Accumulates inputs and outputs, then assembles them into a psbt."""

    def __init__(self, seed: Seed, account_path: list[int] = None):
        self.seed = seed
        self.root = make_root(seed)
        self.account_path = account_path or ACCOUNT_PATH
        self._inputs = []    # (funding_tx, vout_index, derivation_path or None)
        self._outputs = []   # (script_pubkey, value, derivation_path or None)

    def add_our_input(self, value: int, index: int = 0, path: list[int] = None,
                      include_prev_tx: bool = True):
        path = path if path is not None else self.account_path + [0, index]
        pubkey = self.root.derive(path).get_public_key()
        funding = _funding_tx(_p2wpkh(pubkey), value)
        self._inputs.append((funding, 0, path, include_prev_tx))
        return self

    def add_foreign_input(self, value: int = 100_000):
        pubkey = ec.PrivateKey(os.urandom(32)).get_public_key()
        funding = _funding_tx(_p2wpkh(pubkey), value)
        self._inputs.append((funding, 0, None, True))
        return self

    def add_our_output(self, value: int, index: int = 0, path: list[int] = None):
        path = path if path is not None else self.account_path + [1, index]
        pubkey = self.root.derive(path).get_public_key()
        self._outputs.append((_p2wpkh(pubkey), value, path))
        return self

    def add_foreign_output(self, value: int = 100_000):
        pubkey = ec.PrivateKey(os.urandom(32)).get_public_key()
        self._outputs.append((_p2wpkh(pubkey), value, None))
        return self

    def build(self) -> PSBT:
        vin = [
            TransactionInput(funding.txid(), vout_index)
            for funding, vout_index, _, _ in self._inputs
        ]
        vout = [TransactionOutput(value, spk) for spk, value, _ in self._outputs]
        psbt = PSBT(Transaction(vin=vin, vout=vout))

        fingerprint = self.root.my_fingerprint

        for i, (funding, vout_index, path, include_prev_tx) in enumerate(self._inputs):
            scope = psbt.inputs[i]
            if include_prev_tx:
                scope.non_witness_utxo = funding
            else:
                scope.witness_utxo = funding.vout[vout_index]
            if path is not None:
                pubkey = self.root.derive(path).get_public_key()
                scope.bip32_derivations[pubkey] = DerivationPath(fingerprint, path)

        for i, (_spk, _value, path) in enumerate(self._outputs):
            if path is not None:
                pubkey = self.root.derive(path).get_public_key()
                psbt.outputs[i].bip32_derivations[pubkey] = DerivationPath(fingerprint, path)

        return psbt


def standard_round(seed: Seed, our_in: int = 100_000, our_out: int = 99_000,
                   foreign: int = 5) -> PSBT:
    """A round that should pass every check: one of ours in, one of ours back, a real mix."""
    builder = RoundBuilder(seed)
    builder.add_our_input(our_in)
    for _ in range(foreign):
        builder.add_foreign_input()
    builder.add_our_output(our_out)
    for _ in range(foreign):
        builder.add_foreign_output()
    return builder.build()
