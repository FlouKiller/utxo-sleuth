from __future__ import annotations

from utxo_sleuth.models import AddressStats, Input, Output, Tx

P2WPKH = "v0_p2wpkh"
P2PKH = "p2pkh"
P2TR = "v1_p2tr"


def tx(
    txid,
    inputs,
    outputs,
    fee=1_000,
    version=2,
    locktime=0,
    input_type=P2WPKH,
    height=None,
    multisig=None,
):
    """Build a transaction from (address, value) pairs; an output may add a type."""
    return Tx(
        txid=txid,
        version=version,
        locktime=locktime,
        fee=fee,
        height=height,
        inputs=tuple(
            Input(address, value, input_type, 0xFFFFFFFF, multisig)
            for address, value in inputs
        ),
        outputs=tuple(
            Output(vout, spec[0], spec[1], spec[2] if len(spec) > 2 else P2WPKH)
            for vout, spec in enumerate(outputs)
        ),
    )


class FakeApi:
    """An in-memory chain: an address's history is derived from the transactions."""

    def __init__(self, *txs, spenders=None, funded=None):
        self.txs = {t.txid: t for t in txs}
        self.spenders = spenders or {}
        self.funded = funded or {}
        self.calls = 0

    def tx(self, txid):
        self.calls += 1
        return self.txs[txid]

    def outspends(self, txid):
        self.calls += 1
        return [
            self.spenders.get((txid, o.vout)) for o in self.txs[txid].outputs
        ]

    def address_stats(self, address):
        self.calls += 1
        history = self._history(address)
        funded = sum(address in [o.address for o in t.outputs] for t in history)
        return AddressStats(len(history), self.funded.get(address, funded))

    def address_txs(self, address, expected):
        self.calls += 1
        return self._history(address)

    def _history(self, address):
        return [
            t
            for t in self.txs.values()
            if address in t.input_addresses
            or address in [o.address for o in t.outputs]
        ]
