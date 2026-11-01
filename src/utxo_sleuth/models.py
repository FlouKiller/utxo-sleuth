"""Chain data, parsed from Esplora's JSON into the fields the heuristics use."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# A sequence below this value signals replace-by-fee (BIP 125).
RBF_SEQUENCE_LIMIT = 0xFFFFFFFE

_MULTISIG = re.compile(r"^OP_PUSHNUM_(\d+) .* OP_PUSHNUM_(\d+) OP_CHECKMULTISIG$")


def _multisig_policy(vin: dict[str, Any]) -> str | None:
    """"2-of-3" when spending needs several signatures, else None."""
    script = vin.get("inner_witnessscript_asm") or vin.get("inner_redeemscript_asm") or ""
    match = _MULTISIG.match(script)
    if match is None or int(match[1]) < 2:
        return None
    return f"{match[1]}-of-{match[2]}"


@dataclass(frozen=True)
class Input:
    address: str | None
    value: int
    script_type: str | None
    sequence: int
    multisig: str | None = None
    prev_txid: str | None = None
    prev_vout: int | None = None


@dataclass(frozen=True)
class Output:
    vout: int
    address: str | None
    value: int
    script_type: str | None


@dataclass(frozen=True)
class Fingerprint:
    """Wallet-software traits visible in a transaction."""

    version: int
    uses_locktime: bool
    signals_rbf: bool


@dataclass(frozen=True)
class Tx:
    txid: str
    version: int
    locktime: int
    fee: int
    inputs: tuple[Input, ...]
    outputs: tuple[Output, ...]
    coinbase: bool = False
    height: int | None = None
    time: int | None = None

    @property
    def input_addresses(self) -> list[str]:
        return list(dict.fromkeys(i.address for i in self.inputs if i.address))

    @property
    def spendable_outputs(self) -> list[Output]:
        return [o for o in self.outputs if o.address]

    @property
    def fingerprint(self) -> Fingerprint:
        return Fingerprint(
            version=self.version,
            uses_locktime=self.locktime > 0,
            signals_rbf=any(i.sequence < RBF_SEQUENCE_LIMIT for i in self.inputs),
        )

    @classmethod
    def from_esplora(cls, data: dict[str, Any]) -> Tx:
        inputs = []
        coinbase = False
        for vin in data["vin"]:
            coinbase = coinbase or bool(vin.get("is_coinbase"))
            prevout = vin.get("prevout") or {}
            inputs.append(
                Input(
                    address=prevout.get("scriptpubkey_address"),
                    value=prevout.get("value", 0),
                    script_type=prevout.get("scriptpubkey_type"),
                    sequence=vin.get("sequence", 0xFFFFFFFF),
                    multisig=_multisig_policy(vin),
                    prev_txid=vin.get("txid"),
                    prev_vout=vin.get("vout"),
                )
            )
        outputs = tuple(
            Output(
                vout=vout,
                address=out.get("scriptpubkey_address"),
                value=out["value"],
                script_type=out.get("scriptpubkey_type"),
            )
            for vout, out in enumerate(data["vout"])
        )
        return cls(
            txid=data["txid"],
            version=data["version"],
            locktime=data["locktime"],
            fee=data.get("fee", 0),
            inputs=tuple(inputs),
            outputs=outputs,
            coinbase=coinbase,
            height=data.get("status", {}).get("block_height"),
            time=data.get("status", {}).get("block_time"),
        )


@dataclass(frozen=True)
class BlockRef:
    hash: str
    height: int
    time: int


@dataclass(frozen=True)
class AddressStats:
    tx_count: int
    funded_count: int

    @classmethod
    def from_esplora(cls, data: dict[str, Any]) -> AddressStats:
        chain, mempool = data["chain_stats"], data["mempool_stats"]
        return cls(
            tx_count=chain["tx_count"] + mempool["tx_count"],
            funded_count=chain["funded_txo_count"] + mempool["funded_txo_count"],
        )
