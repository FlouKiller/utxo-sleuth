"""Decide what a single transaction says about who owns what.

Change detection is a small Bayesian update. Each output starts with the same
weight, plus one weight for "this transaction has no change at all", and each
heuristic multiplies an output's weight by a likelihood ratio. The ratios are
starting guesses until they are calibrated against wallets whose addresses are
known. They are set so that no single heuristic reaches the default threshold.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from utxo_sleuth.models import Fingerprint, Output, Tx

DEFAULT_CHANGE_THRESHOLD = 0.7
NO_CHANGE_WEIGHT = 1.0
MAX_CHANGE_OUTPUTS = 6
ROUND_UNIT_SATS = 1_000
SERVICE_SWEEP_INPUTS = 20

ROUND_OTHER_LR = 3.0
ROUND_SELF_LR = 0.33
SAME_TYPE_LR = 3.0
OTHER_TYPE_LR = 0.33
REUSED_ADDRESS_LR = 0.25
UNNECESSARY_INPUT_LR = 0.4
SAME_WALLET_LR = 1.5
OTHER_WALLET_LR = 0.5
SERVICE_SWEEP_LR = 0.25
RETURNS_TO_INPUTS_LR = 4.0


@dataclass(frozen=True)
class OutputFacts:
    """What the rest of the chain says about one output."""

    reused: bool = False
    spender: Fingerprint | None = None
    spender_inputs: int = 0
    returns_to_inputs: bool = False


@dataclass(frozen=True)
class ChangeGuess:
    address: str
    vout: int
    probability: float
    reasons: tuple[str, ...]


def looks_like_coinjoin(tx: Tx) -> bool:
    """Equal-value outputs, with at least as many input addresses as outputs.

    A false positive only loses a link, while a false negative merges strangers,
    so anything vaguely mix-shaped is treated as a mix.
    """
    outputs = tx.spendable_outputs
    if len(outputs) < 2:
        return False
    _, equal = Counter(o.value for o in outputs).most_common(1)[0]
    return equal >= 2 and len(tx.input_addresses) >= equal


def change_candidates(tx: Tx) -> list[Output]:
    """Outputs worth scoring; empty when change detection does not apply."""
    outputs = tx.spendable_outputs
    if tx.coinbase or not 2 <= len(outputs) <= MAX_CHANGE_OUTPUTS:
        return []
    owned = set(tx.input_addresses)
    # Paying back to an input address already identifies the change.
    if any(o.address in owned for o in outputs):
        return []
    return outputs


def guess_change(
    tx: Tx,
    facts: dict[int, OutputFacts],
    threshold: float = DEFAULT_CHANGE_THRESHOLD,
) -> ChangeGuess | None:
    candidates = change_candidates(tx)
    if not candidates:
        return None

    weights = {o.vout: 1.0 for o in candidates}
    signals: dict[int, list[tuple[float, str]]] = {o.vout: [] for o in candidates}

    def apply(output: Output, ratio: float, reason: str) -> None:
        weights[output.vout] *= ratio
        signals[output.vout].append((ratio, reason))

    _round_amounts(candidates, apply)
    _script_types(tx, candidates, apply)
    _unnecessary_input(tx, candidates, apply)
    _chain_facts(tx, candidates, facts, apply)

    total = sum(weights.values()) + NO_CHANGE_WEIGHT
    best = max(candidates, key=lambda o: weights[o.vout])
    probability = weights[best.vout] / total
    if probability < threshold:
        return None
    return ChangeGuess(
        best.address, best.vout, probability, _evidence(best, candidates, signals)
    )


def _evidence(best, candidates, signals) -> tuple[str, ...]:
    """Mark each signal "+" if it supports the guess, "-" if it goes against it."""
    evidence = []
    for ratio, reason in signals[best.vout]:
        evidence.append(f"{'+' if ratio > 1 else '-'} {reason}")
    for output in candidates:
        if output is not best:
            for ratio, reason in signals[output.vout]:
                evidence.append(f"{'+' if ratio < 1 else '-'} other output: {reason}")
    return tuple(evidence)


def _round_amounts(candidates, apply) -> None:
    rounded = [o for o in candidates if o.value % ROUND_UNIT_SATS == 0]
    if not rounded or len(rounded) == len(candidates):
        return
    for output in candidates:
        if output in rounded:
            apply(output, ROUND_SELF_LR, "round amount, looks like a payment")
        else:
            apply(output, ROUND_OTHER_LR, "another output has a round amount")


def _script_types(tx: Tx, candidates, apply) -> None:
    input_types = {i.script_type for i in tx.inputs}
    output_types = {o.script_type for o in candidates}
    if len(input_types) != 1 or len(output_types) < 2:
        return
    spent_type = next(iter(input_types))
    if spent_type not in output_types:
        return
    for output in candidates:
        if output.script_type == spent_type:
            apply(output, SAME_TYPE_LR, f"same script type as the inputs ({spent_type})")
        else:
            apply(output, OTHER_TYPE_LR, "different script type from the inputs")


def _unnecessary_input(tx: Tx, candidates, apply) -> None:
    """If this output were change, the rest must be the payment, and a wallet
    would not add an input the payment did not need."""
    values = [i.value for i in tx.inputs]
    if len(values) < 2:
        return
    without_smallest = sum(values) - min(values)
    total_out = sum(o.value for o in candidates)
    for output in candidates:
        payment = total_out - output.value
        if without_smallest >= payment + tx.fee:
            apply(output, UNNECESSARY_INPUT_LR, "would make an input unnecessary")


def _chain_facts(tx: Tx, candidates, facts, apply) -> None:
    for output in candidates:
        fact = facts.get(output.vout)
        if fact is None:
            continue
        if fact.reused:
            apply(output, REUSED_ADDRESS_LR, "address was already funded before this transaction")
        if fact.spender is not None:
            if fact.spender == tx.fingerprint:
                apply(output, SAME_WALLET_LR, "spent with the same wallet fingerprint")
            else:
                apply(output, OTHER_WALLET_LR, "spent with a different wallet fingerprint")
        if fact.spender_inputs >= SERVICE_SWEEP_INPUTS:
            apply(
                output,
                SERVICE_SWEEP_LR,
                f"later swept with {fact.spender_inputs - 1} other inputs, "
                "looks like a service deposit",
            )
        if fact.returns_to_inputs:
            apply(output, RETURNS_TO_INPUTS_LR, "funds came back to the sender")
