"""Walk the transaction graph outward from a seed address.

The walk is best-first: the most trusted address is always expanded next, and
a link's confidence multiplies along the path, so doubt accumulates with
distance. Keeping scores instead of merging addresses outright is what stops
one bad link from swallowing an exchange's whole cluster.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Protocol

from utxo_sleuth.esplora import BudgetExceeded
from utxo_sleuth.heuristics import (
    DEFAULT_CHANGE_THRESHOLD,
    ChangeGuess,
    OutputFacts,
    change_candidates,
    guess_change,
    looks_like_coinjoin,
)
from utxo_sleuth.models import AddressStats, Tx

COMMON_INPUT = "common_input"
CONSOLIDATION = "consolidation"
SWEEP = "sweep"
CHANGE = "change"

RECEIVED_FROM = "received_from"
SENT_TO = "sent_to"

COMMON_INPUT_CONFIDENCE = 0.95
# Lower than common inputs: "send max" to someone else has the same shape.
CONSOLIDATION_CONFIDENCE = 0.75
SWEEP_CONFIDENCE = 0.5

# Past this, an address is plainly reused and its history is not worth fetching.
MAX_REUSE_LOOKUP = 50
# Paying this many addresses at once is what an exchange withdrawal looks like.
BATCH_OUTPUTS = 10
# Smaller batches also count when the sender behaves like a hot wallet.
HOT_WALLET_OUTPUTS = 5
HOT_WALLET_TXS = 50


class ChainApi(Protocol):
    def tx(self, txid: str) -> Tx: ...
    def outspends(self, txid: str) -> list[str | None]: ...
    def address_stats(self, address: str) -> AddressStats: ...
    def address_txs(self, address: str, expected: int) -> list[Tx]: ...


@dataclass(frozen=True)
class Limits:
    max_hops: int = 3
    min_confidence: float = 0.3
    max_addresses: int = 200
    max_address_txs: int = 500
    max_inputs: int = 100
    change_threshold: float = DEFAULT_CHANGE_THRESHOLD


@dataclass(frozen=True)
class Link:
    source: str
    target: str
    kind: str
    confidence: float
    txid: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceContact:
    """A cluster address dealing with a service, which says nothing of ownership."""

    address: str
    service: str
    direction: str
    txid: str


@dataclass
class Member:
    address: str
    confidence: float
    hops: int
    via: Link | None = None
    core: bool = False


@dataclass
class Report:
    seed: str
    members: dict[str, Member] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    services: list[ServiceContact] = field(default_factory=list)
    boundaries: dict[str, str] = field(default_factory=dict)
    skipped_txs: dict[str, str] = field(default_factory=dict)
    unexpanded: int = 0
    truncated: str | None = None


class Tracer:
    def __init__(self, api: ChainApi, limits: Limits = Limits(), tags=None) -> None:
        self.api = api
        self.limits = limits
        self.tags = tags if tags is not None else {}
        self._guesses: dict[str, ChangeGuess | None] = {}

    def trace(self, seed: str) -> Report:
        report = Report(seed=seed)
        report.members[seed] = Member(seed, 1.0, 0)
        queue: list[tuple[float, int, str]] = [(-1.0, 0, seed)]
        expanded: set[str] = set()
        seen_links: set[Link] = set()
        try:
            while queue:
                _, _, address = heapq.heappop(queue)
                if address in expanded:
                    continue
                expanded.add(address)
                self._expand(address, report, queue, seen_links)
        except BudgetExceeded as exc:
            report.truncated = str(exc)
        _mark_core(report)
        report.links = [
            link
            for link in report.links
            if link.source in report.members and link.target in report.members
        ]
        return report

    def _expand(self, address, report, queue, seen_links) -> None:
        member = report.members[address]
        if address in self.tags:
            report.boundaries[address] = f"tagged: {self.tags[address]}"
            return
        if member.hops >= self.limits.max_hops:
            report.unexpanded += 1
            return
        stats = self.api.address_stats(address)
        if stats.tx_count > self.limits.max_address_txs:
            report.boundaries[address] = f"{stats.tx_count} transactions, likely a service"
            return
        txs = self.api.address_txs(address, stats.tx_count)
        for tx in txs:
            self._note_services(address, tx, report)
        policy = _multisig_policy_of(address, txs)
        if policy is not None:
            report.boundaries[address] = f"{policy} multisig, possibly shared"
            return
        for tx in txs:
            for link in self._links(address, tx, report):
                if link not in seen_links:
                    seen_links.add(link)
                    report.links.append(link)
                self._admit(link, member, report, queue)

    def _note_services(self, address: str, tx: Tx, report: Report) -> None:
        inputs = tx.input_addresses
        outputs = [o.address for o in tx.spendable_outputs]
        contacts = []
        if address in inputs:
            contacts = [
                ServiceContact(address, self.tags[o], SENT_TO, tx.txid)
                for o in outputs
                if o in self.tags
            ]
        elif address in outputs:
            senders = dict.fromkeys(self.tags[i] for i in inputs if i in self.tags)
            contacts = [
                ServiceContact(address, sender, RECEIVED_FROM, tx.txid) for sender in senders
            ]
            if not contacts and self._is_payout(inputs, outputs):
                name = f"unknown service (payout to {len(outputs)} addresses)"
                contacts = [ServiceContact(address, name, RECEIVED_FROM, tx.txid)]
        for contact in contacts:
            if contact not in report.services:
                report.services.append(contact)

    def _is_payout(self, inputs: list[str], outputs: list[str]) -> bool:
        if len(outputs) >= BATCH_OUTPUTS:
            return True
        if len(outputs) < HOT_WALLET_OUTPUTS or not inputs:
            return False
        if set(inputs) & set(outputs):
            return True
        return self.api.address_stats(inputs[0]).tx_count >= HOT_WALLET_TXS

    def _admit(self, link, source, report, queue) -> None:
        confidence = source.confidence * link.confidence
        if confidence < self.limits.min_confidence:
            return
        known = report.members.get(link.target)
        if known is not None:
            if confidence > known.confidence:
                known.confidence = confidence
                known.hops = source.hops + 1
                known.via = link
                heapq.heappush(queue, (-confidence, known.hops, known.address))
            return
        if len(report.members) >= self.limits.max_addresses:
            report.truncated = f"address limit of {self.limits.max_addresses} reached"
            return
        hops = source.hops + 1
        report.members[link.target] = Member(link.target, confidence, hops, link)
        heapq.heappush(queue, (-confidence, hops, link.target))

    def _links(self, address: str, tx: Tx, report: Report) -> list[Link]:
        inputs = tx.input_addresses
        if not inputs:
            return []
        if looks_like_coinjoin(tx):
            report.skipped_txs[tx.txid] = "looks like a CoinJoin"
            return []
        if len(inputs) > self.limits.max_inputs:
            report.skipped_txs[tx.txid] = f"{len(inputs)} input addresses, likely a service"
            return []

        links = self._owner_links(address, tx, inputs)
        # Spending together proves a shared wallet. Anything weaker that points at
        # a known service is a customer dealing with it, not the service's owner.
        return [
            link for link in links if link.kind == COMMON_INPUT or link.target not in self.tags
        ]

    def _owner_links(self, address: str, tx: Tx, inputs: list[str]) -> list[Link]:
        spends = address in inputs
        links = []
        if spends:
            links += _star(address, inputs, COMMON_INPUT, COMMON_INPUT_CONFIDENCE, tx.txid)

        outputs = tx.spendable_outputs
        if len(outputs) == 1:
            kind, confidence = (
                (CONSOLIDATION, CONSOLIDATION_CONFIDENCE)
                if len(inputs) > 1
                else (SWEEP, SWEEP_CONFIDENCE)
            )
            reasons = tuple(
                f"- spent from a {i.multisig} multisig, possibly shared"
                for i in tx.inputs
                if i.multisig
            )
            receiver = outputs[0].address
            if spends:
                links += _star(address, [receiver], kind, confidence, tx.txid, reasons)
            elif address == receiver:
                links += _star(address, inputs, kind, confidence, tx.txid, reasons)
            return links

        guess = self._change(tx)
        if guess is not None:
            if spends:
                targets = [guess.address]
            elif address == guess.address:
                targets = inputs
            else:
                targets = []
            links += _star(
                address, targets, CHANGE, guess.probability, tx.txid, guess.reasons
            )
        return links

    def _change(self, tx: Tx) -> ChangeGuess | None:
        if tx.txid not in self._guesses:
            self._guesses[tx.txid] = guess_change(
                tx, self._facts(tx), self.limits.change_threshold
            )
        return self._guesses[tx.txid]

    def _facts(self, tx: Tx) -> dict[int, OutputFacts]:
        candidates = change_candidates(tx)
        if not candidates:
            return {}
        owned = set(tx.input_addresses)
        spenders = self.api.outspends(tx.txid)
        facts = {}
        for output in candidates:
            spender_id = spenders[output.vout] if output.vout < len(spenders) else None
            spender = self.api.tx(spender_id) if spender_id else None
            facts[output.vout] = OutputFacts(
                reused=self._funded_before(output.address, tx),
                spender=spender.fingerprint if spender else None,
                spender_inputs=len(spender.inputs) if spender else 0,
                returns_to_inputs=bool(
                    spender and owned & {o.address for o in spender.spendable_outputs}
                ),
            )
        return facts

    def _funded_before(self, address: str, tx: Tx) -> bool:
        """Change must be fresh when created; what lands on it later is irrelevant.

        Blocks do not order their own transactions here, so a funding earlier in
        the same block does not count.
        """
        stats = self.api.address_stats(address)
        if stats.funded_count <= 1:
            return False
        if stats.funded_count > MAX_REUSE_LOOKUP or tx.height is None:
            return True
        return any(
            other.height is not None
            and other.height < tx.height
            and address in [o.address for o in other.outputs]
            for other in self.api.address_txs(address, stats.tx_count)
        )


def _multisig_policy_of(address: str, txs: list[Tx]) -> str | None:
    """An address only reveals its script when it spends."""
    for tx in txs:
        for spent in tx.inputs:
            if spent.address == address and spent.multisig:
                return spent.multisig
    return None


def _star(address, targets, kind, confidence, txid, reasons=()) -> list[Link]:
    return [
        Link(address, target, kind, confidence, txid, tuple(reasons))
        for target in targets
        if target != address
    ]


def _mark_core(report: Report) -> None:
    """The core is what common inputs alone reach from the seed."""
    neighbours: dict[str, set[str]] = {}
    for link in report.links:
        if link.kind == COMMON_INPUT:
            neighbours.setdefault(link.source, set()).add(link.target)
            neighbours.setdefault(link.target, set()).add(link.source)
    stack = [report.seed]
    core = {report.seed}
    while stack:
        for neighbour in neighbours.get(stack.pop(), ()):
            if neighbour not in core:
                core.add(neighbour)
                stack.append(neighbour)
    for address in core & report.members.keys():
        report.members[address].core = True
