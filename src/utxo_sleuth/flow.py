"""Follow the coins themselves, upstream and downstream of a target address.

Clustering asks who owns an address; this asks where its money came from and
went. Each step follows a real transaction output, so the order of events is
exact. A trail ends at a known service, at something that behaves like one, or
where the coins stop moving.

Following funds says nothing about ownership: a trail crosses people freely, and
it walks through multisig addresses that clustering refuses to enter.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from utxo_sleuth.cluster import ChainApi, is_payout
from utxo_sleuth.esplora import BudgetExceeded
from utxo_sleuth.heuristics import SERVICE_SWEEP_INPUTS, looks_like_coinjoin
from utxo_sleuth.models import Input, Output, Tx

UNSPENT = "unspent"
BACK_TO_TARGET = "back to target"
ALREADY_SHOWN = "already shown"
DEPTH_LIMIT = "depth limit"
NODE_LIMIT = "node limit"
REQUEST_LIMIT = "request limit"
NEWLY_MINED = "newly mined"
COINJOIN = "CoinJoin, trail lost"


@dataclass(frozen=True)
class FlowLimits:
    max_depth: int = 6
    max_branches: int = 3
    max_nodes: int = 150
    max_start_txs: int = 25
    max_address_txs: int = 500


@dataclass
class FlowNode:
    address: str | None
    value: int
    txid: str
    time: int | None
    service: str | None = None
    multisig: str | None = None
    end: str | None = None
    hidden: int = 0
    children: list[FlowNode] = field(default_factory=list)


@dataclass
class FlowReport:
    target: str
    origins: list[FlowNode] = field(default_factory=list)
    destinations: list[FlowNode] = field(default_factory=list)
    truncated: str | None = None


class FlowTracer:
    def __init__(self, api: ChainApi, limits: FlowLimits = FlowLimits(), tags=None) -> None:
        self.api = api
        self.limits = limits
        self.tags = tags if tags is not None else {}
        self._nodes = 0
        self._seen: set[tuple[str, str, int]] = set()

    def trace(self, target: str) -> FlowReport:
        self.report = FlowReport(target)
        self.target = target
        stats = self.api.address_stats(target)
        if stats.tx_count > self.limits.max_address_txs:
            self.report.truncated = f"target has {stats.tx_count} transactions, too many to follow"
            return self.report
        txs = self.api.address_txs(target, stats.tx_count)
        txs.sort(key=lambda t: t.height or float("inf"), reverse=True)
        if len(txs) > self.limits.max_start_txs:
            self.report.truncated = f"only the latest {self.limits.max_start_txs} transactions followed"
        for tx in txs[: self.limits.max_start_txs]:
            if target in tx.input_addresses:
                outputs = [o for o in tx.spendable_outputs if o.address != target]
                self.report.destinations += self._follow_outputs(tx, outputs, 1)
            elif target in [o.address for o in tx.outputs]:
                self.report.origins += self._follow_inputs(tx, 1)
        return self.report

    def _follow_inputs(self, tx: Tx, depth: int) -> list[FlowNode]:
        kept = _largest(tx.inputs, self.limits.max_branches)
        return [self._upstream(spent, tx, depth) for spent in kept]

    def _follow_outputs(self, tx: Tx, outputs: list[Output], depth: int) -> list[FlowNode]:
        kept = _largest(outputs, self.limits.max_branches)
        return [self._downstream(output, tx, depth) for output in kept]

    def _upstream(self, spent: Input, tx: Tx, depth: int) -> FlowNode:
        """`spent` is what `tx` consumed; look at how that address got it."""
        node = FlowNode(spent.address, spent.value, tx.txid, tx.time, multisig=spent.multisig)
        key = ("up", spent.prev_txid or tx.txid, spent.prev_vout or 0)
        if not self._may_continue(node, key, depth):
            return node
        try:
            node.end = self._service_like(tx, spent.address)
            if node.end is None:
                previous = self.api.tx(spent.prev_txid)
                if previous.coinbase:
                    node.end = NEWLY_MINED
                else:
                    node.hidden = max(0, len(previous.inputs) - self.limits.max_branches)
                    node.children = self._follow_inputs(previous, depth + 1)
        except BudgetExceeded as exc:
            self._stop(node, exc)
        return node

    def _downstream(self, output: Output, tx: Tx, depth: int) -> FlowNode:
        """`output` is what `tx` created; look at how it was spent."""
        node = FlowNode(output.address, output.value, tx.txid, tx.time)
        key = ("down", tx.txid, output.vout)
        if not self._may_continue(node, key, depth):
            return node
        try:
            spenders = self.api.outspends(tx.txid)
            spender_id = spenders[output.vout] if output.vout < len(spenders) else None
            if spender_id is None:
                node.end = UNSPENT
                return node
            spender = self.api.tx(spender_id)
            node.multisig = next(
                (i.multisig for i in spender.inputs if i.address == output.address and i.multisig),
                None,
            )
            node.end = self._service_like(spender, output.address)
            if node.end is None:
                outputs = spender.spendable_outputs
                node.hidden = max(0, len(outputs) - self.limits.max_branches)
                node.children = self._follow_outputs(spender, outputs, depth + 1)
        except BudgetExceeded as exc:
            self._stop(node, exc)
        return node

    def _may_continue(self, node: FlowNode, key: tuple[str, str, int], depth: int) -> bool:
        node.service = self.tags.get(node.address) if node.address else None
        if node.service is not None:
            return False
        if node.address == self.target:
            node.end = BACK_TO_TARGET
        elif key in self._seen:
            node.end = ALREADY_SHOWN
        elif depth >= self.limits.max_depth:
            node.end = DEPTH_LIMIT
        elif self._nodes >= self.limits.max_nodes:
            node.end = NODE_LIMIT
            self.report.truncated = f"node limit of {self.limits.max_nodes} reached"
        else:
            self._seen.add(key)
            self._nodes += 1
        return node.end is None

    def _service_like(self, tx: Tx, address: str | None) -> str | None:
        """Why this spend should end the trail, if it should."""
        if looks_like_coinjoin(tx):
            return COINJOIN
        if len(tx.inputs) >= SERVICE_SWEEP_INPUTS:
            return f"likely a service (swept with {len(tx.inputs) - 1} other inputs)"
        outputs = [o.address for o in tx.spendable_outputs]
        if is_payout(self.api, tx.input_addresses, outputs):
            return f"likely a service (pays {len(outputs)} addresses)"
        if address is not None:
            count = self.api.address_stats(address).tx_count
            if count > self.limits.max_address_txs:
                return f"likely a service ({count} transactions)"
        return None

    def _stop(self, node: FlowNode, exc: BudgetExceeded) -> None:
        node.end = REQUEST_LIMIT
        self.report.truncated = str(exc)


def _largest(items: Iterable, count: int) -> list:
    return sorted(items, key=lambda item: item.value, reverse=True)[:count]


def paths(node: FlowNode) -> list[list[FlowNode]]:
    """Every chain from this node to the end of its trail."""
    if not node.children:
        return [[node]]
    return [[node, *rest] for child in node.children for rest in paths(child)]


def main_path(nodes: list[FlowNode]) -> list[FlowNode]:
    """Follow the largest amount at each step."""
    if not nodes:
        return []
    best = max(nodes, key=lambda node: node.value)
    return [best, *main_path(best.children)]
