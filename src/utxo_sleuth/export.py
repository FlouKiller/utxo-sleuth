"""Render a report for people (text, Graphviz) and for tools (JSON)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from utxo_sleuth.cluster import Report


@dataclass(frozen=True)
class Evaluation:
    found: int
    predicted: int
    expected: int

    @property
    def precision(self) -> float:
        return self.found / self.predicted if self.predicted else 0.0

    @property
    def recall(self) -> float:
        return self.found / self.expected if self.expected else 0.0


def evaluate(report: Report, truth: set[str], core_only: bool = False) -> Evaluation:
    """Compare a trace with a wallet's real address list. The seed proves nothing."""
    predicted = {
        address
        for address, member in report.members.items()
        if address != report.seed and (member.core or not core_only)
    }
    expected = truth - {report.seed}
    return Evaluation(len(predicted & expected), len(predicted), len(expected))


def breakdown(report: Report, truth: set[str]) -> dict[str, Evaluation]:
    """Right and wrong guesses per link kind, the numbers calibration needs."""
    kinds: dict[str, list[bool]] = {}
    for address, member in report.members.items():
        if member.via is not None:
            kinds.setdefault(member.via.kind, []).append(address in truth)
    return {
        kind: Evaluation(sum(hits), len(hits), 0) for kind, hits in sorted(kinds.items())
    }


def to_summary(report: Report) -> str:
    """Counts only: safe to share, since no address or txid appears."""
    core = sum(1 for m in report.members.values() if m.core)
    lines = [
        f"Addresses: {len(report.members)} ({core} core, "
        f"{len(report.members) - core} probable)",
        f"Links: {len(report.links)}",
        f"Services seen: {', '.join(sorted({s.service for s in report.services})) or 'none'}",
        f"Stopped at: {len(report.boundaries)} addresses",
        f"Transactions ignored: {len(report.skipped_txs)}",
        f"Not expanded (hop limit): {report.unexpanded} addresses",
    ]
    if report.truncated:
        lines.append(f"INCOMPLETE: {report.truncated}")
    return "\n".join(lines) + "\n"


def to_json(report: Report) -> dict[str, Any]:
    return asdict(report)


def to_dot(report: Report) -> str:
    lines = ["graph cluster {", "  node [shape=box, style=filled, fontname=monospace];"]
    for address, member in report.members.items():
        if address == report.seed:
            colour = "gold"
        elif address in report.boundaries:
            colour = "lightcoral"
        elif member.core:
            colour = "lightblue"
        else:
            colour = "white"
        label = f"{_short(address)}\\n{member.confidence:.2f}"
        lines.append(f'  "{address}" [label="{label}", fillcolor={colour}];')
    for key, link in sorted(_strongest_links(report).items()):
        lines.append(
            f'  "{key[0]}" -- "{key[1]}" '
            f'[label="{link.kind} {link.confidence:.2f}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def to_text(report: Report) -> str:
    members = sorted(
        report.members.values(), key=lambda m: (-m.confidence, m.hops, m.address)
    )
    core = sum(1 for m in members if m.core)
    lines = [
        f"Seed: {report.seed}",
        f"Addresses: {len(members)} ({core} core, {len(members) - core} probable)",
        "",
    ]
    for member in members:
        layer = "core" if member.core else "prob"
        lines.append(
            f"{member.confidence:5.2f}  {layer}  hop {member.hops}  {member.address}"
        )
        if member.via is not None:
            lines.append(f"       via {member.via.kind} in {member.via.txid}")
            lines.extend(f"         {reason}" for reason in member.via.reasons)
    if report.services:
        lines += ["", "Exchanges and services:"]
        for contact in report.services:
            direction = contact.direction.replace("_", " ")
            lines.append(f"  {contact.address} {direction} {contact.service}")
            lines.append(f"    in {contact.txid}")
    if report.boundaries:
        lines += ["", "Stopped at:"]
        lines += [f"  {a}: {why}" for a, why in sorted(report.boundaries.items())]
    if report.skipped_txs:
        lines += ["", f"Transactions ignored: {len(report.skipped_txs)}"]
        lines += [f"  {t}: {why}" for t, why in sorted(report.skipped_txs.items())]
    if report.unexpanded:
        lines += ["", f"Not expanded (hop limit): {report.unexpanded} addresses"]
    if report.truncated:
        lines += ["", f"INCOMPLETE: {report.truncated}"]
    return "\n".join(lines) + "\n"


def _strongest_links(report: Report) -> dict:
    strongest: dict = {}
    for link in report.links:
        key = tuple(sorted((link.source, link.target)))
        if key not in strongest or link.confidence > strongest[key].confidence:
            strongest[key] = link
    return strongest


def _short(address: str) -> str:
    return f"{address[:8]}...{address[-6:]}"
