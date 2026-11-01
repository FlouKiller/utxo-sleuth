"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from utxo_sleuth.cluster import Limits, Tracer
from utxo_sleuth.esplora import DEFAULT_API, DEFAULT_CACHE, ApiError, Esplora
from utxo_sleuth.export import (
    breakdown,
    evaluate,
    to_dot,
    to_flow_text,
    to_json,
    to_summary,
    to_text,
)
from utxo_sleuth.flow import FlowLimits, FlowTracer
from utxo_sleuth.labels import DEFAULT_LABELS, Labels, update_labels
from utxo_sleuth.wallet import (
    DEFAULT_COUNT,
    SEED_SEARCH,
    KeyFileError,
    derive_addresses,
    first_used_address,
    read_public_key,
)

ADDRESS = re.compile(r"^(bc1[a-z0-9]{8,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$")


def build_parser() -> argparse.ArgumentParser:
    defaults = Limits()
    parser = argparse.ArgumentParser(
        prog="utxo-sleuth",
        description="Link the Bitcoin addresses likely owned by the same entity.",
    )
    parser.add_argument(
        "address",
        nargs="?",
        help="seed address (default with --xpub-file: the wallet's first used address)",
    )
    parser.add_argument("--api", default=DEFAULT_API, help="Esplora base URL (default: %(default)s)")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE, help="SQLite cache path")
    flow = FlowLimits()
    parser.add_argument(
        "--flow",
        action="store_true",
        help="follow the funds upstream and downstream instead of clustering",
    )
    parser.add_argument("--flow-depth", type=int, default=flow.max_depth, help="steps per direction")
    parser.add_argument("--flow-branches", type=int, default=flow.max_branches, help="largest branches followed per step")
    parser.add_argument("--max-hops", type=int, default=defaults.max_hops)
    parser.add_argument("--min-confidence", type=float, default=defaults.min_confidence)
    parser.add_argument("--change-threshold", type=float, default=defaults.change_threshold)
    parser.add_argument("--max-addresses", type=int, default=defaults.max_addresses)
    parser.add_argument("--max-address-txs", type=int, default=defaults.max_address_txs)
    parser.add_argument("--max-inputs", type=int, default=defaults.max_inputs)
    parser.add_argument("--max-requests", type=int, default=2000)
    parser.add_argument("--tags", type=Path, help="JSON file mapping addresses to service names")
    parser.add_argument(
        "--update-labels",
        action="store_true",
        help="download exchange address lists to the local labels database",
    )
    parser.add_argument("--labels-db", type=Path, default=DEFAULT_LABELS, help="labels database path")
    truth = parser.add_mutually_exclusive_group()
    truth.add_argument("--truth", type=Path, help="text file with one known address per line")
    truth.add_argument(
        "--xpub-file",
        type=Path,
        help="local file holding the wallet's xpub, ypub or zpub, derived offline",
    )
    parser.add_argument(
        "--xpub-count",
        type=int,
        default=DEFAULT_COUNT,
        help="addresses to derive per chain (default: %(default)s)",
    )
    parser.add_argument(
        "--summary", action="store_true", help="print counts only, with no address or txid"
    )
    parser.add_argument("--json", type=Path, help="write the full report as JSON")
    parser.add_argument("--dot", type=Path, help="write the graph in Graphviz format")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.update_labels:
        print(f"Labels stored: {update_labels(args.labels_db)}")
        if args.address is None and args.xpub_file is None:
            return 0
    if args.address is None and args.xpub_file is None:
        parser.error("give an address, or --xpub-file to start from your wallet")
    if args.flow and (args.summary or args.dot or args.truth or args.xpub_file):
        parser.error("--flow works with an address, and cannot be combined with those options")
    if args.flow and args.address is None:
        parser.error("--flow needs an address")
    if args.address and not ADDRESS.match(args.address):
        print(f"Not a Bitcoin mainnet address: {args.address}", file=sys.stderr)
        return 2

    public_key = None
    wallet: set[str] = set()
    if args.xpub_file:
        try:
            public_key = read_public_key(args.xpub_file)
            wallet = derive_addresses(public_key, args.xpub_count)
        except KeyFileError as exc:
            print(exc, file=sys.stderr)
            return 2
        if args.address and args.address not in wallet:
            print(
                "The seed address is not in this wallet: wrong key, or raise --xpub-count.",
                file=sys.stderr,
            )
            return 2

    extra = json.loads(args.tags.read_text("utf-8")) if args.tags else {}
    labels = Labels(args.labels_db, extra)
    if not labels.downloaded:
        print("Exchange lists not downloaded yet: run with --update-labels.", file=sys.stderr)
    limits = Limits(
        max_hops=args.max_hops,
        min_confidence=args.min_confidence,
        max_addresses=args.max_addresses,
        max_address_txs=args.max_address_txs,
        max_inputs=args.max_inputs,
        change_threshold=args.change_threshold,
    )
    api = Esplora(args.api, args.cache, args.max_requests)
    try:
        seed = args.address or first_used_address(public_key, api)
        if seed is None:
            print(f"No used address in the first {SEED_SEARCH} of this wallet.", file=sys.stderr)
            return 2
        if args.flow:
            flow_limits = FlowLimits(max_depth=args.flow_depth, max_branches=args.flow_branches)
            report = FlowTracer(api, flow_limits, labels).trace(seed)
        else:
            report = Tracer(api, limits, labels).trace(seed)
    except ApiError as exc:
        print(f"API error: {exc}", file=sys.stderr)
        return 1
    finally:
        api.close()
        labels.close()

    if args.flow:
        print(to_flow_text(report), end="")
    else:
        print((to_summary if args.summary else to_text)(report), end="")
    print(f"\nNetwork requests: {api.requests}")
    if wallet:
        # A derived list includes unused addresses, so recall means nothing here.
        for name, core_only in (("core", True), ("all", False)):
            score = evaluate(report, wallet, core_only)
            precision = f"{score.precision:.0%}" if score.predicted else "n/a"
            print(f"Against wallet ({name}): precision {precision} ({score.found}/{score.predicted})")
        for kind, score in breakdown(report, wallet).items():
            print(f"  {kind}: {score.found}/{score.predicted} correct")
    if args.truth:
        truth = {
            line.strip()
            for line in args.truth.read_text("utf-8").splitlines()
            if line.strip()
        }
        for name, core_only in (("core", True), ("all", False)):
            score = evaluate(report, truth, core_only)
            precision = f"{score.precision:.0%}" if score.predicted else "n/a"
            print(
                f"Against truth ({name}): precision {precision} "
                f"({score.found}/{score.predicted}), "
                f"recall {score.recall:.0%} ({score.found}/{score.expected})"
            )
    if args.json:
        args.json.write_text(json.dumps(to_json(report), indent=2), "utf-8")
    if args.dot:
        args.dot.write_text(to_dot(report), "utf-8")
    return 0
