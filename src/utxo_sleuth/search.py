"""Find a transaction from what someone remembers: an amount and a time window.

Each block is downloaded once in its raw form, which takes one request where
walking its transactions through the API would take about 150.

Only confirmed transactions are searched, by the time of their block. That time
is set by the miner, and a transaction can wait a long time before being mined,
so the window should run past the moment it was sent.

A dollar amount is converted again for every block, with the price of that
block's hour, because the same dollars are worth different sats across a window.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Protocol

from embit.script import Script

from utxo_sleuth.models import BlockRef

# Block timestamps are not strictly ordered, so look a little past each edge.
EDGE_BLOCKS = 6
DEFAULT_MAX_BLOCKS = 72
# Covers hourly price moves and the gap between price sources.
DEFAULT_USD_MARGIN = 2.0
DEFAULT_MAX_RESULTS = 50
HEADER_SIZE = 80
SATS_PER_BTC = 100_000_000


class BlockApi(Protocol):
    def tip_height(self) -> int: ...
    def blocks(self, height: int) -> list[BlockRef]: ...
    def raw_block(self, block_hash: str) -> bytes: ...
    def btc_price(self, timestamp: int) -> float: ...


class WindowTooLarge(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    """An amount in sats or in dollars, with its allowed margin."""

    sats: int | None = None
    usd: float | None = None
    margin_pct: float = 0.0
    tolerance: int = 0

    def centre(self, price: float | None) -> float:
        if self.sats is not None:
            return self.sats
        return self.usd / price * SATS_PER_BTC

    def band(self, price: float | None) -> tuple[int, int]:
        centre = self.centre(price)
        margin = centre * self.margin_pct / 100
        low = math.floor(centre - margin) - self.tolerance
        return max(1, low), math.ceil(centre + margin) + self.tolerance


@dataclass(frozen=True)
class Match:
    txid: str
    vout: int
    value: int
    address: str | None
    block: BlockRef
    gap_pct: float = 0.0
    usd: float | None = None
    price: float | None = None


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def skip(self, size: int) -> None:
        self.position += size

    def varint(self) -> int:
        first = self.data[self.position]
        self.position += 1
        if first < 0xFD:
            return first
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
        value = int.from_bytes(self.data[self.position : self.position + size], "little")
        self.position += size
        return value

    def integer(self, size: int) -> int:
        value = int.from_bytes(self.data[self.position : self.position + size], "little")
        self.position += size
        return value


def scan_block(raw: bytes, low: int, high: int) -> Iterator[tuple[str, int, int, str | None]]:
    """Yield (txid, vout, value, address) for outputs worth low to high sats."""
    reader = _Reader(raw)
    reader.skip(HEADER_SIZE)
    for _ in range(reader.varint()):
        start = reader.position
        reader.skip(4)
        segwit = raw[reader.position] == 0
        if segwit:
            reader.skip(2)
        body_start = reader.position
        for _ in range(reader.varint()):
            reader.skip(36)
            reader.skip(reader.varint())
            reader.skip(4)
        hits = []
        for vout in range(reader.varint()):
            value = reader.integer(8)
            size = reader.varint()
            if low <= value <= high:
                hits.append((vout, value, raw[reader.position : reader.position + size]))
            reader.skip(size)
        body_end = reader.position
        if segwit:
            for _ in range(_input_count(raw, body_start)):
                for _ in range(reader.varint()):
                    reader.skip(reader.varint())
        reader.skip(4)
        if hits:
            legacy = raw[start : start + 4] + raw[body_start:body_end]
            legacy += raw[reader.position - 4 : reader.position]
            txid = hashlib.sha256(hashlib.sha256(legacy).digest()).digest()[::-1].hex()
            for vout, value, script in hits:
                yield txid, vout, value, _address(script)


def _input_count(raw: bytes, position: int) -> int:
    reader = _Reader(raw)
    reader.position = position
    return reader.varint()


def _address(script: bytes) -> str | None:
    try:
        return Script(script).address()
    except (ValueError, KeyError, TypeError, IndexError):
        return None


def blocks_in_window(
    api: BlockApi, start: int, end: int, max_blocks: int = DEFAULT_MAX_BLOCKS
) -> list[BlockRef]:
    tip = api.tip_height()
    known: dict[int, BlockRef] = {}

    def block_at(height: int) -> BlockRef:
        if height not in known:
            for block in api.blocks(min(tip, height + 9)):
                known[block.height] = block
        return known[height]

    low, high = 0, tip
    while low < high:
        middle = (low + high) // 2
        if block_at(middle).time < start:
            low = middle + 1
        else:
            high = middle

    found = []
    past_end = 0
    height = max(0, low - EDGE_BLOCKS)
    while height <= tip and past_end < EDGE_BLOCKS:
        block = block_at(height)
        if start <= block.time <= end:
            found.append(block)
            if len(found) > max_blocks:
                raise WindowTooLarge(f"more than {max_blocks} blocks in this time window")
        elif block.time > end:
            past_end += 1
        height += 1
    return found


def find_outputs(
    api: BlockApi,
    target: Target,
    start: int,
    end: int,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    on_block: Callable[[int, int], None] | None = None,
) -> tuple[list[Match], int]:
    """Matching outputs, closest first, and how many blocks were searched."""
    blocks = blocks_in_window(api, start, end, max_blocks)
    matches = []
    for done, block in enumerate(blocks):
        if on_block is not None:
            on_block(done, len(blocks))
        price = api.btc_price(block.time) if target.usd is not None else None
        centre = target.centre(price)
        low, high = target.band(price)
        for txid, vout, value, address in scan_block(api.raw_block(block.hash), low, high):
            usd = value * price / SATS_PER_BTC if price else None
            gap = abs(value - centre) / centre * 100
            matches.append(Match(txid, vout, value, address, block, gap, usd, price))
    matches.sort(key=lambda match: (match.gap_pct, match.block.height))
    return matches, len(blocks)
