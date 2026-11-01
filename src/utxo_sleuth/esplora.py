"""Esplora REST client (mempool.space, Blockstream, or a self-hosted electrs).

Responses are cached in SQLite outside the repository, so re-running a trace
costs no requests and a crash loses nothing. Confirmed transactions never
change and are kept forever; everything else expires.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

import httpx

from utxo_sleuth.models import AddressStats, BlockRef, Tx

DEFAULT_API = "https://mempool.space/api"
# Only mempool.space offers historic prices, so a self-hosted --api still uses it.
PRICE_API = "https://mempool.space/api"
DEFAULT_CACHE = Path.home() / ".cache" / "utxo-sleuth" / "esplora.sqlite"
VOLATILE_TTL = 3600.0
TIP_TTL = 60.0
MAX_ATTEMPTS = 5


class ApiError(RuntimeError):
    """The server refused the request, or kept failing after the retries."""


class BudgetExceeded(RuntimeError):
    """The trace used up its allowance of network requests."""


class ResponseCache:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS response"
            " (key TEXT PRIMARY KEY, body TEXT NOT NULL, expires_at REAL)"
        )

    def get(self, key: str) -> Any | None:
        row = self._db.execute(
            "SELECT body, expires_at FROM response WHERE key = ?", (key,)
        ).fetchone()
        if row is None or (row[1] is not None and row[1] < time.time()):
            return None
        return json.loads(row[0])

    def put(self, key: str, body: Any, ttl: float | None) -> None:
        expires_at = None if ttl is None else time.time() + ttl
        self._db.execute(
            "INSERT OR REPLACE INTO response VALUES (?, ?, ?)",
            (key, json.dumps(body), expires_at),
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()


def _volatile(_: Any) -> float:
    return VOLATILE_TTL


def _tip(_: Any) -> float:
    return TIP_TTL


def _tx_ttl(data: dict[str, Any]) -> float | None:
    return None if data.get("status", {}).get("confirmed") else VOLATILE_TTL


class Esplora:
    def __init__(
        self,
        base_url: str = DEFAULT_API,
        cache_path: Path = DEFAULT_CACHE,
        max_requests: int = 2000,
        min_interval: float = 0.25,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.max_requests = max_requests
        self.min_interval = min_interval
        self.on_request: Callable[[], None] | None = None
        self.requests = 0
        self._last_request = 0.0
        self._cache = ResponseCache(cache_path)
        self._http = httpx.Client(
            timeout=30, headers={"User-Agent": "utxo-sleuth"}, follow_redirects=True
        )

    def tx(self, txid: str) -> Tx:
        return Tx.from_esplora(self._get(f"/tx/{txid}", _tx_ttl))

    def outspends(self, txid: str) -> list[str | None]:
        """For each output of a transaction, the txid spending it, if any."""
        return [
            spend["txid"] if spend.get("spent") else None
            for spend in self._get(f"/tx/{txid}/outspends", _volatile)
        ]

    def address_stats(self, address: str) -> AddressStats:
        return AddressStats.from_esplora(self._get(f"/address/{address}", _volatile))

    def address_txs(self, address: str, expected: int) -> list[Tx]:
        """Every transaction of an address; `expected` comes from address_stats."""
        pages = [self._get(f"/address/{address}/txs", _volatile)]
        count = len(pages[0])
        while pages[-1] and count < expected:
            confirmed = [t for t in pages[-1] if t.get("status", {}).get("confirmed")]
            if not confirmed:
                break
            last = confirmed[-1]["txid"]
            pages.append(self._get(f"/address/{address}/txs/chain/{last}", _volatile))
            count += len(pages[-1])
        return [Tx.from_esplora(tx) for page in pages for tx in page]

    def tip_height(self) -> int:
        return self._get("/blocks/tip/height", _tip)

    def blocks(self, height: int) -> list[BlockRef]:
        """The block at this height and the few before it, newest first."""
        return [
            BlockRef(block["id"], block["height"], block["timestamp"])
            for block in self._get(f"/blocks/{height}", _tip)
        ]

    def raw_block(self, block_hash: str) -> bytes:
        """Too large for the cache, so every call is a request."""
        self._spend_request()
        return self._fetch(f"{self.base_url}/block/{block_hash}/raw").content

    def btc_price(self, timestamp: int) -> float:
        """The USD price of the hour holding this moment."""
        hour = timestamp - timestamp % 3600
        settled = hour < time.time() - 2 * 3600
        body = self._get_url(
            f"{PRICE_API}/v1/historical-price?currency=USD&timestamp={hour}",
            lambda _: None if settled else TIP_TTL,
        )
        prices = body.get("prices") or [{}]
        price = prices[0].get("USD")
        if not price:
            raise ApiError(f"no BTC price known for timestamp {timestamp}")
        return price

    def close(self) -> None:
        self._http.close()
        self._cache.close()

    def _get(self, path: str, ttl_for: Callable[[Any], float | None]) -> Any:
        return self._get_url(self.base_url + path, ttl_for)

    def _get_url(self, key: str, ttl_for: Callable[[Any], float | None]) -> Any:
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        self._spend_request()
        body = self._fetch(key).json()
        self._cache.put(key, body, ttl_for(body))
        return body

    def _spend_request(self) -> None:
        if self.on_request is not None:
            self.on_request()
        if self.requests >= self.max_requests:
            raise BudgetExceeded(f"request budget of {self.max_requests} used up")

    def _fetch(self, url: str) -> httpx.Response:
        problem = "no attempt made"
        for attempt in range(MAX_ATTEMPTS):
            wait = self._last_request + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()
            self.requests += 1
            try:
                response = self._http.get(url)
            except httpx.TransportError as exc:
                problem = str(exc)
                time.sleep(2**attempt)
                continue
            if response.status_code == 429 or response.status_code >= 500:
                problem = f"HTTP {response.status_code}"
                retry_after = response.headers.get("Retry-After", "")
                time.sleep(int(retry_after) if retry_after.isdigit() else 2**attempt)
                continue
            if response.status_code != 200:
                raise ApiError(f"{url}: HTTP {response.status_code}: {response.text[:200]}")
            return response
        raise ApiError(f"{url}: gave up after {MAX_ATTEMPTS} attempts ({problem})")
