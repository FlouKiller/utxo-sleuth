"""Know which addresses belong to exchanges and other services.

Three sources, strongest first: your own --tags file, the short list shipped in
known_services.json, and WalletExplorer's wallets. WalletExplorer states no
redistribution terms, so its data is downloaded to a local cache instead of being
committed. Lookups happen offline and send no address anywhere.

Coverage is partial. Most of WalletExplorer's names date from 2016 and its large
hot wallets are often unnamed, so a missing label proves nothing.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path

import httpx

DEFAULT_LABELS = Path.home() / ".cache" / "utxo-sleuth" / "labels.sqlite"
BUNDLED = Path(__file__).with_name("known_services.json")
CSV_URL = "https://www.walletexplorer.com/wallet/{wallet}/addresses?format=csv&page=all"
DOWNLOAD_DELAY = 2.0
DOWNLOAD_TIMEOUT = 300

WALLETS = (
    "Binance.com",
    "Bitfinex.com",
    "Bitso.com",
    "Bitstamp.net",
    "Bittrex.com",
    "Bitcoin.de",
    "Cex.io",
    "Exmo.com",
    "HitBtc.com",
    "Huobi.com",
    "Huobi.com-2",
    "Kraken.com",
    "Luno.com",
    "OKCoin.com",
    "OKCoin.com-2",
    "Paxful.com",
    "Poloniex.com",
)


def parse_wallet_csv(text: str) -> list[str]:
    """The file opens with a comment line and a header line."""
    rows = csv.reader(io.StringIO(text))
    return [row[0] for index, row in enumerate(rows) if index >= 2 and row]


def update_labels(
    path: Path = DEFAULT_LABELS,
    http: httpx.Client | None = None,
    log: Callable[[str], None] = print,
    delay: float = DOWNLOAD_DELAY,
) -> int:
    """Replace each wallet's addresses; a failed wallet keeps its previous ones."""
    client = http or httpx.Client(
        timeout=DOWNLOAD_TIMEOUT, headers={"User-Agent": "utxo-sleuth"}, follow_redirects=True
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE IF NOT EXISTS label (address TEXT PRIMARY KEY, service TEXT NOT NULL)")
    total = 0
    try:
        for position, wallet in enumerate(WALLETS):
            if position:
                time.sleep(delay)
            try:
                response = client.get(CSV_URL.format(wallet=wallet))
                response.raise_for_status()
            except httpx.HTTPError as exc:
                log(f"{wallet}: failed ({exc}), keeping previous data")
                continue
            addresses = parse_wallet_csv(response.text)
            with db:
                db.execute("DELETE FROM label WHERE service = ?", (wallet,))
                db.executemany(
                    "INSERT OR REPLACE INTO label VALUES (?, ?)",
                    ((address, wallet) for address in addresses),
                )
            total += len(addresses)
            log(f"{wallet}: {len(addresses)} addresses")
    finally:
        db.close()
        if http is None:
            client.close()
    return total


class Labels:
    """Read-only mapping from address to service name."""

    def __init__(
        self,
        path: Path = DEFAULT_LABELS,
        extra: dict[str, str] | None = None,
        bundled: Path = BUNDLED,
    ) -> None:
        self._known = json.loads(bundled.read_text("utf-8")) | (extra or {})
        self._db = sqlite3.connect(path) if path.exists() else None

    @property
    def downloaded(self) -> bool:
        return self._db is not None

    def get(self, address: str) -> str | None:
        if address in self._known:
            return self._known[address]
        if self._db is None:
            return None
        row = self._db.execute(
            "SELECT service FROM label WHERE address = ?", (address,)
        ).fetchone()
        return row[0] if row else None

    def __contains__(self, address: str) -> bool:
        return self.get(address) is not None

    def __getitem__(self, address: str) -> str:
        service = self.get(address)
        if service is None:
            raise KeyError(address)
        return service

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
