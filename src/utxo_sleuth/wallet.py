"""Derive a wallet's addresses from its extended public key, without any network.

This serves only to score a trace against a wallet you own. The key stays in a
local file and the derived addresses are never sent anywhere.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

from embit import bip32, script
from embit.script import Script

DEFAULT_COUNT = 1000
SEED_SEARCH = 20
ACCOUNT_DEPTH = 3
RECEIVE_CHAIN, CHANGE_CHAIN = 0, 1

_BASE58 = "[1-9A-HJ-NP-Za-km-z]"
_PUBLIC_KEY = re.compile(rf"(?<!{_BASE58})[xyz]pub{_BASE58}{{100,}}")
_PRIVATE_KEY = re.compile(rf"(?<!{_BASE58})[a-zA-Z]prv{_BASE58}{{100,}}")


def _nested_segwit(key) -> Script:
    return script.p2sh(script.p2wpkh(key))


# An xpub does not say which address type the wallet uses, so try them all.
# Extra addresses cost nothing: the trace can never predict an unused type.
_SCRIPTS: dict[str, tuple[Callable, ...]] = {
    "xpub": (script.p2pkh, _nested_segwit, script.p2wpkh, script.p2tr),
    "ypub": (_nested_segwit,),
    "zpub": (script.p2wpkh,),
}


class KeyFileError(ValueError):
    """The file holds no usable public key. Never quotes the file's content."""


def read_public_key(path: Path) -> str:
    text = path.read_text("utf-8")
    if _PRIVATE_KEY.search(text):
        raise KeyFileError(
            f"{path} contains a PRIVATE key. Delete this file and use the public key."
        )
    keys = set(_PUBLIC_KEY.findall(text))
    if not keys:
        raise KeyFileError(f"{path}: no mainnet xpub, ypub or zpub found")
    if len(keys) > 1:
        raise KeyFileError(f"{path}: expected one key, found {len(keys)}")
    return keys.pop()


def derive_addresses(public_key: str, count: int = DEFAULT_COUNT) -> set[str]:
    """The first `count` receive and change addresses of an account-level key."""
    account = _account(public_key)
    addresses = set()
    for chain in (RECEIVE_CHAIN, CHANGE_CHAIN):
        addresses.update(_chain_addresses(public_key, account, chain, count))
    return addresses


def first_used_address(public_key: str, api, limit: int = SEED_SEARCH) -> str | None:
    """Pick a seed so nobody has to choose, or paste, a real address."""
    account = _account(public_key)
    for address in _chain_addresses(public_key, account, RECEIVE_CHAIN, limit):
        if api.address_stats(address).tx_count:
            return address
    return None


def _account(public_key: str) -> bip32.HDKey:
    try:
        account = bip32.HDKey.from_string(public_key)
    except (ValueError, TypeError):
        raise KeyFileError("the public key is invalid or mistyped") from None
    if account.depth != ACCOUNT_DEPTH:
        print(
            f"Warning: key depth is {account.depth}, an account-level key has "
            f"{ACCOUNT_DEPTH}. Addresses may not match the wallet.",
            file=sys.stderr,
        )
    return account


def _chain_addresses(public_key, account, chain, count) -> Iterator[str]:
    branch = account.child(chain)
    for index in range(count):
        key = branch.child(index).key
        for build in _SCRIPTS[public_key[:4]]:
            yield build(key).address()
