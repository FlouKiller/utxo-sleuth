"""Vectors come from the public BIP test mnemonic "abandon ... about"."""

import pytest

from conftest import FakeApi, tx
from utxo_sleuth import cli
from utxo_sleuth.cluster import Tracer
from utxo_sleuth.export import breakdown, to_summary
from utxo_sleuth.wallet import (
    KeyFileError,
    derive_addresses,
    first_used_address,
    read_public_key,
)

BIP44 = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
BIP49 = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"
BIP84 = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
BIP86 = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"

BIP84_RECEIVE = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
BIP84_CHANGE = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"


@pytest.mark.parametrize(
    "key, address",
    [
        (BIP44, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
        (BIP49, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
        (BIP84, BIP84_RECEIVE),
        (BIP86, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
    ],
)
def test_each_standard_derives_its_first_address(key, address):
    assert address in derive_addresses(key, count=1)


def test_both_chains_are_derived():
    assert derive_addresses(BIP84, count=1) == {BIP84_RECEIVE, BIP84_CHANGE}


def test_a_key_is_found_among_wallet_export_decorations(tmp_path):
    path = tmp_path / "wallet.xpub"
    path.write_text(f"wpkh([73c5da0a/84h/0h/0h]{BIP84}/0/*)#abcdefgh\n", "utf-8")
    assert read_public_key(path) == BIP84


def test_a_private_key_is_refused_without_being_echoed(tmp_path):
    secret = "xprv" + BIP84[4:]
    path = tmp_path / "wallet.xpub"
    path.write_text(secret, "utf-8")
    with pytest.raises(KeyFileError, match="PRIVATE") as caught:
        read_public_key(path)
    assert secret not in str(caught.value)


def test_a_private_key_beside_a_public_one_is_still_refused(tmp_path):
    path = tmp_path / "wallet.xpub"
    path.write_text(f"{BIP84}\n{'zprv' + BIP84[4:]}\n", "utf-8")
    with pytest.raises(KeyFileError, match="PRIVATE"):
        read_public_key(path)


def test_seed_words_are_not_read_as_a_key(tmp_path):
    path = tmp_path / "wallet.xpub"
    path.write_text("abandon " * 11 + "about", "utf-8")
    with pytest.raises(KeyFileError, match="no mainnet") as caught:
        read_public_key(path)
    assert "abandon" not in str(caught.value)


def test_a_corrupted_key_is_refused_without_being_echoed():
    corrupted = BIP84[:-1] + ("a" if BIP84[-1] != "a" else "b")
    with pytest.raises(KeyFileError) as caught:
        derive_addresses(corrupted, count=1)
    assert corrupted not in str(caught.value)


def test_two_different_keys_are_refused(tmp_path):
    path = tmp_path / "wallet.xpub"
    path.write_text(f"{BIP44}\n{BIP84}\n", "utf-8")
    with pytest.raises(KeyFileError, match="found 2"):
        read_public_key(path)


def test_a_seed_outside_the_wallet_stops_before_any_network(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "Esplora", lambda *args: pytest.fail("network used"))
    path = tmp_path / "wallet.xpub"
    path.write_text(BIP84, "utf-8")
    other = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
    assert cli.main([other, "--xpub-file", str(path), "--xpub-count", "1"]) == 2
    assert "not in this wallet" in capsys.readouterr().err


def test_the_first_used_address_is_found():
    api = FakeApi(tx("t", [("sender", 10)], [("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 9)]))
    assert first_used_address(BIP84, api) == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"


def test_an_unused_wallet_has_no_first_address():
    assert first_used_address(BIP84, FakeApi(), limit=2) is None


def test_an_address_or_a_key_is_required(capsys):
    with pytest.raises(SystemExit):
        cli.main([])
    assert "--xpub-file" in capsys.readouterr().err


def report():
    return Tracer(
        FakeApi(
            tx("t1", [("a", 10), ("b", 10)], [("x", 7), ("y", 12)]),
            tx("t2", [("c", 10)], [("a", 9)]),
        )
    ).trace("a")


def test_summary_has_no_address():
    summary = to_summary(report())
    assert "Addresses: 3" in summary
    assert "Services seen: none" in summary
    assert not {"a,", "b", "c"} & set(summary.split())


def test_breakdown_scores_each_link_kind():
    scores = breakdown(report(), {"b"})
    assert (scores["common_input"].found, scores["common_input"].predicted) == (1, 1)
    assert (scores["sweep"].found, scores["sweep"].predicted) == (0, 1)
