import httpx

from utxo_sleuth.labels import WALLETS, Labels, parse_wallet_csv, update_labels

BINANCE_HOT = "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h"
SAMPLE = (
    '"#Wallet Binance.com (00000b55c1bcbc1f). Source: WalletExplorer.com"\n'
    "address,balance,incoming txs,last used in block\n"
    "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s,0.09148088,882229,954590\n"
    "bc1qcgmpzx2pww9h3g9slxwzjqrztv7fy4t0lkye99,0.0025515,2,876928\n"
)


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_the_export_is_parsed():
    assert parse_wallet_csv(SAMPLE) == [
        "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s",
        "bc1qcgmpzx2pww9h3g9slxwzjqrztv7fy4t0lkye99",
    ]


def test_a_download_can_be_looked_up_offline(tmp_path):
    path = tmp_path / "labels.sqlite"
    total = update_labels(
        path,
        client(lambda request: httpx.Response(200, text=SAMPLE)),
        log=lambda _: None,
        delay=0,
    )
    assert total == 2 * len(WALLETS)
    labels = Labels(path)
    assert labels.downloaded
    assert "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s" in labels
    assert "unknown" not in labels
    labels.close()


def test_a_failed_wallet_keeps_its_previous_addresses(tmp_path):
    path = tmp_path / "labels.sqlite"
    ok = client(lambda request: httpx.Response(200, text=SAMPLE))
    update_labels(path, ok, log=lambda _: None, delay=0)
    messages = []
    failing = client(lambda request: httpx.Response(503))
    assert update_labels(path, failing, log=messages.append, delay=0) == 0
    assert len(messages) == len(WALLETS)
    labels = Labels(path)
    assert labels.get("1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s") is not None
    labels.close()


def test_bundled_addresses_need_no_download(tmp_path):
    labels = Labels(tmp_path / "absent.sqlite")
    assert not labels.downloaded
    assert labels[BINANCE_HOT] == "Binance.com"


def test_your_own_tags_win(tmp_path):
    labels = Labels(tmp_path / "absent.sqlite", {BINANCE_HOT: "Mine"})
    assert labels[BINANCE_HOT] == "Mine"
