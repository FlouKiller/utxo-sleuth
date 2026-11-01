import hashlib

import pytest

from utxo_sleuth import cli
from utxo_sleuth.export import to_search_text
from utxo_sleuth.models import BlockRef
from utxo_sleuth.search import (
    Target,
    WindowTooLarge,
    blocks_in_window,
    find_outputs,
    scan_block,
)

P2WPKH = bytes.fromhex("0014") + bytes(range(20))
OP_RETURN = bytes.fromhex("6a0401020304")
INPUT = bytes(36) + b"\x00" + b"\xff\xff\xff\xff"
VERSION = (2).to_bytes(4, "little")
LOCKTIME = bytes(4)


def find_amount(api, amount, start, end, tolerance=0):
    return find_outputs(api, Target(sats=amount, tolerance=tolerance), start, end)


def serialize_outputs(outputs):
    body = bytes([len(outputs)])
    for value, script in outputs:
        body += value.to_bytes(8, "little") + bytes([len(script)]) + script
    return body


def legacy_tx(*outputs):
    return VERSION + b"\x01" + INPUT + serialize_outputs(outputs) + LOCKTIME


def segwit_tx(*outputs):
    witness = b"\x02\x01\xaa\x02\xbb\xcc"
    return (
        VERSION + b"\x00\x01\x01" + INPUT + serialize_outputs(outputs) + witness + LOCKTIME
    )


def txid_of(legacy):
    return hashlib.sha256(hashlib.sha256(legacy).digest()).digest()[::-1].hex()


def block_of(*txs):
    return bytes(80) + bytes([len(txs)]) + b"".join(txs)


class FakeBlocks:
    def __init__(self, times, raw=None, price=50_000):
        self.chain = [BlockRef(f"h{n}", n, time) for n, time in enumerate(times)]
        self.raw = raw or {}
        self.price = price
        self.downloads = []

    def btc_price(self, timestamp):
        return self.price(timestamp) if callable(self.price) else self.price

    def tip_height(self):
        return self.chain[-1].height

    def blocks(self, height):
        return self.chain[max(0, height - 9) : height + 1][::-1]

    def raw_block(self, block_hash):
        self.downloads.append(block_hash)
        return self.raw.get(block_hash, block_of())


def test_a_legacy_output_is_found():
    raw = block_of(legacy_tx((5_000, P2WPKH), (517_412, P2WPKH)))
    expected = txid_of(legacy_tx((5_000, P2WPKH), (517_412, P2WPKH)))
    assert [(t, v, a) for t, v, a, _ in scan_block(raw, 517_412, 517_412)] == [
        (expected, 1, 517_412)
    ]


def test_a_segwit_transaction_keeps_its_txid_and_the_next_one_still_parses():
    raw = block_of(segwit_tx((517_412, P2WPKH)), legacy_tx((517_412, P2WPKH), (9, P2WPKH)))
    found = list(scan_block(raw, 517_412, 517_412))
    assert [hit[0] for hit in found] == [
        txid_of(legacy_tx((517_412, P2WPKH))),
        txid_of(legacy_tx((517_412, P2WPKH), (9, P2WPKH))),
    ]


def test_addresses_are_decoded():
    raw = block_of(legacy_tx((517_412, P2WPKH)))
    assert next(scan_block(raw, 517_412, 517_412))[3].startswith("bc1q")


def test_a_script_without_address_is_kept():
    raw = block_of(legacy_tx((517_412, OP_RETURN)))
    assert next(scan_block(raw, 517_412, 517_412))[3] is None


def test_long_counts_are_read():
    txs = [legacy_tx((n + 1, P2WPKH)) for n in range(300)]
    raw = bytes(80) + b"\xfd" + (300).to_bytes(2, "little") + b"".join(txs)
    assert len(list(scan_block(raw, 1, 300))) == 300


def test_blocks_are_found_by_time():
    api = FakeBlocks([1_000 + 600 * n for n in range(1_000)])
    found = blocks_in_window(api, 1_000 + 600 * 500, 1_000 + 600 * 503)
    assert [b.height for b in found] == [500, 501, 502, 503]


def test_out_of_order_timestamps_near_the_edge_are_kept():
    times = [100, 200, 300, 500, 400, 600, 700, 800, 900, 1_000, 1_100, 1_200, 1_300]
    assert 4 in [b.height for b in blocks_in_window(FakeBlocks(times), 350, 450)]


def test_a_window_near_the_tip_works():
    api = FakeBlocks([100 * n for n in range(30)])
    assert [b.height for b in blocks_in_window(api, 2_800, 9_000)] == [28, 29]


def test_a_huge_window_is_refused():
    api = FakeBlocks([100 * n for n in range(200)])
    with pytest.raises(WindowTooLarge):
        blocks_in_window(api, 0, 100_000, max_blocks=10)


def test_only_blocks_of_the_window_are_downloaded():
    target = block_of(legacy_tx((517_412, P2WPKH)))
    outside = block_of(legacy_tx((517_412, P2WPKH), (1, P2WPKH)))
    api = FakeBlocks([100 * n for n in range(30)], {"h5": target, "h20": outside})
    matches, searched = find_amount(api, 517_412, 450, 550)
    assert searched == 1
    assert api.downloads == ["h5"]
    assert matches[0].block.height == 5


def test_tolerance_widens_the_match():
    raw = block_of(legacy_tx((517_400, P2WPKH), (517_500, P2WPKH)))
    api = FakeBlocks([100 * n for n in range(30)], {"h5": raw})
    assert len(find_amount(api, 517_412, 450, 550)[0]) == 0
    assert [m.value for m in find_amount(api, 517_412, 450, 550, tolerance=20)[0]] == [517_400]


def test_dollars_become_sats_at_the_price_of_each_block():
    # $100 is 200,000 sats at 50,000 and 100,000 sats at 100,000.
    early = block_of(legacy_tx((200_000, P2WPKH), (100_000, P2WPKH)))
    late = block_of(legacy_tx((200_000, P2WPKH), (100_000, P2WPKH)))
    api = FakeBlocks(
        [100 * n for n in range(30)],
        {"h5": early, "h6": late},
        price=lambda time: 50_000 if time < 550 else 100_000,
    )
    matches, _ = find_outputs(api, Target(usd=100, margin_pct=2), 450, 650)
    assert [(m.block.height, m.value) for m in matches] == [(5, 200_000), (6, 100_000)]
    assert matches[0].usd == pytest.approx(100)


def test_the_margin_is_a_percentage_both_ways():
    assert Target(usd=100, margin_pct=2).band(50_000) == (196_000, 204_000)
    assert Target(sats=1_000, margin_pct=10).band(None) == (900, 1_100)


def test_a_margin_never_reaches_empty_outputs():
    assert Target(sats=5, tolerance=100).band(None)[0] == 1


def test_results_come_closest_first():
    raw = block_of(legacy_tx((205_000, P2WPKH), (200_500, P2WPKH), (197_000, P2WPKH)))
    api = FakeBlocks([100 * n for n in range(30)], {"h5": raw})
    matches, _ = find_outputs(api, Target(usd=100, margin_pct=3), 450, 550)
    assert [m.value for m in matches] == [200_500, 197_000, 205_000]
    assert matches[0].gap_pct == pytest.approx(0.25)


def test_results_show_their_dollar_value():
    raw = block_of(legacy_tx((200_000, P2WPKH)))
    api = FakeBlocks([100 * n for n in range(30)], {"h5": raw})
    text = to_search_text(*find_outputs(api, Target(usd=100, margin_pct=1), 450, 550))
    assert "$100.00 at $50,000/BTC" in text


def test_long_results_are_cut_to_the_closest():
    raw = block_of(legacy_tx((1_000, P2WPKH), (1_001, P2WPKH), (1_002, P2WPKH)))
    api = FakeBlocks([100 * n for n in range(30)], {"h5": raw})
    matches, blocks = find_outputs(api, Target(sats=1_000, margin_pct=1), 450, 550)
    text = to_search_text(matches, blocks, limit=1)
    assert "Showing the 1 closest" in text
    assert "1,002 sats" not in text


def test_results_are_readable():
    raw = block_of(legacy_tx((517_412, P2WPKH)))
    api = FakeBlocks([100 * n for n in range(30)], {"h5": raw})
    text = to_search_text(*find_amount(api, 517_412, 450, 550))
    assert "517,412 sats, 0.00% off, block 5" in text
    assert "Matching outputs: 1" in text


def test_an_amount_needs_a_start(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--find-amount", "517412"])
    assert "--from" in capsys.readouterr().err


def test_sats_and_dollars_exclude_each_other():
    with pytest.raises(SystemExit):
        cli.main(["--find-amount", "1", "--find-usd", "1", "--from", "2026-01-15 20:00"])


def test_a_bad_date_is_refused(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--find-amount", "1", "--from", "yesterday"])
    assert "YYYY-MM-DD" in capsys.readouterr().err


def test_the_end_must_follow_the_start(capsys):
    code = cli.main(
        ["--find-amount", "1", "--from", "2026-01-15 20:00", "--to", "2026-01-15 19:00"]
    )
    assert code == 2
    assert "--to" in capsys.readouterr().err
