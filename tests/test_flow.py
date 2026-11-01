import pytest

from conftest import FakeApi, tx
from utxo_sleuth import cli
from utxo_sleuth.export import to_flow_text, to_json
from utxo_sleuth.flow import (
    ALREADY_SHOWN,
    BACK_TO_TARGET,
    COINJOIN,
    DEPTH_LIMIT,
    NEWLY_MINED,
    UNSPENT,
    FlowLimits,
    FlowTracer,
    main_path,
    paths,
)
from utxo_sleuth.models import Input, Tx

EXCHANGE = {"hot": "Binance.com"}


def round_trip_chain():
    """hot -> relay -> target -> shared -> target, and target -> shop."""
    withdrawal = tx("t1", [("hot", 900_000, "t0", 0)], [("relay", 500_000), ("other", 399_000)])
    forward = tx("t2", [("relay", 500_000, "t1", 0)], [("target", 450_000), ("deposit", 49_000)])
    spend = tx("t3", [("target", 450_000, "t2", 0)], [("shared", 8_000), ("shop", 441_000)])
    refund = tx("t4", [("shared", 8_000, "t3", 0)], [("target", 7_800)], multisig="2-of-2")
    return FakeApi(withdrawal, forward, spend, refund)


def names(chain):
    return [node.service or node.address for node in chain]


def test_funds_are_traced_back_to_the_exchange():
    report = FlowTracer(round_trip_chain(), tags=EXCHANGE).trace("target")
    chain = paths(next(n for n in report.origins if n.address == "relay"))[0]
    assert names(chain) == ["relay", "Binance.com"]


def test_funds_coming_back_end_on_the_target():
    report = FlowTracer(round_trip_chain(), tags=EXCHANGE).trace("target")
    chain = paths(next(n for n in report.destinations if n.address == "shared"))[0]
    assert names(chain) == ["shared", "target"]
    assert chain[0].multisig == "2-of-2"
    assert chain[-1].end == BACK_TO_TARGET


def test_unspent_funds_end_the_trail():
    report = FlowTracer(round_trip_chain(), tags=EXCHANGE).trace("target")
    shop = next(n for n in report.destinations if n.address == "shop")
    assert shop.end == UNSPENT


def test_a_labelled_destination_ends_the_trail():
    api = FakeApi(tx("t", [("target", 900)], [("hot", 800), ("rest", 77)]))
    report = FlowTracer(api, tags=EXCHANGE).trace("target")
    assert report.destinations[0].service == "Binance.com"
    assert not report.destinations[0].children


def test_a_big_sweep_is_a_service_deposit():
    pay = tx("t1", [("target", 900)], [("deposit", 800), ("rest", 77)])
    sweep = tx(
        "t2",
        [("deposit", 800, "t1", 0)] + [(f"i{n}", 1_000 + n, "x", n) for n in range(24)],
        [("cold", 30_000)],
    )
    report = FlowTracer(FakeApi(pay, sweep)).trace("target")
    deposit = next(n for n in report.destinations if n.address == "deposit")
    assert deposit.end == "likely a service (swept with 24 other inputs)"


def test_a_payout_is_an_unknown_service_upstream():
    outputs = [(f"o{n}", 1_100 + n) for n in range(12)] + [("target", 5_555)]
    report = FlowTracer(FakeApi(tx("batch", [("hot", 99_999, "t0", 0)], outputs))).trace("target")
    assert report.origins[0].end == "likely a service (pays 13 addresses)"


def test_a_coinjoin_loses_the_trail():
    pay = tx("t1", [("target", 900)], [("a", 800), ("b", 77)])
    mix = tx(
        "t2",
        [("a", 800, "t1", 0), ("c", 800, "x", 0), ("d", 800, "y", 0)],
        [("x1", 700), ("x2", 700), ("x3", 700)],
    )
    report = FlowTracer(FakeApi(pay, mix)).trace("target")
    assert next(n for n in report.destinations if n.address == "a").end == COINJOIN


def test_newly_mined_coins_end_the_trail():
    mined = Tx(
        txid="cb", version=2, locktime=0, fee=0, inputs=(), outputs=(), coinbase=True
    )
    api = FakeApi(mined, tx("t1", [("miner", 900, "cb", 0)], [("target", 800)]))
    assert FlowTracer(api).trace("target").origins[0].end == NEWLY_MINED


def test_only_spent_outputs_are_followed_not_the_address_history():
    # "relay" spent the coins of t2 but also has an unrelated older spend.
    unrelated = tx("old", [("relay", 5, "z", 0)], [("stranger", 4)])
    pay = tx("t1", [("target", 900)], [("relay", 800), ("rest", 77)])
    next_hop = tx("t2", [("relay", 800, "t1", 0)], [("end", 700)])
    report = FlowTracer(FakeApi(unrelated, pay, next_hop)).trace("target")
    relay = next(n for n in report.destinations if n.address == "relay")
    assert [c.address for c in relay.children] == ["end"]


def test_depth_limit_marks_the_trail():
    pay = tx("t1", [("target", 900)], [("a", 800), ("x", 77)])
    hop = tx("t2", [("a", 800, "t1", 0)], [("b", 700), ("y", 66)])
    report = FlowTracer(FakeApi(pay, hop), FlowLimits(max_depth=2)).trace("target")
    a = next(n for n in report.destinations if n.address == "a")
    assert a.children[0].end == DEPTH_LIMIT


def test_only_the_largest_branches_are_followed():
    outputs = [(f"o{n}", 1_100 + n) for n in range(4)]
    pay = tx("t1", [("target", 9_000)], [("a", 6_000), ("x", 77)])
    fan = tx("t2", [("a", 6_000, "t1", 0)], outputs)
    report = FlowTracer(FakeApi(pay, fan), FlowLimits(max_branches=2)).trace("target")
    a = next(n for n in report.destinations if n.address == "a")
    assert a.hidden == 2
    assert [c.address for c in a.children] == ["o3", "o2"]


def test_a_coin_is_not_walked_twice():
    pay = tx("t1", [("target", 9_000)], [("a", 6_000), ("b", 2_000)])
    join = tx("t2", [("a", 6_000, "t1", 0), ("b", 2_000, "t1", 1)], [("c", 7_000), ("d", 777)])
    next_hop = tx("t3", [("c", 7_000, "t2", 0)], [("e", 6_000), ("f", 555)])
    report = FlowTracer(FakeApi(pay, join, next_hop)).trace("target")
    ends = [chain[-1].end for root in report.destinations for chain in paths(root)]
    assert ALREADY_SHOWN in ends


def test_a_busy_target_is_refused():
    history = [tx(f"h{n}", [("z", 10)], [("target", 9)]) for n in range(3)]
    report = FlowTracer(FakeApi(*history), FlowLimits(max_address_txs=2)).trace("target")
    assert "3 transactions" in report.truncated
    assert report.origins == []


def test_the_main_flow_follows_the_largest_amounts():
    report = FlowTracer(round_trip_chain(), tags=EXCHANGE).trace("target")
    assert names(main_path(report.destinations)) == ["shop"]
    assert names(main_path(report.origins)) == ["relay", "Binance.com"]


def test_text_reads_as_a_chain():
    text = to_flow_text(FlowTracer(round_trip_chain(), tags=EXCHANGE).trace("target"))
    assert "Binance.com -> relay" in text
    assert "(back to target)" in text
    assert "[2-of-2 multisig]" in text
    assert text.isascii()


def test_json_export_keeps_the_tree():
    data = to_json(FlowTracer(round_trip_chain(), tags=EXCHANGE).trace("target"))
    assert data["origins"][0]["children"][0]["service"] == "Binance.com"


@pytest.mark.parametrize("extra", [["--summary"], ["--dot", "x.dot"]])
def test_flow_refuses_cluster_options(extra, capsys):
    address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    with pytest.raises(SystemExit):
        cli.main([address, "--flow", *extra])
    assert "--flow" in capsys.readouterr().err
