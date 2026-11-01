import pytest

from conftest import P2PKH, FakeApi, tx
from utxo_sleuth.cluster import (
    CHANGE,
    COMMON_INPUT_CONFIDENCE,
    CONSOLIDATION,
    Limits,
    Tracer,
)
from utxo_sleuth.esplora import BudgetExceeded
from utxo_sleuth.export import evaluate, to_dot, to_json, to_text


def members(report):
    return set(report.members)


def clear_payment(txid, sender, change, receiver="shop"):
    return tx(
        txid,
        [(sender, 500_000)],
        [(receiver, 100_000, P2PKH), (change, 399_123)],
    )


def test_common_inputs_are_linked_transitively():
    api = FakeApi(
        tx("t1", [("a", 10), ("b", 10)], [("x", 7), ("y", 12)]),
        tx("t2", [("b", 10), ("c", 10)], [("v", 8), ("w", 11)]),
    )
    report = Tracer(api).trace("a")
    assert members(report) == {"a", "b", "c"}
    assert report.members["c"].confidence == pytest.approx(COMMON_INPUT_CONFIDENCE**2)
    assert all(m.core for m in report.members.values())


def test_outgoing_change_is_probable_not_core():
    report = Tracer(FakeApi(clear_payment("t", "a", "rest"))).trace("a")
    assert members(report) == {"a", "rest"}
    assert report.members["rest"].via.kind == CHANGE
    assert report.members["rest"].via.reasons
    assert not report.members["rest"].core


def test_change_links_back_to_the_inputs():
    report = Tracer(FakeApi(clear_payment("t", "sender", "a"))).trace("a")
    assert "sender" in members(report)


def test_a_payment_received_does_not_link_the_sender():
    report = Tracer(FakeApi(clear_payment("t", "sender", "rest", receiver="a"))).trace("a")
    assert members(report) == {"a"}


def test_consolidation_links_both_ways():
    api = FakeApi(tx("t", [("a", 10), ("b", 10)], [("vault", 19)]))
    assert Tracer(api).trace("a").members["vault"].via.kind == CONSOLIDATION
    assert members(Tracer(api).trace("vault")) == {"vault", "a", "b"}


def test_a_coinjoin_links_nothing():
    mix = tx(
        "mix",
        [("a", 200_000), ("stranger1", 200_000), ("stranger2", 200_000)],
        [("x", 100_000), ("y", 100_000), ("z", 100_000)],
    )
    report = Tracer(FakeApi(mix)).trace("a")
    assert members(report) == {"a"}
    assert report.skipped_txs == {"mix": "looks like a CoinJoin"}


def test_a_tagged_service_is_kept_but_not_expanded():
    api = FakeApi(
        tx("t1", [("a", 10), ("exchange", 10)], [("x", 7), ("y", 12)]),
        tx("t2", [("exchange", 10), ("customer", 10)], [("v", 8), ("w", 11)]),
    )
    report = Tracer(api, tags={"exchange": "Some Exchange"}).trace("a")
    assert members(report) == {"a", "exchange"}
    assert report.boundaries == {"exchange": "tagged: Some Exchange"}


def test_a_busy_address_is_not_expanded():
    api = FakeApi(
        tx("t1", [("a", 10), ("busy", 10)], [("x", 7), ("y", 12)]),
        tx("t2", [("busy", 10), ("customer", 10)], [("v", 8), ("w", 11)]),
    )
    report = Tracer(api, Limits(max_address_txs=1)).trace("a")
    assert "customer" not in members(report)
    assert "busy" in report.boundaries


def test_too_many_inputs_are_ignored():
    inputs = [("a", 10)] + [(f"i{n}", 10) for n in range(5)]
    report = Tracer(FakeApi(tx("big", inputs, [("x", 7), ("y", 12)])), Limits(max_inputs=3)).trace("a")
    assert members(report) == {"a"}
    assert "big" in report.skipped_txs


def test_hop_limit():
    api = FakeApi(
        tx("t1", [("a", 10), ("b", 10)], [("x", 7), ("y", 12)]),
        tx("t2", [("b", 10), ("c", 10)], [("v", 8), ("w", 11)]),
    )
    report = Tracer(api, Limits(max_hops=1)).trace("a")
    assert members(report) == {"a", "b"}
    assert report.unexpanded == 1


def test_confidence_floor_stops_weak_chains():
    api = FakeApi(
        tx("t1", [("a", 10)], [("b", 9)]),
        tx("t2", [("b", 9)], [("c", 8)]),
    )
    assert members(Tracer(api, Limits(min_confidence=0.3)).trace("a")) == {"a", "b"}


def test_address_limit_truncates_visibly():
    inputs = [("a", 10)] + [(f"i{n}", 10) for n in range(5)]
    report = Tracer(FakeApi(tx("t", inputs, [("x", 7), ("y", 12)])), Limits(max_addresses=3)).trace("a")
    assert len(report.members) == 3
    assert "address limit" in report.truncated


def test_running_out_of_budget_keeps_partial_results():
    class Limited(FakeApi):
        def address_txs(self, address, expected):
            if address == "b":
                raise BudgetExceeded("request budget of 1 used up")
            return super().address_txs(address, expected)

    api = Limited(tx("t1", [("a", 10), ("b", 10)], [("x", 7), ("y", 12)]))
    report = Tracer(api).trace("a")
    assert members(report) == {"a", "b"}
    assert "budget" in report.truncated


def test_a_stronger_path_replaces_a_weaker_one():
    api = FakeApi(
        tx("sweep", [("a", 10)], [("b", 9)]),
        tx("join", [("a", 10), ("b", 10)], [("x", 7), ("y", 12)]),
    )
    report = Tracer(api).trace("a")
    assert report.members["b"].confidence == pytest.approx(COMMON_INPUT_CONFIDENCE)


def test_a_refund_after_the_payment_is_not_reuse():
    funding = tx(
        "funding",
        [("sender", 410_321)],
        [("a", 383_204), ("deposit", 27_000, P2PKH)],
        height=100,
    )
    refund = tx("refund", [("contract", 8_211)], [("a", 8_020)], height=110)
    report = Tracer(FakeApi(funding, refund)).trace("a")
    assert "sender" in members(report)


def test_earlier_funding_is_reuse():
    earlier = tx("earlier", [("z", 5_000)], [("a", 4_000), ("b", 777)], height=90)
    funding = tx(
        "funding",
        [("sender", 410_321)],
        [("a", 383_204), ("deposit", 27_000, P2PKH)],
        height=100,
    )
    report = Tracer(FakeApi(earlier, funding)).trace("a")
    assert "sender" not in members(report)


def test_the_walk_stops_at_a_multisig():
    api = FakeApi(
        tx("t1", [("shared", 21_310)], [("a", 21_102)], multisig="2-of-2"),
        tx("t2", [("shared", 8_211)], [("stranger", 8_020)], multisig="2-of-2"),
    )
    report = Tracer(api).trace("a")
    assert members(report) == {"a", "shared"}
    assert report.boundaries == {"shared": "2-of-2 multisig, possibly shared"}
    assert report.members["shared"].via.reasons == (
        "- spent from a 2-of-2 multisig, possibly shared",
    )


def test_a_withdrawal_from_a_labelled_exchange_is_reported():
    api = FakeApi(tx("w", [("hot", 900)], [("a", 500), ("b", 399)]))
    report = Tracer(api, tags={"hot": "Binance.com"}).trace("a")
    assert members(report) == {"a"}
    assert [(s.service, s.direction) for s in report.services] == [
        ("Binance.com", "received_from")
    ]


def test_a_deposit_to_a_labelled_exchange_is_reported():
    api = FakeApi(tx("d", [("a", 900)], [("hot", 800)]))
    report = Tracer(api, tags={"hot": "Kraken.com"}).trace("a")
    assert members(report) == {"a"}
    assert [(s.service, s.direction) for s in report.services] == [("Kraken.com", "sent_to")]


def test_a_large_payout_is_reported_as_an_unknown_service():
    outputs = [(f"o{n}", 1_100 + n) for n in range(19)] + [("a", 5_555)]
    report = Tracer(FakeApi(tx("batch", [("hot", 99_999)], outputs))).trace("a")
    assert report.services[0].service == "unknown service (payout to 20 addresses)"


def small_batch(sender, change=None):
    outputs = [(f"o{n}", 1_100 + n) for n in range(5)] + [("a", 5_555)]
    if change:
        outputs.append((change, 77_777))
    return tx("batch", [(sender, 99_999)], outputs)


def test_a_small_batch_paying_the_sender_back_is_a_payout():
    report = Tracer(FakeApi(small_batch("hot", change="hot"))).trace("a")
    assert report.services[0].service == "unknown service (payout to 7 addresses)"


def test_a_small_batch_from_a_busy_sender_is_a_payout():
    history = [tx(f"h{n}", [("z", 10)], [("hot", 9)]) for n in range(50)]
    report = Tracer(FakeApi(small_batch("hot"), *history)).trace("a")
    assert report.services[0].service == "unknown service (payout to 6 addresses)"


def test_a_small_batch_from_a_quiet_sender_is_not_a_payout():
    assert Tracer(FakeApi(small_batch("friend"))).trace("a").services == []


def test_two_outputs_from_a_sender_paying_itself_back_is_not_a_payout():
    assert Tracer(FakeApi(tx("t", [("x", 9_000)], [("a", 5_555), ("x", 3_333)]))).trace("a").services == []


def test_evaluation_against_a_known_wallet():
    report = Tracer(FakeApi(clear_payment("t", "a", "rest"))).trace("a")
    assert evaluate(report, {"a", "rest", "unused"}).recall == 0.5
    assert evaluate(report, {"a", "rest", "unused"}).precision == 1.0
    assert evaluate(report, {"a", "rest"}, core_only=True).predicted == 0


def test_exports_cover_the_report():
    report = Tracer(FakeApi(clear_payment("t", "a", "rest"))).trace("a")
    assert "rest" in to_text(report)
    assert '"a" -- "rest"' in to_dot(report)
    assert to_json(report)["members"]["rest"]["via"]["kind"] == CHANGE
