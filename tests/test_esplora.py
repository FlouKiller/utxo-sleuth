import httpx
import pytest

from utxo_sleuth.esplora import ApiError, BudgetExceeded, Esplora
from utxo_sleuth.models import Tx

CONFIRMED = {"confirmed": True}


def raw_tx(txid, status=CONFIRMED):
    return {
        "txid": txid,
        "version": 2,
        "locktime": 0,
        "fee": 200,
        "status": status,
        "vin": [
            {
                "sequence": 0xFFFFFFFD,
                "prevout": {
                    "scriptpubkey_address": "a",
                    "scriptpubkey_type": "v0_p2wpkh",
                    "value": 1_000,
                },
            }
        ],
        "vout": [
            {"scriptpubkey_address": "b", "scriptpubkey_type": "p2pkh", "value": 800},
            {"scriptpubkey_type": "op_return", "value": 0},
        ],
    }


@pytest.fixture
def client(tmp_path):
    api = Esplora("https://esplora.test/api", tmp_path / "cache.sqlite", min_interval=0)
    yield api
    api.close()


def serve(api, handler):
    api._http = httpx.Client(transport=httpx.MockTransport(handler))


def test_parsing_keeps_what_the_heuristics_need():
    parsed = Tx.from_esplora(raw_tx("t"))
    assert parsed.input_addresses == ["a"]
    assert [o.address for o in parsed.spendable_outputs] == ["b"]
    assert parsed.fingerprint.signals_rbf
    assert not parsed.fingerprint.uses_locktime


def test_a_multisig_spend_is_recognised():
    data = raw_tx("t")
    data["vin"][0]["inner_witnessscript_asm"] = (
        "OP_PUSHNUM_2 OP_PUSHBYTES_33 02b7 OP_PUSHBYTES_33 037d OP_PUSHNUM_2 OP_CHECKMULTISIG"
    )
    assert Tx.from_esplora(data).inputs[0].multisig == "2-of-2"


def test_a_plain_spend_is_not_a_multisig():
    assert Tx.from_esplora(raw_tx("t")).inputs[0].multisig is None


def test_a_confirmed_transaction_knows_its_height():
    assert Tx.from_esplora(raw_tx("t", {"confirmed": True, "block_height": 7})).height == 7
    assert Tx.from_esplora(raw_tx("t", {"confirmed": False})).height is None


def test_coinbase_has_no_input_addresses():
    data = raw_tx("t")
    data["vin"] = [{"is_coinbase": True, "prevout": None, "sequence": 0}]
    parsed = Tx.from_esplora(data)
    assert parsed.coinbase
    assert parsed.input_addresses == []


def test_confirmed_transactions_are_served_from_the_cache(client):
    hits = []

    def handler(request):
        hits.append(request.url.path)
        return httpx.Response(200, json=raw_tx("t"))

    serve(client, handler)
    client.tx("t")
    client.tx("t")
    assert len(hits) == 1


def test_address_history_follows_pagination(client):
    def handler(request):
        path = request.url.path
        if path.endswith("/txs"):
            return httpx.Response(200, json=[raw_tx("t1"), raw_tx("t2")])
        if path.endswith("/txs/chain/t2"):
            return httpx.Response(200, json=[raw_tx("t3")])
        raise AssertionError(path)

    serve(client, handler)
    assert [t.txid for t in client.address_txs("a", 3)] == ["t1", "t2", "t3"]


def test_rate_limits_are_retried(client):
    answers = iter(
        [
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json=[{"spent": True, "txid": "n"}, {"spent": False}]),
        ]
    )
    serve(client, lambda request: next(answers))
    assert client.outspends("t") == ["n", None]


def test_a_refused_request_raises(client):
    serve(client, lambda request: httpx.Response(400, text="Invalid Bitcoin address"))
    with pytest.raises(ApiError, match="Invalid Bitcoin address"):
        client.address_stats("nope")


def test_the_request_budget_is_enforced(client):
    client.max_requests = 1
    serve(client, lambda request: httpx.Response(200, json=raw_tx("t")))
    client.tx("t1")
    with pytest.raises(BudgetExceeded):
        client.tx("t2")
