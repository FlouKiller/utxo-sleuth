import http.client
import json
import threading
import time

import pytest

from conftest import FakeApi, tx
from utxo_sleuth.ui import jobs
from utxo_sleuth.ui.jobs import Cancelled, Job, JobManager, UserError
from utxo_sleuth.ui.server import InterfaceServer

SEED = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def wait(job):
    deadline = time.time() + 5
    while job.state == "running" and time.time() < deadline:
        time.sleep(0.01)
    return job


@pytest.fixture
def server():
    def fail(params, job):
        raise UserError("Montant invalide")

    def slow(params, job):
        while True:
            job.check()
            time.sleep(0.01)

    runners = {"echo": lambda params, job: params, "fail": fail, "slow": slow}
    instance = InterfaceServer(0, JobManager(runners))
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    yield instance
    instance.shutdown()
    instance.server_close()


def request(server, method, path, body=None, headers=None):
    port = server.server_address[1]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    sent = {"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"}
    sent.update(headers or {})
    connection.request(method, path, json.dumps(body) if body is not None else None, sent)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, data


def view(server, job_id):
    return json.loads(request(server, "GET", f"/api/jobs/{job_id}")[1])


def start(server, kind, params=None):
    return json.loads(request(server, "POST", "/api/jobs", {"kind": kind, "params": params or {}})[1])


def finished(server, job_id):
    deadline = time.time() + 5
    while time.time() < deadline:
        current = view(server, job_id)
        if current["state"] != "running":
            return current
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def test_the_page_is_served(server):
    status, body = request(server, "GET", "/")
    assert status == 200
    assert "UTXO Sleuth".encode() in body


def test_the_page_loads_nothing_from_outside(server):
    page = request(server, "GET", "/")[1].decode("utf-8")
    assert "<script src" not in page
    assert "<link" not in page


def test_a_job_returns_its_result(server):
    created = start(server, "echo", {"a": 1})
    assert finished(server, created["id"])["result"] == {"a": 1}


def test_a_failed_job_keeps_its_message(server):
    created = start(server, "fail")
    result = finished(server, created["id"])
    assert (result["state"], result["error"]) == ("failed", "Montant invalide")


def test_a_job_can_be_cancelled(server):
    created = start(server, "slow")
    request(server, "POST", f"/api/jobs/{created['id']}/cancel", {})
    assert finished(server, created["id"])["state"] == "cancelled"


def test_an_unknown_kind_is_refused(server):
    assert request(server, "POST", "/api/jobs", {"kind": "nope"})[0] == 400


def test_another_host_is_refused(server):
    assert request(server, "GET", "/", headers={"Host": "evil.example"})[0] == 403


def test_a_form_post_from_a_website_is_refused(server):
    headers = {"Content-Type": "text/plain"}
    assert request(server, "POST", "/api/jobs", {"kind": "echo"}, headers)[0] == 415


def test_the_server_only_listens_locally(server):
    assert server.server_address[0] == "127.0.0.1"


@pytest.mark.parametrize(
    "params, message",
    [
        ({"unit": "usd"}, "montant"),
        ({"unit": "usd", "amount": "abc", "start": "2026-01-15T20:00"}, "invalide"),
        ({"unit": "usd", "amount": 10}, "début"),
        ({"unit": "sats", "amount": 10, "start": "hier"}, "Date invalide"),
        ({"unit": "usd", "amount": 10, "margin": 80, "start": "2026-01-15T20:00"}, "margin"),
        (
            {"unit": "usd", "amount": 10, "start": "2026-01-15T20:00", "end": "2026-01-15T19:00"},
            "après",
        ),
    ],
)
def test_search_explains_bad_input(params, message):
    with pytest.raises(UserError, match=message):
        jobs.run_search(params, Job("search"))


def test_flow_refuses_a_bad_address():
    with pytest.raises(UserError, match="adresse"):
        jobs.run_flow({"address": "nope"}, Job("flow"))


def test_cluster_needs_a_starting_point(monkeypatch):
    monkeypatch.setattr(jobs, "_api", lambda params, job: Closable())
    with pytest.raises(UserError, match="xpub"):
        jobs.run_cluster({}, Job("cluster"))


class Closable(FakeApi):
    requests = 0

    def close(self):
        pass


def test_cluster_returns_a_report_a_page_can_show(monkeypatch):
    api = Closable(tx("t", [(SEED, 10), ("other", 10)], [("x", 7), ("y", 12)]))
    monkeypatch.setattr(jobs, "_api", lambda params, job: api)
    result = jobs.run_cluster({"address": SEED}, Job("cluster"))
    json.dumps(result)
    assert set(result["members"]) == {SEED, "other"}
    assert "graph cluster" in result["dot"]


def test_flow_returns_a_report_a_page_can_show(monkeypatch):
    api = Closable(tx("t", [(SEED, 10)], [("x", 7), ("y", 2)]))
    monkeypatch.setattr(jobs, "_api", lambda params, job: api)
    result = jobs.run_flow({"address": SEED}, Job("flow"))
    json.dumps(result)
    assert result["destinations"][0]["address"] == "x"


def test_a_cancelled_job_stops_at_its_next_request():
    job = Job("flow")
    job.cancel.set()
    api = jobs._api({}, job)
    with pytest.raises(Cancelled):
        api.on_request()
    api.close()
