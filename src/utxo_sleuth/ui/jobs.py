"""Long analyses, run in background threads so the page can follow them."""

from __future__ import annotations

import argparse
import json
import threading
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from utxo_sleuth.cli import ADDRESS, moment
from utxo_sleuth.cluster import Limits, Tracer
from utxo_sleuth.esplora import (
    DEFAULT_API,
    DEFAULT_CACHE,
    ApiError,
    BudgetExceeded,
    Esplora,
)
from utxo_sleuth.export import breakdown, evaluate, to_dot, to_json
from utxo_sleuth.flow import FlowLimits, FlowTracer
from utxo_sleuth.labels import DEFAULT_LABELS, Labels, update_labels
from utxo_sleuth.search import (
    DEFAULT_MAX_BLOCKS,
    DEFAULT_MAX_RESULTS,
    Target,
    WindowTooLarge,
    find_outputs,
)
from utxo_sleuth.wallet import (
    KeyFileError,
    derive_addresses,
    first_used_address,
    read_public_key,
)

MAX_KEPT_JOBS = 30
DEFAULT_MAX_REQUESTS = 2000
ONE_HOUR = 3600


class UserError(ValueError):
    """A problem to show as it is, in the language of the interface."""


class Cancelled(Exception):
    pass


@dataclass
class Job:
    kind: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    state: str = "running"
    progress: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    cancel: threading.Event = field(default_factory=threading.Event)

    def check(self) -> None:
        if self.cancel.is_set():
            raise Cancelled

    def view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "state": self.state,
            "progress": self.progress,
            "result": self.result,
            "error": self.error,
        }


def _number(params, key, default, low, high, kind=int):
    value = params.get(key)
    if value in (None, ""):
        return default
    try:
        number = kind(value)
    except (TypeError, ValueError):
        raise UserError(f"Valeur invalide pour {key} : {value}") from None
    if not low <= number <= high:
        raise UserError(f"{key} doit être entre {low} et {high}.")
    return number


def _address(params) -> str:
    address = str(params.get("address") or "").strip()
    if not ADDRESS.match(address):
        raise UserError("Ce n'est pas une adresse Bitcoin valide.")
    return address


def _moment(params, key) -> int | None:
    text = params.get(key)
    if not text:
        return None
    try:
        return moment(text)
    except argparse.ArgumentTypeError:
        raise UserError(f"Date invalide : {text}") from None


def _api(params, job: Job) -> Esplora:
    api = Esplora(
        str(params.get("api") or DEFAULT_API),
        DEFAULT_CACHE,
        _number(params, "max_requests", DEFAULT_MAX_REQUESTS, 1, 100_000),
    )

    def on_request() -> None:
        job.check()
        job.progress["requests"] = api.requests

    api.on_request = on_request
    return api


def _labels(params) -> Labels:
    path = str(params.get("tags_file") or "").strip()
    extra = {}
    if path:
        try:
            extra = json.loads(Path(path).read_text("utf-8"))
        except OSError:
            raise UserError(f"Fichier d'étiquettes introuvable : {path}") from None
        except ValueError:
            raise UserError(f"Ce fichier n'est pas un JSON valide : {path}") from None
    return Labels(DEFAULT_LABELS, extra)


def run_cluster(params, job: Job) -> dict[str, Any]:
    xpub_file = str(params.get("xpub_file") or "").strip()
    truth_file = str(params.get("truth_file") or "").strip()
    defaults = Limits()
    limits = Limits(
        max_hops=_number(params, "max_hops", defaults.max_hops, 1, 20),
        min_confidence=_number(params, "min_confidence", defaults.min_confidence, 0, 1, float),
        max_addresses=_number(params, "max_addresses", defaults.max_addresses, 1, 5000),
        max_address_txs=_number(params, "max_address_txs", defaults.max_address_txs, 1, 100_000),
        max_inputs=_number(params, "max_inputs", defaults.max_inputs, 1, 10_000),
        change_threshold=_number(
            params, "change_threshold", defaults.change_threshold, 0, 1, float
        ),
    )
    public_key, wallet = None, set()
    if xpub_file:
        wallet = derive_addresses(read_public_key(Path(xpub_file)))
    truth = set()
    if truth_file:
        try:
            lines = Path(truth_file).read_text("utf-8").splitlines()
        except OSError:
            raise UserError(f"Fichier introuvable : {truth_file}") from None
        truth = {line.strip() for line in lines if line.strip()}
    address = str(params.get("address") or "").strip()
    labels = _labels(params)
    api = _api(params, job)
    try:
        if address:
            seed = _address(params)
        elif xpub_file:
            public_key = read_public_key(Path(xpub_file))
            seed = first_used_address(public_key, api)
            if seed is None:
                raise UserError("Aucune adresse utilisée trouvée dans ce wallet.")
        else:
            raise UserError("Indique une adresse ou un fichier xpub.")
        report = Tracer(api, limits, labels).trace(seed)
    finally:
        api.close()
        labels.close()
    result = to_json(report)
    result["dot"] = to_dot(report)
    result["requests"] = api.requests
    if wallet or truth:
        known = wallet or truth
        result["evaluation"] = {
            name: _score(evaluate(report, known, core_only), recall=bool(truth))
            for name, core_only in (("core", True), ("all", False))
        }
        result["evaluation"]["kinds"] = {
            kind: _score(score, recall=False) for kind, score in breakdown(report, known).items()
        }
    return result


def _score(score, recall: bool) -> dict[str, Any]:
    return {
        "found": score.found,
        "predicted": score.predicted,
        "expected": score.expected if recall else None,
        "precision": score.precision if score.predicted else None,
        "recall": score.recall if recall else None,
    }


def run_flow(params, job: Job) -> dict[str, Any]:
    target = _address(params)
    defaults = FlowLimits()
    limits = FlowLimits(
        max_depth=_number(params, "flow_depth", defaults.max_depth, 1, 30),
        max_branches=_number(params, "flow_branches", defaults.max_branches, 1, 20),
        max_nodes=_number(params, "flow_nodes", defaults.max_nodes, 1, 2000),
        max_address_txs=_number(params, "max_address_txs", defaults.max_address_txs, 1, 100_000),
    )
    labels = _labels(params)
    api = _api(params, job)
    try:
        report = FlowTracer(api, limits, labels).trace(target)
    finally:
        api.close()
        labels.close()
    result = to_json(report)
    result["requests"] = api.requests
    return result


def run_search(params, job: Job) -> dict[str, Any]:
    unit = params.get("unit")
    if unit == "usd":
        target = Target(
            usd=_number(params, "amount", None, 0.01, 1e10, float),
            margin_pct=_number(params, "margin", 0, 0, 50, float),
        )
        filled = target.usd
    else:
        target = Target(
            sats=_number(params, "amount", None, 1, 21 * 10**14),
            margin_pct=_number(params, "margin", 0, 0, 50, float),
        )
        filled = target.sats
    if filled is None:
        raise UserError("Indique un montant.")
    start = _moment(params, "start")
    if start is None:
        raise UserError("Indique le début du créneau.")
    end = _moment(params, "end") or start + ONE_HOUR
    if end <= start:
        raise UserError("La fin du créneau doit venir après le début.")
    max_blocks = _number(params, "max_blocks", DEFAULT_MAX_BLOCKS, 1, 1000)
    limit = _number(params, "max_results", DEFAULT_MAX_RESULTS, 1, 1000)

    def on_block(done: int, total: int) -> None:
        job.check()
        job.progress.update(done=done, total=total)

    api = _api(params, job)
    try:
        matches, blocks = find_outputs(api, target, start, end, max_blocks, on_block)
    except WindowTooLarge:
        raise UserError(
            f"Plus de {max_blocks} blocs dans ce créneau : réduis-le ou augmente la limite."
        ) from None
    finally:
        api.close()
    return {
        "matches": [asdict(match) for match in matches[:limit]],
        "total": len(matches),
        "blocks": blocks,
        "unit": unit,
        "requests": api.requests,
    }


def run_labels(params, job: Job) -> dict[str, Any]:
    done = []

    def log(line: str) -> None:
        job.check()
        done.append(line)
        job.progress["lines"] = list(done)

    return {"total": update_labels(DEFAULT_LABELS, log=log), "lines": done}


def labels_status() -> dict[str, Any]:
    if not DEFAULT_LABELS.exists():
        return {"downloaded": False}
    stat = DEFAULT_LABELS.stat()
    return {"downloaded": True, "size": stat.st_size, "updated": int(stat.st_mtime)}


RUNNERS: dict[str, Callable[[Any, Job], Any]] = {
    "cluster": run_cluster,
    "flow": run_flow,
    "search": run_search,
    "labels": run_labels,
}


class JobManager:
    def __init__(self, runners=RUNNERS) -> None:
        self.runners = runners
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(self, kind: str, params: dict[str, Any]) -> Job | None:
        if kind not in self.runners:
            return None
        job = Job(kind)
        with self._lock:
            self.jobs[job.id] = job
            for old in list(self.jobs)[:-MAX_KEPT_JOBS]:
                del self.jobs[old]
        threading.Thread(target=self._run, args=(job, params), daemon=True).start()
        return job

    def _run(self, job: Job, params: dict[str, Any]) -> None:
        try:
            job.result = self.runners[job.kind](params, job)
            job.state = "done"
        except Cancelled:
            job.state = "cancelled"
        except (UserError, KeyFileError) as exc:
            job.error, job.state = str(exc), "failed"
        except (ApiError, BudgetExceeded) as exc:
            job.error, job.state = f"Erreur de l'API : {exc}", "failed"
        except OSError as exc:
            job.error, job.state = f"Fichier ou réseau inaccessible : {exc}", "failed"
        except Exception as exc:  # A thread has nobody else to report to.
            job.error, job.state = f"Erreur inattendue : {exc}", "failed"

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)
