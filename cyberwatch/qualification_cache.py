"""Cache sûr du rapport de qualification complet.

Le cache n'est utilisé que lorsque l'ensemble du snapshot pré-qualification est
strictement inchangé. Cette granularité évite les incohérences possibles d'un
skip item-par-item alors que certaines règles Sector travaillent au niveau de
l'organisation ou du corpus.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable, Mapping

from .model import Incident, Item
from .qualification_decision import QualificationDecision, summarize_decisions

CACHE_VERSION = "QUAL-CACHE-2"
CACHE_JSON_NAME = "qualification_cache.json"
USAGE_OBSERVATION_VERSION = "QUAL-CACHE-USAGE-1"
USAGE_METRIC_COLUMNS = [
    "Run_ID", "As_Of", "Mode", "Cache_Hit", "Cache_Miss_Reason",
    "Skipped_Items", "Cache_Version",
]
_CACHE_ENGINE_FILES = (
    "qualification.py",
    "qualification_cache.py",
    "qualification_decision.py",
    "dedup.py",
    "incident_identity.py",
    "identity.py",
    "model.py",
)


def cache_path(data_dir: Path) -> Path:
    return Path(data_dir) / CACHE_JSON_NAME


def pending_cache_path() -> Path:
    root = Path(os.getenv("RUNNER_TEMP") or tempfile.gettempdir())
    return root / "cyberwatch_qualification_cache_pending.json"


def usage_observation_path() -> Path:
    root = Path(os.getenv("RUNNER_TEMP") or tempfile.gettempdir())
    return root / "cyberwatch_qualification_cache_usage.json"


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _hash_payload(payload: object) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def rows_digest(rows: Iterable[Mapping[str, object]]) -> str:
    normalized = [
        {str(k): str(v or "") for k, v in sorted(row.items())}
        for row in rows
    ]
    normalized.sort(key=lambda row: json.dumps(row, ensure_ascii=False, sort_keys=True))
    return _hash_payload(normalized)


def engine_digest(root: Path) -> str:
    rows = []
    for name in _CACHE_ENGINE_FILES:
        path = Path(root) / "cyberwatch" / name
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest = ""
        rows.append((name, digest))
    return _hash_payload(rows)


def load_cache(data_dir: Path) -> dict:
    payload = _read_json(cache_path(data_dir))
    return payload if payload.get("Version") == CACHE_VERSION else {}


def write_pending_cache(payload: Mapping[str, object]) -> None:
    path = pending_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = dict(payload)
    data["Version"] = CACHE_VERSION
    path.write_text(
        json.dumps(data, ensure_ascii=False, sort_keys=True, indent=1) + "\n",
        encoding="utf-8",
    )


def load_pending_cache() -> dict:
    payload = _read_json(pending_cache_path())
    return payload if payload.get("Version") == CACHE_VERSION else {}


def clear_pending_cache() -> None:
    pending_cache_path().unlink(missing_ok=True)


def cache_matches(
    payload: Mapping[str, object],
    *,
    policy_version: str,
    dependency_digest: str,
    engine_digest_value: str,
    previous_provenance_digest: str,
    previous_registry_digest: str,
    prequalification_fingerprints: Mapping[str, str],
) -> tuple[bool, str]:
    if not payload:
        return False, "cache_absent"
    if payload.get("Version") != CACHE_VERSION:
        return False, "cache_version"
    if payload.get("Policy_Version") != policy_version:
        return False, "policy_version"
    if payload.get("Dependency_Digest") != dependency_digest:
        return False, "dependency_digest"
    if payload.get("Engine_Digest") != engine_digest_value:
        return False, "engine_digest"
    if payload.get("Next_Provenance_Digest") != previous_provenance_digest:
        return False, "provenance_changed"
    if payload.get("Next_Registry_Digest") != previous_registry_digest:
        return False, "incident_registry_changed"
    cached = payload.get("Prequalification_Fingerprints")
    if not isinstance(cached, dict):
        return False, "fingerprints_missing"
    normalized = {str(k): str(v) for k, v in cached.items()}
    expected = {str(k): str(v) for k, v in prequalification_fingerprints.items()}
    if normalized != expected:
        return False, "fingerprints_changed"
    return True, ""


def report_to_payload(
    report,
    *,
    policy_version: str,
    dependency_digest: str,
    engine_digest_value: str,
    prequalification_fingerprints: Mapping[str, str],
) -> dict:
    return {
        "Version": CACHE_VERSION,
        "Policy_Version": policy_version,
        "Dependency_Digest": dependency_digest,
        "Engine_Digest": engine_digest_value,
        "Next_Provenance_Digest": rows_digest(report.provenance),
        "Next_Registry_Digest": rows_digest(report.incident_id_registry),
        "Prequalification_Fingerprints": dict(sorted(prequalification_fingerprints.items())),
        "Items": [item.to_row() for item in report.items],
        "Incidents": [incident.to_row() for incident in report.incidents],
        "Changes": dict(report.changes),
        "Provenance": list(report.provenance),
        "Decisions": [decision.to_row() for decision in report.decisions],
        "Decision_Summary": list(report.decision_summary),
        "Incident_ID_Registry": list(report.incident_id_registry),
        "Items_Hash": report.items_hash,
        "Incidents_Hash": report.incidents_hash,
    }


def payload_parts(payload: Mapping[str, object]) -> dict:
    items = [Item.from_row(row) for row in payload.get("Items", []) if isinstance(row, dict)]
    incidents = [Incident.from_row(row) for row in payload.get("Incidents", []) if isinstance(row, dict)]
    decisions = [
        QualificationDecision.from_row(row)
        for row in payload.get("Decisions", [])
        if isinstance(row, dict)
    ]
    summary = payload.get("Decision_Summary")
    if not isinstance(summary, list):
        summary = summarize_decisions(decisions)
    return {
        "items": items,
        "incidents": incidents,
        "changes": dict(payload.get("Changes") or {}),
        "provenance": list(payload.get("Provenance") or []),
        "decisions": decisions,
        "decision_summary": summary,
        "incident_id_registry": list(payload.get("Incident_ID_Registry") or []),
        "items_hash": str(payload.get("Items_Hash") or ""),
        "incidents_hash": str(payload.get("Incidents_Hash") or ""),
    }


def write_usage_observation(*, hit: bool, miss_reason: str = "", skipped_items: int = 0) -> None:
    path = usage_observation_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "Version": USAGE_OBSERVATION_VERSION,
        "Cache_Hit": bool(hit),
        "Cache_Miss_Reason": miss_reason,
        "Skipped_Items": int(skipped_items),
        "Cache_Version": CACHE_VERSION,
    }
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def read_usage_observation() -> dict:
    payload = _read_json(usage_observation_path())
    return payload if payload.get("Version") == USAGE_OBSERVATION_VERSION else {}
