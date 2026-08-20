"""Primitives déterministes pour l'exécution incrémentale de la qualification.

Deux contrats coexistent volontairement :
- le fingerprint pré-qualification ne contient que les entrées brutes/stables et
  peut donc décider si le moteur doit retravailler un item ;
- le fingerprint post-qualification et le cache shadow vérifient que la sortie
  et sa provenance restent identiques d'un run au suivant.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable, Mapping

from .model import Item

QUALIFICATION_FINGERPRINT_VERSION = "QUAL-FP-2"
PREQUAL_FINGERPRINT_VERSION = "PREQUAL-FP-1"
SHADOW_CACHE_VERSION = "QUAL-SHADOW-1"
PREQUAL_OBSERVATION_VERSION = "PREQUAL-OBS-1"

QUALIFICATION_CODE_FILES = (
    "qualification.py",
    "qualification_decision.py",
    "qualification_policy.py",
    "enrichment.py",
    "sector.py",
    "context_sector.py",
    "sector_registry.py",
    "sector_registry_safety.py",
    "source_llm_fallback.py",
    "sector_fallback_migration.py",
)

PROCESSING_STATE_COLUMNS = [
    "Item_ID", "Qualification_Fingerprint", "Policy_Version", "Dependency_Digest",
    "Last_Processed_Run_ID", "Last_Processed_As_Of",
]
PREQUAL_STATE_COLUMNS = [
    "Item_ID", "Prequalification_Fingerprint", "Policy_Version", "Dependency_Digest",
    "Last_Qualified_Run_ID", "Last_Qualified_As_Of",
]
INCREMENTAL_METRIC_COLUMNS = [
    "Run_ID", "As_Of", "Mode", "Policy_Version", "Dependency_Digest", "Items_Count",
    "New_Items", "Dirty_Items", "Unchanged_Items", "Reuse_Rate", "Shadow_Checked",
    "Shadow_Mismatches", "Shadow_Mismatch_Rate",
    "Prequal_New_Items", "Prequal_Dirty_Items", "Prequal_Unchanged_Items",
    "Prequal_Reuse_Rate",
]
SHADOW_CACHE_COLUMNS = [
    "Item_ID", "Qualification_Fingerprint", "Output_Hash", "Provenance_Hash",
    "Cache_Version", "Run_ID", "As_Of",
]

_ITEM_FIELDS = (
    "Item_ID", "Source_ID", "Source_Item_ID", "Published_Date", "Event_Date",
    "Organisation_Raw", "Organisation_Key", "Threat_Raw", "Threat", "Sector",
    "Location", "Title", "URL",
)
_PREQUAL_ITEM_FIELDS = (
    "Item_ID", "Source_ID", "Source_Item_ID", "Published_Date", "Event_Date",
    "Organisation_Raw", "Organisation_Key", "Threat_Raw", "Title", "URL",
)
_OUTPUT_FIELDS = ("Item_ID", "Organisation_Key", "Threat", "Sector", "Location")


@dataclass(frozen=True)
class DirtySet:
    new: tuple[str, ...]
    dirty: tuple[str, ...]
    unchanged: tuple[str, ...]
    fingerprints: dict[str, str]

    @property
    def work_item_ids(self) -> tuple[str, ...]:
        return self.new + self.dirty

    @property
    def reuse_ratio(self) -> float:
        total = len(self.new) + len(self.dirty) + len(self.unchanged)
        return (len(self.unchanged) / total) if total else 1.0


@dataclass(frozen=True)
class ShadowResult:
    checked: int
    mismatches: tuple[str, ...]

    @property
    def mismatch_rate(self) -> float:
        return (len(self.mismatches) / self.checked) if self.checked else 0.0


def _stable_rows(rows: Iterable[Mapping[str, object]], *, ignored: frozenset[str] = frozenset()) -> list[dict[str, str]]:
    normalized = [{str(k): str(v or "") for k, v in sorted(row.items()) if str(k) not in ignored} for row in rows]
    return sorted(normalized, key=lambda row: json.dumps(row, ensure_ascii=False, sort_keys=True))


def _hash_payload(payload: object) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def dependency_digest(*, reference_rows: Iterable[Mapping[str, object]] = (), org_cache_rows: Iterable[Mapping[str, object]] = (), code_paths: Iterable[Path] = ()) -> str:
    code = []
    for path in sorted((Path(p) for p in code_paths), key=lambda p: str(p)):
        try:
            payload = path.read_bytes()
        except OSError:
            payload = b""
        code.append((path.name, hashlib.sha256(payload).hexdigest()))
    return _hash_payload({"reference": _stable_rows(reference_rows), "org_cache": _stable_rows(org_cache_rows), "code": code})


def qualification_dependency_digest(root: Path, *, reference_rows: Iterable[Mapping[str, object]] = (), org_cache_rows: Iterable[Mapping[str, object]] = ()) -> str:
    return dependency_digest(
        reference_rows=reference_rows,
        org_cache_rows=org_cache_rows,
        code_paths=[Path(root) / "cyberwatch" / name for name in QUALIFICATION_CODE_FILES],
    )


def _stable_fact_rows(rows: Iterable[Mapping[str, object]]) -> list[dict[str, str]]:
    return _stable_rows(rows, ignored=frozenset({"Item_ID", "Collected_As_Of"}))


def qualification_fingerprint(item: Item, source_facts: Iterable[Mapping[str, object]] = (), *, policy_version: str, dependency_digest_value: str = "") -> str:
    return _hash_payload({
        "fingerprint_version": QUALIFICATION_FINGERPRINT_VERSION,
        "policy_version": policy_version,
        "dependency_digest": dependency_digest_value,
        "item": {field: str(getattr(item, field, "") or "") for field in _ITEM_FIELDS},
        "source_facts": _stable_fact_rows(source_facts),
    })


def prequalification_fingerprint(item: Item, source_facts: Iterable[Mapping[str, object]] = (), *, policy_version: str, dependency_digest_value: str = "") -> str:
    """Empreinte des seules entrées qui peuvent influencer ``qualify()``."""
    return _hash_payload({
        "fingerprint_version": PREQUAL_FINGERPRINT_VERSION,
        "policy_version": policy_version,
        "dependency_digest": dependency_digest_value,
        "item": {field: str(getattr(item, field, "") or "") for field in _PREQUAL_ITEM_FIELDS},
        "source_facts": _stable_fact_rows(source_facts),
    })


def _classify(items: Iterable[Item], previous_fingerprints: Mapping[str, str], *, facts_by_item: Mapping[str, Iterable[Mapping[str, object]]] | None, fingerprint_fn, policy_version: str, dependency_digest_value: str) -> DirtySet:
    facts_by_item = facts_by_item or {}
    new, dirty, unchanged, fingerprints = [], [], [], {}
    for item in sorted(items, key=lambda value: value.Item_ID):
        fingerprint = fingerprint_fn(item, facts_by_item.get(item.Item_ID, ()), policy_version=policy_version, dependency_digest_value=dependency_digest_value)
        fingerprints[item.Item_ID] = fingerprint
        previous = previous_fingerprints.get(item.Item_ID)
        (new if previous is None else unchanged if previous == fingerprint else dirty).append(item.Item_ID)
    return DirtySet(tuple(new), tuple(dirty), tuple(unchanged), fingerprints)


def classify_items(items: Iterable[Item], previous_fingerprints: Mapping[str, str], *, facts_by_item: Mapping[str, Iterable[Mapping[str, object]]] | None = None, policy_version: str, dependency_digest_value: str = "") -> DirtySet:
    return _classify(items, previous_fingerprints, facts_by_item=facts_by_item, fingerprint_fn=qualification_fingerprint, policy_version=policy_version, dependency_digest_value=dependency_digest_value)


def classify_prequalification_items(items: Iterable[Item], previous_fingerprints: Mapping[str, str], *, facts_by_item: Mapping[str, Iterable[Mapping[str, object]]] | None = None, policy_version: str, dependency_digest_value: str = "") -> DirtySet:
    return _classify(items, previous_fingerprints, facts_by_item=facts_by_item, fingerprint_fn=prequalification_fingerprint, policy_version=policy_version, dependency_digest_value=dependency_digest_value)


def fingerprints_from_state(rows: Iterable[Mapping[str, object]], *, column: str = "Qualification_Fingerprint") -> dict[str, str]:
    return {str(row.get("Item_ID") or ""): str(row.get(column) or "") for row in rows if row.get("Item_ID") and row.get(column)}


def state_rows(dirty_set: DirtySet, *, policy_version: str, dependency_digest_value: str = "", run_id: str, as_of: str) -> list[dict[str, str]]:
    return [{"Item_ID": item_id, "Qualification_Fingerprint": fingerprint, "Policy_Version": policy_version, "Dependency_Digest": dependency_digest_value, "Last_Processed_Run_ID": run_id, "Last_Processed_As_Of": as_of} for item_id, fingerprint in sorted(dirty_set.fingerprints.items())]


def prequalification_state_rows(dirty_set: DirtySet, *, policy_version: str, dependency_digest_value: str = "", run_id: str, as_of: str) -> list[dict[str, str]]:
    return [{"Item_ID": item_id, "Prequalification_Fingerprint": fingerprint, "Policy_Version": policy_version, "Dependency_Digest": dependency_digest_value, "Last_Qualified_Run_ID": run_id, "Last_Qualified_As_Of": as_of} for item_id, fingerprint in sorted(dirty_set.fingerprints.items())]


def prequalification_observation_path() -> Path:
    root = Path(os.getenv("RUNNER_TEMP") or tempfile.gettempdir())
    return root / "cyberwatch_prequalification_observation.json"


def write_prequalification_observation(dirty_set: DirtySet, *, policy_version: str, dependency_digest_value: str) -> None:
    path = prequalification_observation_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "Version": PREQUAL_OBSERVATION_VERSION,
        "Policy_Version": policy_version,
        "Dependency_Digest": dependency_digest_value,
        "New": list(dirty_set.new),
        "Dirty": list(dirty_set.dirty),
        "Unchanged": list(dirty_set.unchanged),
        "Fingerprints": dirty_set.fingerprints,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def read_prequalification_observation() -> dict:
    path = prequalification_observation_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if payload.get("Version") == PREQUAL_OBSERVATION_VERSION else {}


def dirty_set_from_observation(payload: Mapping[str, object]) -> DirtySet | None:
    fingerprints = payload.get("Fingerprints")
    if not isinstance(fingerprints, dict):
        return None
    return DirtySet(
        tuple(str(v) for v in payload.get("New", []) if v),
        tuple(str(v) for v in payload.get("Dirty", []) if v),
        tuple(str(v) for v in payload.get("Unchanged", []) if v),
        {str(k): str(v) for k, v in fingerprints.items()},
    )


def _provenance_hash(item_id: str, rows: Iterable[Mapping[str, object]]) -> str:
    return _hash_payload(_stable_rows([row for row in rows if str(row.get("Item_ID") or "") == item_id]))


def shadow_cache_rows(items: Iterable[Item], fingerprints: Mapping[str, str], provenance_rows: Iterable[Mapping[str, object]], *, run_id: str, as_of: str) -> list[dict[str, str]]:
    provenance_rows = list(provenance_rows)
    rows = []
    for item in sorted(items, key=lambda value: value.Item_ID):
        rows.append({
            "Item_ID": item.Item_ID,
            "Qualification_Fingerprint": fingerprints.get(item.Item_ID, ""),
            "Output_Hash": _hash_payload({field: str(getattr(item, field, "") or "") for field in _OUTPUT_FIELDS}),
            "Provenance_Hash": _provenance_hash(item.Item_ID, provenance_rows),
            "Cache_Version": SHADOW_CACHE_VERSION, "Run_ID": run_id, "As_Of": as_of,
        })
    return rows


def compare_shadow_cache(previous_rows: Iterable[Mapping[str, object]], current_rows: Iterable[Mapping[str, object]], unchanged_item_ids: Iterable[str]) -> ShadowResult:
    previous = {str(row.get("Item_ID") or ""): row for row in previous_rows if row.get("Cache_Version") == SHADOW_CACHE_VERSION}
    current = {str(row.get("Item_ID") or ""): row for row in current_rows}
    checked, mismatches = 0, []
    for item_id in sorted(set(unchanged_item_ids)):
        left, right = previous.get(item_id), current.get(item_id)
        if left is None or right is None:
            continue
        checked += 1
        if left.get("Qualification_Fingerprint") != right.get("Qualification_Fingerprint") or left.get("Output_Hash") != right.get("Output_Hash") or left.get("Provenance_Hash") != right.get("Provenance_Hash"):
            mismatches.append(item_id)
    return ShadowResult(checked, tuple(mismatches))


def metric_row(dirty_set: DirtySet, *, run_id: str, as_of: str, mode: str, policy_version: str, dependency_digest_value: str = "", shadow: ShadowResult | None = None, prequal: DirtySet | None = None) -> dict[str, str]:
    shadow = shadow or ShadowResult(0, ())
    row = {
        "Run_ID": run_id, "As_Of": as_of, "Mode": mode, "Policy_Version": policy_version,
        "Dependency_Digest": dependency_digest_value, "Items_Count": str(len(dirty_set.fingerprints)),
        "New_Items": str(len(dirty_set.new)), "Dirty_Items": str(len(dirty_set.dirty)),
        "Unchanged_Items": str(len(dirty_set.unchanged)), "Reuse_Rate": f"{dirty_set.reuse_ratio:.6f}",
        "Shadow_Checked": str(shadow.checked), "Shadow_Mismatches": str(len(shadow.mismatches)),
        "Shadow_Mismatch_Rate": f"{shadow.mismatch_rate:.6f}",
        "Prequal_New_Items": "", "Prequal_Dirty_Items": "", "Prequal_Unchanged_Items": "",
        "Prequal_Reuse_Rate": "",
    }
    if prequal is not None:
        row.update({
            "Prequal_New_Items": str(len(prequal.new)),
            "Prequal_Dirty_Items": str(len(prequal.dirty)),
            "Prequal_Unchanged_Items": str(len(prequal.unchanged)),
            "Prequal_Reuse_Rate": f"{prequal.reuse_ratio:.6f}",
        })
    return row
