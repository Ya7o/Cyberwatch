"""Préflight, manifeste et comparaison pour un vrai reset à froid.

Ce module ne publie jamais de données et ne déclenche aucun appel réseau.
Il sert de garde avant le workflow ``cold-reset.yml``.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import llm_preflight, llm_runtime
from .llm_legacy_bridge import normalize_legacy_request

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

#: Référentiels statiques que le code ne sait pas régénérer. Leur absence
#: interdit toute reconstruction, quel que soit le mode. Miroir de
#: `zero_reset.PRESERVED_DATA_PATHS`, dont un test garantit l'alignement.
BOOTSTRAP_REFERENCE_FILES = (
    "enrichment_reference.csv",
    "organisation_aliases.csv",
    "sector_auto_policy.json",
    "territorial_identities.csv",
)

#: État calculé par les runs précédents. Un `rebuild` s'appuie dessus et exige
#: sa présence ; un `zero` le détruit délibérément, et son absence y est un
#: résultat attendu, pas une anomalie.
IDENTITY_STATE_FILES = (
    "incident_id_registry.csv",
    "organisation_sector_registry.csv",
    "quality_baseline.json",
)

PROTECTED_FILES = tuple(BOOTSTRAP_REFERENCE_FILES + IDENTITY_STATE_FILES)

MODE_REBUILD = "rebuild"
MODE_ZERO = "zero"

COLD_CACHE_FILES = (
    "ai_qualifications.csv",
    "source_facts_ai_cache.json",
    "cyberattaque_semantic_cache.json",
    "rich_facts_semantic_cache.json",
    "org_enrichment_cache.csv",
    "qualification_shadow_cache.csv",
    "qualification_provenance.csv",
    "prequalification_state.csv",
    "item_processing_state.csv",
)

DERIVED_FILES = (
    "items.csv",
    "incidents.csv",
    "source_facts.csv",
    "snapshot.json",
    "baseline.json",
    "dedup_audit_candidates.csv",
    "ai_usage.csv",
    "llm_usage.json",
    "source_facts_ai_usage.json",
)


@dataclass(frozen=True)
class FileState:
    path: str
    exists: bool
    size: int = 0
    sha256: str = ""
    rows: int | None = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _csv_rows(path: Path) -> int | None:
    if path.suffix.lower() != ".csv":
        return None
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return sum(1 for _ in csv.reader(handle)) - 1
    except (OSError, UnicodeError):
        return None


def file_state(path: Path) -> FileState:
    if not path.exists():
        return FileState(str(path.relative_to(ROOT)), False)
    return FileState(
        str(path.relative_to(ROOT)), True, path.stat().st_size, _sha256(path), _csv_rows(path)
    )


def _usage() -> dict[str, Any]:
    path = DATA / "llm_usage.json"
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _task_average_seconds(task: str, default: float) -> float:
    bucket = (_usage().get("by_task") or {}).get(task) or {}
    calls = int(bucket.get("calls_succeeded", 0) or 0)
    duration = float(bucket.get("duration_seconds", 0.0) or 0.0)
    return duration / calls if calls and duration else default


def _task_average_cost(task: str, default: float) -> float:
    bucket = (_usage().get("by_task") or {}).get(task) or {}
    calls = int(bucket.get("calls_succeeded", 0) or 0)
    cost = float(bucket.get("estimated_cost_usd", 0.0) or 0.0)
    return cost / calls if calls and cost else default


def _cache_counts() -> dict[str, int]:
    reports = {r.name: r for r in llm_preflight.reports()}
    return {name: report.entries for name, report in reports.items()}


def estimate() -> dict[str, Any]:
    """Estimation prudente d'une première passe froide, sans réseau."""
    counts = _cache_counts()
    candidates = {
        "qualification": max(counts.get("qualification", 0), 1),
        "cyberattaque_semantic": max(counts.get("cyberattaque_semantic", 0), 1),
        "source_facts": max(counts.get("source_facts", 0), 1),
    }
    estimates: dict[str, dict[str, Any]] = {}
    defaults = {
        "qualification": (1.5, 0.00008),
        "cyberattaque_semantic": (7.4, 0.00061),
        "source_facts": (4.0, 0.00035),
    }
    total_seconds = 0.0
    total_cost = 0.0
    for task, candidate_count in candidates.items():
        budget = llm_runtime.DEFAULT_TASK_BUDGETS.get(task, {})
        max_calls = int(budget.get("max_calls", candidate_count) or candidate_count)
        first_pass_calls = min(candidate_count, max_calls)
        seconds_per_call = _task_average_seconds(task, defaults[task][0])
        cost_per_call = _task_average_cost(task, defaults[task][1])
        duration = first_pass_calls * seconds_per_call
        cost = first_pass_calls * cost_per_call
        total_seconds += duration
        total_cost += cost
        estimates[task] = {
            "candidates_proxy": candidate_count,
            "first_pass_calls": first_pass_calls,
            "deferred_proxy": max(0, candidate_count - first_pass_calls),
            "seconds_per_call": round(seconds_per_call, 3),
            "estimated_seconds": round(duration, 1),
            "estimated_cost_usd": round(cost, 4),
        }
    # Collecte + validation + enrichissement registre : enveloppe fixe prudente.
    overhead_seconds = 12 * 60
    total_seconds += overhead_seconds
    return {
        "tasks": estimates,
        "overhead_seconds": overhead_seconds,
        "estimated_first_pass_minutes": round(total_seconds / 60, 1),
        "estimated_first_pass_cost_usd": round(total_cost, 3),
        "recommended_timeout_minutes": max(90, int(total_seconds / 60) + 30),
        "recommended_cost_cap_usd": max(0.50, round(total_cost * 2 + 0.05, 2)),
        "warning": "Les nombres de candidats sont des proxys de cache, pas un dry-run exact du collecteur.",
    }


def preflight(mode: str = MODE_REBUILD) -> dict[str, Any]:
    llm = llm_preflight.summary()
    protected = [file_state(DATA / name) for name in PROTECTED_FILES]
    required = set(BOOTSTRAP_REFERENCE_FILES)
    if mode != MODE_ZERO:
        required |= set(IDENTITY_STATE_FILES)
    missing_protected = [
        state.path
        for name, state in zip(PROTECTED_FILES, protected)
        if not state.exists and name in required
    ]
    # En mode zero, l'état d'identité a été purgé volontairement : on le
    # rapporte pour la traçabilité sans en faire un blocage.
    purged_state = [
        state.path
        for name, state in zip(PROTECTED_FILES, protected)
        if not state.exists and name not in required
    ]

    source_model = llm_runtime.model_for_task("source_facts")
    probe = normalize_legacy_request(
        "source_facts",
        {"model": "gpt-5-nano", "reasoning": {"effort": "minimal"}},
    )
    bridge_ok = probe.get("model") == source_model and (
        not source_model.startswith("gpt-4o") or "reasoning" not in probe
    )

    reasons: list[str] = []
    if missing_protected:
        reasons.append("référentiels/identités protégés absents: " + ", ".join(missing_protected))
    if not bridge_ok:
        reasons.append("contrat SourceFacts legacy non aligné avec le runtime central")

    return {
        "offline": True,
        "mode": mode,
        "verdict": "GO" if not reasons else "NO-GO",
        "reasons": reasons,
        "purged_state_files": purged_state,
        "routing": llm.get("routing", {}),
        "source_facts_bridge_ok": bridge_ok,
        "protected_files": [asdict(state) for state in protected],
        "cold_cache_files": [asdict(file_state(DATA / name)) for name in COLD_CACHE_FILES],
        "derived_files": [asdict(file_state(DATA / name)) for name in DERIVED_FILES],
        "llm_cache_preflight": llm,
        "estimate": estimate(),
    }


def manifest(mode: str = MODE_REBUILD) -> dict[str, Any]:
    names = sorted(set(PROTECTED_FILES + COLD_CACHE_FILES + DERIVED_FILES))
    return {
        "schema": "cyberwatch-cold-reset-manifest-v1",
        "mode": mode,
        "files": [asdict(file_state(DATA / name)) for name in names],
        "preflight": preflight(mode),
    }


def _read_ids(path: Path, column: str) -> set[str]:
    if not path.exists():
        return set()
    with path.open(encoding="utf-8", newline="") as handle:
        return {str(row.get(column) or "") for row in csv.DictReader(handle) if row.get(column)}


def compare(before: Path, after: Path, id_column: str) -> dict[str, Any]:
    old = _read_ids(before, id_column)
    new = _read_ids(after, id_column)
    return {
        "id_column": id_column,
        "before": len(old),
        "after": len(new),
        "lost": sorted(old - new),
        "added": sorted(new - old),
        "churn_count": len(old ^ new),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cyberwatch.cold_reset")
    sub = parser.add_subparsers(dest="command", required=True)
    preflight_parser = sub.add_parser("preflight")
    preflight_parser.add_argument("--mode", choices=(MODE_REBUILD, MODE_ZERO), default=MODE_REBUILD)
    manifest_parser = sub.add_parser("manifest")
    manifest_parser.add_argument("--mode", choices=(MODE_REBUILD, MODE_ZERO), default=MODE_REBUILD)
    manifest_parser.add_argument("--output")
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("--before", required=True)
    compare_parser.add_argument("--after", required=True)
    compare_parser.add_argument("--id-column", required=True)
    args = parser.parse_args(argv)

    if args.command == "preflight":
        payload = preflight(args.mode)
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if payload["verdict"] == "GO" else 2
    if args.command == "manifest":
        payload = manifest(args.mode)
        text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        return 0 if payload["preflight"]["verdict"] == "GO" else 2
    payload = compare(Path(args.before), Path(args.after), args.id_column)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
