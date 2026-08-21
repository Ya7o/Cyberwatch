"""Préflight LLM strictement offline avant rebuild/reset de la base.

Cette commande n'instancie aucun collecteur et n'effectue aucun appel réseau.
Elle vérifie le routage effectif, inventorie les caches LLM et estime la part de
cache compatible avec les modèles actuellement sélectionnés.

Usage : ``python -m cyberwatch.llm_preflight``.
"""
from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import ai, llm_runtime

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"


@dataclass(frozen=True)
class CacheReport:
    name: str
    path: str
    entries: int
    compatible: int
    incompatible: int
    unknown_model: int
    effective_model: str

    @property
    def hit_rate(self) -> float:
        return round((self.compatible / self.entries * 100.0), 1) if self.entries else 100.0


def _csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _json(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}


def _model_from_value(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("model", "Model"):
            model = value.get(key)
            if isinstance(model, str) and model.strip():
                return model.strip()
    return ""


def _cache_values(payload: Any) -> list[Any]:
    """Retourne les vraies entrées d'un cache JSON, quel que soit son wrapper."""
    if not isinstance(payload, dict):
        return []
    entries = payload.get("entries")
    if isinstance(entries, dict):
        return list(entries.values())
    # Les caches sémantiques historiques sont plats ; ignorer les métadonnées
    # conventionnelles si elles existent à côté des entrées.
    return [
        value
        for key, value in payload.items()
        if not str(key).startswith("_") and isinstance(value, dict)
    ]


def _json_cache_report(name: str, path: Path, task: str) -> CacheReport:
    values = _cache_values(_json(path))
    effective = llm_runtime.model_for_task(task)
    compatible = incompatible = unknown = 0
    for value in values:
        model = _model_from_value(value)
        if not model:
            unknown += 1
        elif model == effective:
            compatible += 1
        else:
            incompatible += 1
    return CacheReport(
        name=name,
        path=str(path.relative_to(ROOT)),
        entries=len(values),
        compatible=compatible,
        incompatible=incompatible,
        unknown_model=unknown,
        effective_model=effective,
    )


def _latest_qualification_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Reproduit la sémantique du cache runtime : la dernière ligne gagne."""
    latest: dict[tuple[str, str], dict[str, str]] = {}
    anonymous: list[dict[str, str]] = []
    for row in rows:
        item_id = (row.get("Item_ID") or "").strip()
        input_hash = (row.get("Input_Hash") or "").strip()
        if item_id and input_hash:
            latest[(item_id, input_hash)] = row
        else:
            anonymous.append(row)
    return [*latest.values(), *anonymous]


def qualification_report() -> CacheReport:
    path = DATA / "ai_qualifications.csv"
    rows = _latest_qualification_rows(_csv_rows(path))
    effective = llm_runtime.model_for_task("qualification")
    compatible = incompatible = unknown = 0
    for row in rows:
        model = (row.get("Model") or "").strip()
        prompt = (row.get("Prompt_Version") or "").strip()
        if not model:
            unknown += 1
        elif model == effective and prompt == ai.PROMPT_VERSION:
            compatible += 1
        else:
            incompatible += 1
    return CacheReport(
        name="qualification",
        path=str(path.relative_to(ROOT)),
        entries=len(rows),
        compatible=compatible,
        incompatible=incompatible,
        unknown_model=unknown,
        effective_model=effective,
    )


def reports() -> list[CacheReport]:
    return [
        qualification_report(),
        _json_cache_report(
            "source_facts",
            DATA / "source_facts_ai_cache.json",
            "source_facts",
        ),
        _json_cache_report(
            "cyberattaque_semantic",
            DATA / "cyberattaque_semantic_cache.json",
            "cyberattaque_semantic",
        ),
    ]


def summary() -> dict[str, Any]:
    cache_reports = reports()
    known = sum(r.compatible + r.incompatible for r in cache_reports)
    compatible = sum(r.compatible for r in cache_reports)
    cold = sum(r.incompatible for r in cache_reports)
    unknown = sum(r.unknown_model for r in cache_reports)
    known_hit_rate = round(compatible / known * 100.0, 1) if known else 100.0
    reasons: list[str] = []
    if cold:
        reasons.append(f"{cold} entrée(s) de cache portent un modèle/prompt incompatible")
    if unknown:
        reasons.append(f"{unknown} entrée(s) de cache ne déclarent pas leur modèle")
    # Un cache froid est attendu après une migration de modèle mais il doit être
    # visible avant reset. En dessous de 75 % de compatibilité connue, le reset
    # cache-first reste possible mais une régénération LLM doit être planifiée à
    # part : le préflight retourne donc NO-GO pour un reset avec réchauffage.
    verdict = "GO" if known_hit_rate >= 75.0 else "NO-GO"
    return {
        "offline": True,
        "routing": {
            "qualification": llm_runtime.model_for_task("qualification"),
            "source_facts": llm_runtime.model_for_task("source_facts"),
            "cyberattaque_semantic": llm_runtime.model_for_task("cyberattaque_semantic"),
            "dedup": llm_runtime.model_for_task("dedup"),
        },
        "cache_reports": [asdict(r) | {"hit_rate": r.hit_rate} for r in cache_reports],
        "known_cache_hit_rate": known_hit_rate,
        "known_cold_entries": cold,
        "unknown_model_entries": unknown,
        "verdict": verdict,
        "reasons": reasons,
        "warning": (
            "Le préflight estime la compatibilité statique des caches ; il ne déclenche "
            "aucun LLM et ne prédit pas exactement le nombre de candidats du prochain run."
        ),
    }


def main() -> int:
    payload = summary()
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload["verdict"] == "GO" else 2


if __name__ == "__main__":
    raise SystemExit(main())
