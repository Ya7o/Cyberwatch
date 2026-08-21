"""Préflight LLM strictement offline avant rebuild/reset de la base.

Cette commande n'instancie aucun collecteur et n'effectue aucun appel réseau.
Elle vérifie le routage effectif, inventorie les caches LLM et estime la part de
cache compatible avec les modèles actuellement sélectionnés.

Usage : ``python -m cyberwatch.llm_preflight``.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from . import ai, llm_runtime, source_facts_ai

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


def _json_cache_report(name: str, path: Path, task: str) -> CacheReport:
    payload = _json(path)
    values = list(payload.values()) if isinstance(payload, dict) else []
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


def qualification_report() -> CacheReport:
    path = DATA / "ai_qualifications.csv"
    rows = _csv_rows(path)
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
    # Un cache froid n'est pas une erreur : il doit seulement être visible avant
    # un reset. Le NO-GO est réservé à une couverture connue très faible.
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
            "aucun LLM et ne prétend pas prédire exactement le nombre de candidats du prochain run."
        ),
    }


def main() -> int:
    payload = summary()
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload["verdict"] == "GO" else 2


if __name__ == "__main__":
    raise SystemExit(main())
