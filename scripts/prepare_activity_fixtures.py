"""Promeut les six couples activité/secteur de RUN-20260910T125214 en fixtures.

La collecte est le premier run où l'extraction a réellement tourné : douze
appels, douze succès, six couples demandés, zéro accepté. Ses réponses et les
contextes exacts qui les ont produites sont figés ici pour que chaque décision
du validateur reste reproductible sans réseau ni clé d'API.

Source : `git show f714507:data/llm_runs/RUN-20260910T125214/source_facts_ai_trace.json`
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "fixtures" / "activity_20260910"
COMMIT = "f714507"
TRACE = "data/llm_runs/RUN-20260910T125214/source_facts_ai_trace.json"
ACTIVITY_FIELDS = ("activity_description", "activity_sector_match")


def _output_text(response: dict) -> str:
    for block in response.get("output", []):
        for part in block.get("content", []):
            if part.get("type") == "output_text":
                return str(part.get("text") or "")
    return ""


def _user_prompt(request: dict) -> str:
    for message in request.get("input", []):
        if message.get("role") == "user":
            return str(message.get("content") or "")
    return ""


def main() -> int:
    try:
        raw = subprocess.run(
            ["git", "show", f"{COMMIT}:{TRACE}"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"TRACE INTROUVABLE ({COMMIT}) : {exc}")
        return 1

    TARGET.mkdir(parents=True, exist_ok=True)
    cases = []
    for event in json.loads(raw):
        if "activity_description" not in (event.get("requested_fields") or []):
            continue
        proposal = json.loads(_output_text(event["response"]))
        cases.append({
            "item_id": event["item_id"],
            "source_id": event["source_id"],
            "organisation": event["organisation"],
            "url": event["url"],
            "content_hash": event["content_hash"],
            "context": _user_prompt(event["request"]),
            "proposal": {field: proposal.get(field) for field in ACTIVITY_FIELDS},
            "recorded_rejections": {
                field: value for field, value in (event.get("rejections") or {}).items()
                if field in ACTIVITY_FIELDS
            },
        })
    if len(cases) != 6:
        print(f"ATTENDU 6 couples, TROUVÉ {len(cases)}")
        return 1
    path = TARGET / "run_20260910T125214.json"
    path.write_text(
        json.dumps({"run_id": "RUN-20260910T125214", "commit": COMMIT,
                    "prompt_version": "2026-09-05.source-facts.16", "cases": cases},
                   ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"OK : {len(cases)} couples -> {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
