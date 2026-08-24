#!/usr/bin/env python3
"""Audite un corpus de validation déjà reconstruit, sans le modifier."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cyberwatch import store
from cyberwatch.headline import is_organisation_name_only, is_publishable_headline
from cyberwatch.validation_corpus import ValidationCorpus, canonical_url


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    corpus = ValidationCorpus.load(args.manifest)
    items = store.load_items()
    incidents = store.load_incidents()
    problems = corpus.audit(items, incidents)
    try:
        published = json.loads((store.SITE_DATA_DIR / "incidents.json").read_text(encoding="utf-8"))
        facts = json.loads((store.SITE_DATA_DIR / "facts.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        published, facts = [], {}
        problems.append(f"Corpus validation : actifs publiés illisibles ({type(exc).__name__})")

    targets_by_case: dict[str, set[tuple[str, str]]] = {}
    for target in corpus.targets:
        targets_by_case.setdefault(target.case_id, set()).add(target.key)
    case_reports = []
    for case_id, expected in sorted(targets_by_case.items()):
        matches = []
        for row in published if isinstance(published, list) else []:
            links = {
                (str(link.get("source") or ""), canonical_url(str(link.get("url") or "")))
                for link in row.get("source_links", []) if isinstance(link, dict) and link.get("url")
            }
            if links == expected:
                matches.append(row)
        if len(matches) != 1:
            problems.append(f"Corpus validation : fiche publiée introuvable pour {case_id}")
            continue
        row = matches[0]
        summary = str(row.get("summary") or "").strip()
        if not is_publishable_headline(summary) or is_organisation_name_only(summary, str(row.get("org") or "")):
            problems.append(f"Corpus validation : synthèse éditoriale absente ou invalide pour {case_id}")
        detail = facts.get(str(row.get("id") or ""), {}) if isinstance(facts, dict) else {}
        initial_access = str(((detail.get("fields") or {}).get("initial_access") or {}).get("value") or "")
        if case_id == "sport_2000" and initial_access == "compromised_credentials":
            problems.append("Corpus validation : Sport 2000 infère encore des identifiants compromis")
        if case_id in {"declic_services", "solimut", "suez"} and not row.get("sensitive_data_exposed"):
            problems.append(f"Corpus validation : données sensibles non signalées pour {case_id}")
        case_reports.append({
            "case": case_id,
            "incident_id": row.get("id"),
            "organisation": row.get("org"),
            "summary": summary,
            "sensitive_data_exposed": bool(row.get("sensitive_data_exposed")),
            "initial_access": initial_access,
            "source_links": row.get("source_links", []),
        })
    payload = {
        "schema_version": 1,
        "corpus": corpus.name,
        "targets": len(corpus.targets),
        "expected_incidents": len(corpus.case_ids),
        "items": len(items),
        "incidents": len(incidents),
        "cases": case_reports,
        "problems": problems,
        "verdict": "PASS" if not problems else "FAIL",
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
