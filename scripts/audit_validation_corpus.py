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

    def contains(values, *needles):
        folded = " ".join(str(value or "").casefold() for value in values)
        return all(needle.casefold() in folded for needle in needles)

    def claims_of(detail, kind):
        return [row.get("value") for row in detail.get("claims", []) if isinstance(row, dict) and row.get("type") == kind]

    def field_or_claim(detail, field, kind, *needles):
        scalar = ((detail.get("fields") or {}).get(field) or {}).get("value")
        return contains([scalar, *claims_of(detail, kind)], *needles)
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
        if case_id == "sport_2000":
            exposed = [str(entry.get("value") or "") for entry in detail.get("data_types", []) if isinstance(entry, dict)]
            if contains(exposed, "IBAN") or contains(exposed, "cartes de paiement"):
                problems.append("Corpus validation : Sport 2000 présente des données bancaires explicitement absentes")
            if row.get("sensitive_data_exposed"):
                problems.append("Corpus validation : Sport 2000 porte à tort le tag Données sensibles")
        if case_id in {"declic_services", "solimut", "suez"} and not row.get("sensitive_data_exposed"):
            problems.append(f"Corpus validation : données sensibles non signalées pour {case_id}")
        values = {str(entry.get("value") or "").casefold() for entry in detail.get("affected", []) if isinstance(entry, dict)}
        claims = detail.get("claims", []) if isinstance(detail.get("claims"), list) else []
        if case_id == "sport_2000" and not any("zerobytes" in str(claim.get("value") or "").casefold() for claim in claims if isinstance(claim, dict)):
            problems.append("Corpus validation : acteur Sport 2000 absent des faits sourcés")
        if case_id == "dinum":
            if row.get("threat") != "Fuite de données":
                problems.append("Corpus validation : DINUM doit être qualifié Fuite de données")
            if row.get("sector") != "Administration / Collectivité" or row.get("location") != "France métropolitaine":
                problems.append("Corpus validation : référentiel déterministe DINUM non appliqué")
            if not any("31544" in value.replace(" ", "") for value in values):
                problems.append("Corpus validation : volume DINUM absent")
        if case_id == "declic_services" and not any("6271531" in value.replace(" ", "") for value in values):
            problems.append("Corpus validation : volume Déclic Services absent")
        if case_id == "solimut" and not any("1244445" in value.replace(" ", "") for value in values):
            problems.append("Corpus validation : volume Solimut absent")
        # Contrat de complétude issu des cinq fiches de référence : il ne
        # demande jamais d'inventer un fait, mais bloque si un fait sourcé
        # attendu est perdu entre extraction, SourceFacts et interface.
        if case_id == "sport_2000":
            if not field_or_claim(detail, "threat_actor", "actor", "zerobytes"):
                problems.append("Corpus validation : acteur Sport 2000 absent")
            if not contains([entry.get("value") for entry in detail.get("systems", []) if isinstance(entry, dict)] + claims_of(detail, "system"), "pilot"):
                problems.append("Corpus validation : système Pilot Sport 2000 absent")
        elif case_id == "dinum":
            if not field_or_claim(detail, "threat_actor", "actor", "0xsec"):
                problems.append("Corpus validation : acteur DINUM absent")
            if not contains([entry.get("value") for entry in detail.get("systems", []) if isinstance(entry, dict)] + claims_of(detail, "system"), "cloud"):
                problems.append("Corpus validation : système cloud DINUM absent")
        elif case_id == "declic_services":
            if not field_or_claim(detail, "threat_actor", "actor", "zerobytes"):
                problems.append("Corpus validation : acteur Déclic Services absent")
            if not contains([entry.get("value") for entry in detail.get("systems", []) if isinstance(entry, dict)] + claims_of(detail, "system"), "wordpress"):
                problems.append("Corpus validation : système WordPress Déclic Services absent")
        elif case_id == "solimut":
            if not field_or_claim(detail, "threat_actor", "actor", "misere"):
                problems.append("Corpus validation : acteur Solimut absent")
            actor = str(((detail.get("fields") or {}).get("threat_actor") or {}).get("value") or "")
            if actor.casefold() != "misere":
                problems.append("Corpus validation : acteur principal Solimut incorrect")
            if not contains([entry.get("value") for entry in detail.get("data_types", []) if isinstance(entry, dict)], "sécurité sociale"):
                problems.append("Corpus validation : NIR Solimut absent")
        elif case_id == "suez":
            if not field_or_claim(detail, "third_party", "third_party", "prestataire"):
                problems.append("Corpus validation : prestataire SUEZ absent")
            if any("prestataire" in str(entry.get("value") or "").casefold() for entry in detail.get("systems", []) if isinstance(entry, dict)):
                problems.append("Corpus validation : tiers SUEZ présenté à tort comme système")
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
