"""Évaluation isolée du modèle courant sur les textes figés de l'audit.

Trois étages sont mesurés séparément, parce qu'ils échouent séparément :

1. **réponse brute** — ce que le modèle propose, avant tout validateur ;
2. **validée** — ce que les contrats de `source_facts_ai` acceptent ;
3. **publiée** — ce qui atteint SourceFacts puis l'incident.

Rien n'est écrit dans `data/` ni dans `assets/data/`, et aucun appel réseau n'a
lieu sans `--api` **et** une clé. Sans appel, l'étage « réponse brute » est
déclaré **non mesuré** : un run sans inférence ne dit rien de la performance du
modèle, et aucune supériorité d'un modèle n'est revendiquée ici.

Les confiances déclarées par le modèle ne sont jamais converties en score de
précision : elles sont rapportées telles quelles, à part.

    python scripts/evaluate_qualification.py                 # étages 2 et 3
    OPENAI_API_KEY=… python scripts/evaluate_qualification.py --api
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cyberwatch import article_body, config, dedup, enrichment, source_facts, sources  # noqa: E402
from cyberwatch.collectors.base import RawEntry  # noqa: E402
from cyberwatch.identity import item_id  # noqa: E402
from cyberwatch.model import Item  # noqa: E402
from cyberwatch.normalize import organisation_key  # noqa: E402

EXPECTATIONS = ROOT / "bench" / "qualification_eval" / "expectations.json"
RESULTS_DIR = ROOT / "bench" / "qualification_eval"

NOT_MEASURED = "performance non mesurée"
PARTIAL = "évaluation partielle"

#: Plafond partagé avec la collecte : l'évaluation ne crée pas son propre budget.
SHARED_COST_CAP_USD = 0.03


def _entry(article: dict) -> RawEntry:
    text = (ROOT / article["context"]).read_text(encoding="utf-8")
    title, _, body = text.partition("\n\n")
    return RawEntry(
        source_item_id=article["url"],
        title=title.strip(),
        summary="",
        content=body.strip(),
        url=article["url"],
        organisation=article["organisation"],
        published=article["published_date"],
    )


def _item(article: dict) -> Item:
    key = organisation_key(article["organisation"])
    return Item(
        Item_ID=article["item_id"],
        Source_ID=article["source_id"],
        Source_Item_ID=article["url"],
        Published_Date=article["published_date"],
        Organisation_Raw=article["organisation"],
        Organisation_Key=key,
        Sector=config.SECTOR_UNKNOWN,
        Location=article["expected"].get("location", ""),
        Title=_entry(article).title,
        URL=article["url"],
        Collected_As_Of="2026-09-10T00:00:00+04:00",
    )


def _forbidden_hits(blob: str, forbidden: list[str]) -> list[str]:
    lowered = blob.casefold()
    return [term for term in forbidden if term.casefold() in lowered]


def _raw_stage(articles: list[dict], enabled: bool) -> dict:
    """Réponses brutes du modèle, sans validateur. Non mesuré sans appel."""
    if not enabled:
        return {"measured": False, "label": NOT_MEASURED, "articles": []}

    from cyberwatch import source_facts_ai
    from cyberwatch.source_facts_ai_contract import _EDITORIAL_FIELDS

    runtime = source_facts_ai._runtime()
    rows = []
    for article in articles:
        entry, item = _entry(article), _item(article)
        context = article_body.prepare_entry(entry).prepared
        fields = set(_EDITORIAL_FIELDS)
        body = source_facts_ai._request_body(item, context, fields, runtime)
        started = time.monotonic()
        try:
            payload = source_facts_ai._post_openai(body, runtime)
            raw = json.loads(source_facts_ai._extract_output_text(payload))
            error = ""
        except Exception as exc:  # noqa: BLE001 — une panne est un résultat mesuré
            raw, error = {}, f"{type(exc).__name__}: {exc}"
        duration = time.monotonic() - started
        blob = json.dumps(raw, ensure_ascii=False)
        rows.append({
            "item_id": article["item_id"],
            "error": error,
            "raw": raw,
            "unsupported_claims": _forbidden_hits(blob, article["forbidden_claims"]),
            "produced_fields": sorted(key for key, value in raw.items() if value),
            # Reportée telle quelle : ce n'est pas une précision mesurée.
            "declared_confidences": {
                key: value.get("confidence")
                for key, value in raw.items() if isinstance(value, dict)
            },
            "duration_seconds": round(duration, 3),
        })
    return {
        "measured": True,
        "requested_model": runtime.model,
        "effective_model": runtime.effective_model,
        "calls": runtime.calls,
        "cost_usd": round(runtime.cost, 6),
        "cost_cap_usd": SHARED_COST_CAP_USD,
        "articles": rows,
    }


def _validated_stage(articles: list[dict]) -> dict:
    """Faits retenus par les contrats, après extraction complète d'un article."""
    rows = []
    for article in articles:
        entry, item = _entry(article), _item(article)
        started = time.monotonic()
        fact = source_facts.extract_source_fact(item, entry, sources.by_id(article["source_id"])) or {}
        duration = time.monotonic() - started
        abstained = [name for name in article["must_abstain"] if not _fact_value(fact, name)]
        blob = json.dumps({k: v for k, v in fact.items() if k != "Source_Metadata_JSON"},
                          ensure_ascii=False)
        rows.append({
            "item_id": article["item_id"],
            "appropriate_abstentions": abstained,
            "missing_abstentions": [
                name for name in article["must_abstain"] if name not in abstained
            ],
            "unsupported_claims": _forbidden_hits(blob, article["forbidden_claims"]),
            "impact": fact.get("Impact", ""),
            "impact_evidence": _evidence(fact).get("Impact", ""),
            "summary": fact.get("Summary", ""),
            "quoted_evidence_grounded": _evidence_is_grounded(fact, entry),
            "duration_seconds": round(duration, 3),
        })
    return {"measured": True, "articles": rows}


def _fact_value(fact: dict, name: str):
    column = {
        "initial_access": "Initial_Access", "affected_count": "Affected_Count",
        "data_types": "Data_Types_JSON", "vulnerabilities": "Vulnerabilities_JSON",
        "third_party": "Third_Party",
    }.get(name, name)
    value = fact.get(column, "")
    if isinstance(value, str) and value.strip() in {"[]", "{}"}:
        return ""
    return value


def _evidence(fact: dict) -> dict:
    try:
        parsed = json.loads(fact.get("Evidence_JSON") or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _evidence_is_grounded(fact: dict, entry: RawEntry) -> bool:
    """Chaque citation retenue doit se retrouver dans le corps de l'article."""
    from cyberwatch.normalize import searchable

    body = searchable(article_body.prepare_entry(entry).prepared)
    for value in _evidence(fact).values():
        needle = searchable(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
        if needle and needle not in body:
            return False
    return True


def _published_stage(articles: list[dict], pairs: list[dict]) -> dict:
    """Incidents publiés, et décisions de fusion, sur le même corpus figé."""
    observations = []
    for article in articles:
        entry, item = _entry(article), _item(article)
        fact = source_facts.extract_source_fact(item, entry, sources.by_id(article["source_id"]))
        observations.append((item, fact or {}))
    items = [item for item, _ in observations]
    facts = [fact for _, fact in observations if fact]
    report = enrichment.finalize_snapshot(
        items, facts, run_id="EVAL-QUALIFICATION", as_of="2026-09-10T00:00:00+04:00"
    )

    published = []
    by_item = {item.Item_ID: item for item in items}
    for incident in report.incidents:
        published.append({
            "incident_id": incident.Incident_ID,
            "organisation": incident.Organisation,
            "sector": incident.Secteur,
            "threat": incident.Menace,
            "location": incident.Localisation,
            "sources": str(incident.Sources).split(" | "),
            "items": incident.Items_Count,
        })

    correct_facts, unsupported = 0, []
    for article in articles:
        expected = article["expected"]
        item = by_item[article["item_id"]]
        incident = next(
            (row for row in report.incidents
             if article["url"] in str(row.Source_URLs)), None
        )
        if incident is None:
            unsupported.append({"item_id": item.Item_ID, "problem": "aucun incident publié"})
            continue
        for field, value in (("threat", incident.Menace), ("sector", incident.Secteur),
                             ("location", incident.Localisation)):
            if expected.get(field) is None:
                continue
            if value == expected[field]:
                correct_facts += 1
            else:
                unsupported.append({
                    "item_id": item.Item_ID, "field": field,
                    "expected": expected[field], "published": value,
                })

    merges = _merge_results(items, pairs)
    return {
        "measured": True,
        "incidents": published,
        "correct_published_fields": correct_facts,
        "incorrect_published_fields": unsupported,
        **merges,
    }


def _merge_results(items: list[Item], pairs: list[dict]) -> dict:
    """Fusions correctes et fausses fusions, sur les paires attendues."""
    synthetic = Item(
        Item_ID="ITM-TARNOS-SYNTHETIQUE", Source_ID="FRENCHBREACHES",
        Source_Item_ID="https://frenchbreaches.com/alertes/tarnos",
        Published_Date="2026-08-29", Organisation_Raw="Tarnos",
        Organisation_Key=organisation_key("Tarnos"), Threat=config.THREAT_UNKNOWN,
        Sector=config.SECTOR_ADMIN, Location="France métropolitaine", Title="Tarnos",
        URL="https://frenchbreaches.com/alertes/tarnos",
        Collected_As_Of="2026-08-30T00:00:00+04:00",
    )
    corpus = items + [synthetic]
    grouped: dict[str, str] = {}
    for incident in dedup.build_incidents(corpus):
        for member in corpus:
            if member.URL in str(incident.Source_URLs):
                grouped[member.Item_ID] = incident.Incident_ID

    correct, missed, false_merges = 0, [], []
    for pair in pairs:
        left, right = pair["left"], pair["right"]
        if left not in grouped or right not in grouped:
            missed.append({**pair, "problem": "observation absente du corpus figé"})
            continue
        merged = grouped[left] == grouped[right]
        if merged == pair["expected_merge"]:
            correct += 1
        elif merged:
            false_merges.append(pair)
        else:
            missed.append(pair)
    return {
        "correct_merges": correct,
        "false_merges": false_merges,
        "missed_merges": missed,
    }


def _verdict(raw: dict, validated: dict, published: dict) -> dict:
    if not raw["measured"]:
        label, complete = NOT_MEASURED, False
    elif any(row["error"] for row in raw["articles"]):
        label, complete = PARTIAL, False
    else:
        label, complete = "évaluation complète", True
    return {
        "label": label,
        "raw_stage_measured": raw["measured"],
        "validation_stage_measured": validated["measured"],
        "publication_stage_measured": published["measured"],
        "complete": complete,
        "model_comparison": "aucune : un seul modèle exécuté, aucune supériorité mesurée",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", action="store_true",
                        help="Autorise les appels réseau ; exige OPENAI_API_KEY")
    parser.add_argument("--out", default="", help="Chemin du bilan JSON")
    args = parser.parse_args(argv)

    payload = json.loads(EXPECTATIONS.read_text(encoding="utf-8"))
    articles, pairs = payload["articles"], payload["pairs"]

    api_enabled = bool(args.api and os.getenv("OPENAI_API_KEY", "").strip())
    if args.api and not api_enabled:
        print("OPENAI_API_KEY absente : l'étage « réponse brute » reste non mesuré.",
              file=sys.stderr)
    if api_enabled:
        # Le plafond partagé de la collecte s'applique tel quel à l'évaluation.
        os.environ.setdefault("LLM_MAX_COST_USD_PER_RUN", str(SHARED_COST_CAP_USD))
        os.environ.setdefault("SOURCE_FACTS_AI_MAX_COST_USD_PER_RUN", str(SHARED_COST_CAP_USD))

    raw = _raw_stage(articles, api_enabled)
    validated = _validated_stage(articles)
    published = _published_stage(articles, pairs)
    result = {
        "version": payload["version"],
        "expectations": str(EXPECTATIONS.relative_to(ROOT)),
        "verdict": _verdict(raw, validated, published),
        "raw_response": raw,
        "validated": validated,
        "published": published,
    }

    destination = Path(args.out) if args.out else RESULTS_DIR / "latest.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "verdict": result["verdict"],
        "correct_published_fields": published["correct_published_fields"],
        "incorrect_published_fields": published["incorrect_published_fields"],
        "correct_merges": published["correct_merges"],
        "false_merges": published["false_merges"],
        "missed_merges": published["missed_merges"],
        "report": str(destination),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
