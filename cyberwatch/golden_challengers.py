"""Comparaison du golden set avec des exports de qualification concurrents.

Les challengers sont des sorties expérimentales (par exemple les exports ChatGPT
FrenchBreaches et Cyberattaque.org). Ils ne modifient jamais le golden set : ils
sont seulement évalués contre lui, au même titre que la DB Cyberwatch courante.
"""
from __future__ import annotations

from pathlib import Path

from . import config
from .golden import MatchResult, REFERENCE_FIELDS, _iso_date, _split_multi, evaluate, match_golden
from .normalize import organisation_key

MANUAL_MATCH_COLUMNS = ["Golden_ID", "Challenger", "Source_URL", "Notes"]

COMPARISON_DETAIL_COLUMNS = [
    "Golden_ID",
    "Organisation",
    "Reference_Date",
    "Challenger",
    "DB_Match_Status",
    "DB_Match_Strategy",
    "DB_Incident_ID",
    "Challenger_Match_Status",
    "Challenger_Match_Strategy",
    "Challenger_Source_URLs",
    "Secteur_REF",
    "Secteur_DB",
    "Secteur_Challenger",
    "Secteur_DB_Match",
    "Secteur_Challenger_Match",
    "Menace_REF",
    "Menace_DB",
    "Menace_Challenger",
    "Menace_DB_Match",
    "Menace_Challenger_Match",
    "Localisation_REF",
    "Localisation_DB",
    "Localisation_Challenger",
    "Localisation_DB_Match",
    "Localisation_Challenger_Match",
]

_LOCATION_ALIASES = {
    "france": config.LOC_FRANCE,
    "france métropolitaine": config.LOC_FRANCE,
    "france metropolitaine": config.LOC_FRANCE,
    "la réunion": config.LOC_REUNION,
    "la reunion": config.LOC_REUNION,
    "réunion": config.LOC_REUNION,
    "reunion": config.LOC_REUNION,
    "mayotte": config.LOC_MAYOTTE,
    "maurice": config.LOC_MAURICE,
    "madagascar": config.LOC_MADAGASCAR,
    "seychelles": config.LOC_SEYCHELLES,
    "comores": config.LOC_COMORES,
    "inconnu": config.LOC_INCONNU,
    "": config.LOC_INCONNU,
}


def normalize_challenger_location(value: str) -> str:
    """Ramène le territoire d'un export LLM à la nomenclature Cyberwatch.

    Les territoires hors périmètre sont volontairement ramenés à Inconnu : le
    benchmark ne doit pas inventer une nouvelle taxonomie uniquement pour un
    challenger.
    """
    cleaned = str(value or "").strip()
    if cleaned in config.LOCATIONS:
        return cleaned
    return _LOCATION_ALIASES.get(cleaned.lower(), config.LOC_INCONNU)


def canonical_challenger_row(row: dict[str, str], challenger: str) -> dict[str, str]:
    organisation = (row.get("organisation") or row.get("Organisation") or "").strip()
    return {
        "Challenger": challenger,
        "Date": (row.get("date") or row.get("Date") or "").strip(),
        "Organisation": organisation,
        "Organisation_Key": organisation_key(organisation),
        "Source_URLs": (row.get("source_urls") or row.get("Source_URLs") or "").strip(),
        "Secteur": (row.get("secteur") or row.get("Secteur") or config.SECTOR_UNKNOWN).strip()
        or config.SECTOR_UNKNOWN,
        "Menace": (row.get("type_menace") or row.get("Menace") or config.THREAT_UNKNOWN).strip()
        or config.THREAT_UNKNOWN,
        "Localisation": normalize_challenger_location(
            row.get("territoire") or row.get("Localisation") or ""
        ),
    }


def canonical_challenger_rows(rows: list[dict[str, str]], challenger: str) -> list[dict[str, str]]:
    return [canonical_challenger_row(row, challenger) for row in rows]


def _manual_match_url(
    golden_id: str, challenger: str, manual_matches: list[dict[str, str]]
) -> str:
    matches = [
        (row.get("Source_URL") or "").strip()
        for row in manual_matches
        if (row.get("Golden_ID") or "").strip() == golden_id
        and (row.get("Challenger") or "").strip() == challenger
        and (row.get("Source_URL") or "").strip()
    ]
    return matches[0] if len(matches) == 1 else ""


def _challenger_score(
    golden: dict[str, str], challenger_row: dict[str, str]
) -> tuple[int, int, int] | None:
    gold_urls = _split_multi(golden.get("Source_URLs", ""))
    current_urls = _split_multi(challenger_row.get("Source_URLs", ""))
    url_overlap = len(gold_urls & current_urls)

    gold_date = _iso_date(golden.get("Reference_Date", ""))
    current_date = _iso_date(challenger_row.get("Date", ""))
    days = abs((gold_date - current_date).days) if gold_date and current_date else 999999

    # L'URL de la source est une preuve d'identité plus forte que l'ordre des
    # mots dans le nom (ex. "Motoculture Cravero" / "Cravero Motoculture").
    if url_overlap:
        return (3, url_overlap, -days)

    current_key = challenger_row.get("Organisation_Key", "")
    gold_keys = {
        (golden.get("Organisation_Key") or "").strip(),
        organisation_key(golden.get("Organisation", "")),
    }
    gold_keys.discard("")
    if not current_key or current_key not in gold_keys:
        return None

    if days <= 3:
        return (2, 0, -days)
    if days <= config.INCIDENT_GAP_DAYS:
        return (1, 0, -days)
    return None


def match_challenger(
    golden: dict[str, str],
    challenger_rows: list[dict[str, str]],
    challenger: str,
    manual_matches: list[dict[str, str]] | None = None,
) -> MatchResult:
    """Retrouve un cas golden dans un export challenger sans fuzzy matching."""
    manual_matches = manual_matches or []
    manual_url = _manual_match_url(golden.get("Golden_ID", ""), challenger, manual_matches)
    if manual_url:
        direct = [
            row for row in challenger_rows
            if manual_url in _split_multi(row.get("Source_URLs", ""))
        ]
        if len(direct) == 1:
            return MatchResult("MATCHED", "manual_source_url", direct[0])
        if len(direct) > 1:
            return MatchResult("AMBIGUOUS", "manual_source_url")

    scored: list[tuple[tuple[int, int, int], dict[str, str]]] = []
    for row in challenger_rows:
        score = _challenger_score(golden, row)
        if score is not None:
            scored.append((score, row))
    if not scored:
        return MatchResult("MISSING")

    scored.sort(
        key=lambda pair: (pair[0], pair[1].get("Date", ""), pair[1].get("Source_URLs", "")),
        reverse=True,
    )
    best_score = scored[0][0]
    best = [row for score, row in scored if score == best_score]
    if len(best) != 1:
        return MatchResult("AMBIGUOUS")

    strategy = {3: "source_url", 2: "organisation_and_date", 1: "organisation_window"}[
        best_score[0]
    ]
    return MatchResult("MATCHED", strategy, best[0])


def _field_metrics(details: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    matched = [row for row in details if row["Match_Status"] == "MATCHED"]
    summaries: dict[str, dict[str, object]] = {}
    for label, ref_field, _current_field, unknown in REFERENCE_FIELDS:
        total = len(matched)
        value_field = f"{label}_Challenger"
        match_field = f"{label}_Match"
        qualified = sum(row[value_field] != unknown for row in matched)
        correct = sum(bool(row[match_field]) for row in matched)
        correct_when_qualified = sum(
            bool(row[match_field]) and row[value_field] != unknown for row in matched
        )
        summaries[label] = {
            "matched_cases": total,
            "correct": correct,
            "accuracy_pct": round(100.0 * correct / total, 1) if total else 0.0,
            "qualified": qualified,
            "coverage_pct": round(100.0 * qualified / total, 1) if total else 0.0,
            "precision_when_qualified_pct": (
                round(100.0 * correct_when_qualified / qualified, 1) if qualified else 0.0
            ),
            "resolvable_unknown": sum(
                row[value_field] == unknown and row[ref_field] != unknown for row in matched
            ),
            "wrong_classification": sum(
                row[value_field] != unknown and row[value_field] != row[ref_field]
                for row in matched
            ),
            "reference_unknown": sum(row[ref_field] == unknown for row in matched),
        }
    return summaries


def evaluate_challenger(
    golden_rows: list[dict[str, str]],
    raw_rows: list[dict[str, str]],
    challenger: str,
    manual_matches: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    rows = canonical_challenger_rows(raw_rows, challenger)
    details: list[dict[str, object]] = []
    matched = ambiguous = missing = 0

    for golden in golden_rows:
        result = match_challenger(golden, rows, challenger, manual_matches)
        if result.status == "MATCHED":
            matched += 1
        elif result.status == "AMBIGUOUS":
            ambiguous += 1
        else:
            missing += 1
        current = result.incident or {}
        detail: dict[str, object] = {
            "Golden_ID": golden.get("Golden_ID", ""),
            "Organisation": golden.get("Organisation", ""),
            "Reference_Date": golden.get("Reference_Date", ""),
            "Match_Status": result.status,
            "Match_Strategy": result.strategy,
            "Challenger_Source_URLs": current.get("Source_URLs", ""),
        }
        for label, ref_field, current_field, _unknown in REFERENCE_FIELDS:
            ref = golden.get(ref_field, "")
            value = current.get(current_field, "") if result.status == "MATCHED" else ""
            detail[ref_field] = ref
            detail[f"{label}_Challenger"] = value
            detail[f"{label}_Match"] = result.status == "MATCHED" and value == ref
        details.append(detail)

    return {
        "challenger": challenger,
        "cases": len(golden_rows),
        "matched": matched,
        "ambiguous": ambiguous,
        "missing": missing,
        "fields": _field_metrics(details),
        "details": details,
    }


def _pairwise_field(
    db_by_id: dict[str, dict[str, object]],
    challenger_by_id: dict[str, dict[str, object]],
    label: str,
) -> dict[str, object]:
    common_ids = [
        golden_id for golden_id in sorted(set(db_by_id) & set(challenger_by_id))
        if db_by_id[golden_id]["Match_Status"] == "MATCHED"
        and challenger_by_id[golden_id]["Match_Status"] == "MATCHED"
    ]
    db_match = f"{label}_Match"
    ch_match = f"{label}_Match"
    both = db_only = challenger_only = neither = 0
    for golden_id in common_ids:
        db_ok = bool(db_by_id[golden_id][db_match])
        ch_ok = bool(challenger_by_id[golden_id][ch_match])
        if db_ok and ch_ok:
            both += 1
        elif db_ok:
            db_only += 1
        elif ch_ok:
            challenger_only += 1
        else:
            neither += 1
    total = len(common_ids)
    db_correct = both + db_only
    challenger_correct = both + challenger_only
    db_accuracy = 100.0 * db_correct / total if total else 0.0
    challenger_accuracy = 100.0 * challenger_correct / total if total else 0.0
    return {
        "common_matched_cases": total,
        "both_correct": both,
        "db_only_correct": db_only,
        "challenger_only_correct": challenger_only,
        "neither_correct": neither,
        "db_accuracy_pct": round(db_accuracy, 1),
        "challenger_accuracy_pct": round(challenger_accuracy, 1),
        "delta_accuracy_pp": round(challenger_accuracy - db_accuracy, 1),
        "gains": challenger_only,
        "regressions": db_only,
    }


def compare_challengers(
    golden_rows: list[dict[str, str]],
    incidents: list[dict[str, str]],
    challengers: dict[str, list[dict[str, str]]],
    manual_matches: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    """Compare DB et challengers sur exactement les mêmes cas golden."""
    db_result = evaluate(golden_rows, incidents)
    db_details = db_result.pop("details")
    db_by_id = {str(row["Golden_ID"]): row for row in db_details}

    challenger_results: dict[str, dict[str, object]] = {}
    comparison_details: list[dict[str, object]] = []
    pairwise: dict[str, dict[str, object]] = {}

    for challenger, raw_rows in challengers.items():
        result = evaluate_challenger(golden_rows, raw_rows, challenger, manual_matches)
        ch_details = result.pop("details")
        ch_by_id = {str(row["Golden_ID"]): row for row in ch_details}
        challenger_results[challenger] = result
        pairwise[challenger] = {
            label: _pairwise_field(db_by_id, ch_by_id, label)
            for label, _ref, _current, _unknown in REFERENCE_FIELDS
        }

        for golden in golden_rows:
            golden_id = golden.get("Golden_ID", "")
            db = db_by_id.get(golden_id, {})
            ch = ch_by_id.get(golden_id, {})
            row: dict[str, object] = {
                "Golden_ID": golden_id,
                "Organisation": golden.get("Organisation", ""),
                "Reference_Date": golden.get("Reference_Date", ""),
                "Challenger": challenger,
                "DB_Match_Status": db.get("Match_Status", "MISSING"),
                "DB_Match_Strategy": db.get("Match_Strategy", ""),
                "DB_Incident_ID": db.get("Incident_ID_Current", ""),
                "Challenger_Match_Status": ch.get("Match_Status", "MISSING"),
                "Challenger_Match_Strategy": ch.get("Match_Strategy", ""),
                "Challenger_Source_URLs": ch.get("Challenger_Source_URLs", ""),
            }
            for label, ref_field, _current, _unknown in REFERENCE_FIELDS:
                row[ref_field] = golden.get(ref_field, "")
                row[f"{label}_DB"] = db.get(f"{label}_CW", "")
                row[f"{label}_Challenger"] = ch.get(f"{label}_Challenger", "")
                row[f"{label}_DB_Match"] = db.get(f"{label}_Match", False)
                row[f"{label}_Challenger_Match"] = ch.get(f"{label}_Match", False)
            comparison_details.append(row)

    return {
        "cases": len(golden_rows),
        "db": db_result,
        "challengers": challenger_results,
        "pairwise_vs_db": pairwise,
        "details": comparison_details,
    }


def load_optional_csv(path: Path | str) -> list[dict[str, str]]:
    target = Path(path)
    if not target.exists():
        return []
    from .golden import read_csv

    return read_csv(target)
