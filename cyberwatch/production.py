"""Pilotage quotidien de la fiabilité, de la qualité et du coût produit."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from . import config, duplicate_audit, incident_dedup, org_identity, qualification, store
from . import dedup as dedup_engine
from .model import Incident, Item
from .normalize import classify_location, classify_sector, classify_threat, looks_cyber

FRESHNESS_TARGET_HOURS = 36.0
SCHEDULED_SUCCESS_TARGET_PCT = 95.0
SECTOR_UNKNOWN_TARGET_PCT = 10.0
LOCATION_UNKNOWN_TARGET_PCT = 5.0
REQUIRED_CONSECUTIVE_SCHEDULED_SUCCESSES = 7
SCHEDULED_RELIABILITY_WINDOW = 30

BUSINESS_CORPUS_PATH = Path(__file__).resolve().parents[1] / "validation" / "business_corpus.json"
DEDUP_CORPUS_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "dedup_identity_cases.json"


def _pct(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 2) if denominator else 0.0


def _float(value: object, default: float = 0.0) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def _optional_int(value: object) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    return int(_float(value))


def _parse_datetime(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed


def load_business_corpus(path: Path | None = None) -> list[dict]:
    payload = json.loads((path or BUSINESS_CORPUS_PATH).read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    if not isinstance(cases, list) or not cases:
        raise ValueError("Le corpus métier doit contenir une liste non vide de cas.")
    return cases


def evaluate_business_corpus(cases: list[dict] | None = None) -> dict:
    """Évalue les règles déterministes sur un corpus versionné et sans réseau."""
    cases = cases or load_business_corpus()
    false_positives: list[str] = []
    false_negatives: list[str] = []
    classification_errors: list[str] = []
    negative_scope_cases = 0

    for case in cases:
        case_id = str(case.get("case_id") or "sans-id")
        kind = case.get("kind")
        if kind == "scope":
            expected = bool(case.get("expected_in_scope"))
            predicted = looks_cyber(case.get("text", ""))
            if not expected:
                negative_scope_cases += 1
            if predicted and not expected:
                false_positives.append(case_id)
            elif expected and not predicted:
                false_negatives.append(case_id)
            expected_threat = case.get("expected_threat")
            if expected_threat and classify_threat(case.get("text", "")) != expected_threat:
                classification_errors.append(case_id)
        elif kind == "location":
            predicted = classify_location(
                case.get("text", ""),
                given=case.get("given", ""),
                entity=case.get("entity", ""),
                default=case.get("default", ""),
            )
            if predicted != case.get("expected"):
                classification_errors.append(case_id)
        elif kind == "sector":
            predicted = classify_sector(
                case.get("organisation", ""),
                case.get("text", ""),
                given=case.get("given", ""),
            )
            if predicted != case.get("expected"):
                classification_errors.append(case_id)
        else:
            raise ValueError(f"Type de cas métier inconnu : {kind!r}")

    return {
        "cases": len(cases),
        "false_positives": len(false_positives),
        "false_positive_rate_pct": _pct(len(false_positives), negative_scope_cases),
        "false_negatives": len(false_negatives),
        "classification_errors": len(classification_errors),
        "failed_cases": sorted(false_positives + false_negatives + classification_errors),
        "passed": not (false_positives or false_negatives or classification_errors),
    }


def evaluate_dedup_corpus(path: Path | None = None) -> dict:
    payload = json.loads((path or DEDUP_CORPUS_PATH).read_text(encoding="utf-8"))
    return duplicate_audit.dedup_identity_benchmark(payload.get("cases", []))


def dedup_quality_counts(
    items: list[Item],
    *,
    dedup_review_rows: list[dict] | None = None,
    incident_decision_rows: list[dict] | None = None,
    organisation_identity_rows: list[dict] | None = None,
) -> dict[str, int]:
    """Classe séparément les doublons manqués, fusions faibles et attentes."""
    decisions = incident_dedup.decision_map(incident_decision_rows or [])
    previous_registry = org_identity.ORGANISATION_IDENTITY_REGISTRY
    if organisation_identity_rows is not None:
        org_identity.ORGANISATION_IDENTITY_REGISTRY = {
            row.get("Alias_Key", ""): row.get("Canonical_Key", "")
            for row in organisation_identity_rows
            if row.get("Decision") == org_identity.DECISION_SAME
            and row.get("Alias_Key") and row.get("Canonical_Key")
        }
    try:
        components = dedup_engine.group_components(items, decisions)
        grouped = {
            item.Item_ID: index
            for index, component in enumerate(components)
            for item in component
        }
        audit_candidates = duplicate_audit.find_audit_candidates(items)
    finally:
        org_identity.ORGANISATION_IDENTITY_REGISTRY = previous_registry

    confirmed_same = {
        row.get("Pair_Key", "")
        for row in incident_decision_rows or []
        if row.get("Decision") == incident_dedup.SAME
    }
    missed: set[str] = set()
    weak: set[str] = set()
    for candidate in audit_candidates:
        pair = incident_dedup.pair_key(candidate.left.Item_ID, candidate.right.Item_ID)
        same_group = grouped.get(candidate.left.Item_ID) == grouped.get(candidate.right.Item_ID)
        if candidate.risk_type == duplicate_audit.RISK_MISSED_DUPLICATE and not same_group:
            missed.add(pair)
        elif (
            candidate.risk_type == duplicate_audit.RISK_FALSE_MERGE
            and same_group
            and pair not in confirmed_same
        ):
            weak.add(pair)

    same_not_grouped = {
        row.get("Pair_Key", "")
        for row in incident_decision_rows or []
        if row.get("Decision") == incident_dedup.SAME
        and grouped.get(row.get("Left_Item_ID")) != grouped.get(row.get("Right_Item_ID"))
    }
    pending = {
        row.get("pair_key", "")
        for row in dedup_review_rows or []
        if row.get("pair_key") and row.get("status") not in {"APPLIED", "DIFFERENT"}
    }
    return {
        "missed_duplicate_candidate_pairs": len(missed),
        "weak_merge_review_pairs": len(weak),
        "validated_same_not_grouped_pairs": len(same_not_grouped),
        "pending_review_pairs": len(pending),
    }


def metric_row(
    *,
    run_id: str,
    as_of: str,
    trigger: str,
    overall_status: str,
    published: bool,
    items: list[Item],
    incidents: list[Incident],
    duration_seconds: float,
    requests: int,
    llm_calls: int,
    llm_cost_usd: float,
    new_items: list[Item] | None = None,
    source_facts_retry_summary: dict | None = None,
    source_facts_rows: list[dict] | None = None,
    dedup_review_rows: list[dict] | None = None,
    incident_decision_rows: list[dict] | None = None,
    organisation_identity_rows: list[dict] | None = None,
) -> dict:
    incident_count = len(incidents)
    sector_unknown = sum(i.Secteur == config.SECTOR_UNKNOWN for i in incidents)
    location_unknown = sum(i.Localisation == config.LOC_INCONNU for i in incidents)
    new_items = new_items or []
    retry = source_facts_retry_summary or {}
    new_sector_unknown = sum(item.Sector == config.SECTOR_UNKNOWN for item in new_items)
    new_threat_unknown = sum(item.Threat == config.THREAT_UNKNOWN for item in new_items)
    new_location_unknown = sum(item.Location == config.LOC_INCONNU for item in new_items)
    duplicate_pairs = len(duplicate_audit.find_audit_candidates(items))
    dedup_quality = dedup_quality_counts(
        items,
        dedup_review_rows=dedup_review_rows,
        incident_decision_rows=incident_decision_rows,
        organisation_identity_rows=organisation_identity_rows,
    )
    corpus = evaluate_business_corpus()
    dedup = evaluate_dedup_corpus()
    fact_quality = source_fact_quality_counts(source_facts_rows or [])
    return {
        "Run_ID": run_id,
        "As_Of": as_of,
        "Trigger": trigger,
        "Overall_Status": overall_status,
        "Published": str(bool(published)).lower(),
        "Items_Count": len(items),
        "Incidents_Count": incident_count,
        "Sector_Unknown_Count": sector_unknown,
        "Sector_Unknown_Pct": f"{_pct(sector_unknown, incident_count):.2f}",
        "Location_Unknown_Count": location_unknown,
        "Location_Unknown_Pct": f"{_pct(location_unknown, incident_count):.2f}",
        "New_Items_Count": len(new_items),
        "New_Sector_Unknown_Count": new_sector_unknown,
        "New_Sector_Unknown_Pct": f"{_pct(new_sector_unknown, len(new_items)):.2f}",
        "New_Threat_Unknown_Count": new_threat_unknown,
        "New_Threat_Unknown_Pct": f"{_pct(new_threat_unknown, len(new_items)):.2f}",
        "New_Location_Unknown_Count": new_location_unknown,
        "New_Location_Unknown_Pct": f"{_pct(new_location_unknown, len(new_items)):.2f}",
        "SourceFacts_Retry_Queued_Before": int(retry.get("queued_before", 0)),
        "SourceFacts_Retry_Attempted": int(retry.get("attempted", 0)),
        "SourceFacts_Retry_Queued_After": int(retry.get("queued_after", 0)),
        "SourceFacts_Nonassertive_Suppressed_Count": fact_quality["nonassertive"],
        "SourceFacts_Contextual_Vulnerability_Count": fact_quality["contextual_vulnerabilities"],
        "SourceFacts_Unsupported_Affected_Unit_Count": fact_quality["unsupported_units"],
        "Potential_Duplicate_Pairs": duplicate_pairs,
        "Potential_Duplicate_Rate_Pct": f"{_pct(duplicate_pairs, incident_count):.2f}",
        "Missed_Duplicate_Candidate_Pairs": dedup_quality["missed_duplicate_candidate_pairs"],
        "Weak_Merge_Review_Pairs": dedup_quality["weak_merge_review_pairs"],
        "Validated_Same_Not_Grouped_Pairs": dedup_quality["validated_same_not_grouped_pairs"],
        "Pending_Review_Pairs": dedup_quality["pending_review_pairs"],
        "Corpus_Cases": corpus["cases"],
        "Corpus_False_Positives": corpus["false_positives"],
        "Corpus_False_Positive_Rate_Pct": f"{corpus['false_positive_rate_pct']:.2f}",
        "Corpus_False_Negatives": corpus["false_negatives"],
        "Corpus_Classification_Errors": corpus["classification_errors"],
        "Dedup_Known_False_Merges": dedup["known_nonduplicate_false_merge_count"],
        "Duration_s": f"{duration_seconds:.1f}",
        "Requests": requests,
        "LLM_Calls": llm_calls,
        "LLM_Cost_USD": f"{llm_cost_usd:.6f}",
    }


def source_fact_quality_counts(rows: list[dict]) -> dict[str, int]:
    """Compte les faits conservés pour audit mais exclus des affirmations publiques."""
    from .fact_resolution_counts import _HYPOTHETICAL_EVIDENCE_RE, _NEGATED_EVIDENCE_RE
    from .fact_resolution_vulnerabilities import VULNERABILITY_INCIDENT_LINK_RE

    nonassertive = 0
    contextual_vulnerabilities = 0
    unsupported_units = 0
    supported_units = {"people", "accounts", "users", "clients", "records", "files"}
    for row in rows:
        try:
            metadata = json.loads(str(row.get("Source_Metadata_JSON") or "{}"))
        except (TypeError, ValueError):
            continue
        rich = metadata.get("rich_facts") if isinstance(metadata, dict) else {}
        if not isinstance(rich, dict):
            continue
        for collection in ("data_types", "affected_datasets"):
            for fact in rich.get(collection, []) if isinstance(rich.get(collection), list) else []:
                if not isinstance(fact, dict):
                    continue
                status = str(fact.get("status") or "").casefold()
                evidence = str(fact.get("evidence") or "")
                if status in {"negated", "denied", "hypothesis"} or (
                    _NEGATED_EVIDENCE_RE.search(evidence)
                    or _HYPOTHETICAL_EVIDENCE_RE.search(evidence)
                ):
                    nonassertive += 1
        for fact in rich.get("vulnerabilities", []) if isinstance(rich.get("vulnerabilities"), list) else []:
            if not isinstance(fact, dict):
                continue
            relationship = str(fact.get("relationship") or "").casefold()
            evidence = str(fact.get("evidence") or "")
            if relationship in {"candidate", "mentioned"} or (
                not relationship and not VULNERABILITY_INCIDENT_LINK_RE.search(evidence)
            ):
                contextual_vulnerabilities += 1
        for fact in rich.get("affected_counts", []) if isinstance(rich.get("affected_counts"), list) else []:
            if isinstance(fact, dict):
                unit = str(fact.get("unit") or "").strip().casefold()
                if unit and unit not in supported_units:
                    unsupported_units += 1
    return {
        "nonassertive": nonassertive,
        "contextual_vulnerabilities": contextual_vulnerabilities,
        "unsupported_units": unsupported_units,
    }


def scheduled_reliability(run_log: list[dict]) -> dict:
    observed = [row for row in run_log if row.get("Trigger") == "schedule"][-SCHEDULED_RELIABILITY_WINDOW:]
    successes = sum(row.get("Overall_Status") == "OK" for row in observed)
    consecutive = 0
    for row in reversed(observed):
        if row.get("Overall_Status") != "OK":
            break
        consecutive += 1
    return {
        "observed": len(observed),
        "window": SCHEDULED_RELIABILITY_WINDOW,
        "successes": successes,
        "success_rate_pct": _pct(successes, len(observed)) if observed else None,
        "target_pct": SCHEDULED_SUCCESS_TARGET_PCT,
        "consecutive_successes": consecutive,
        "required_consecutive_successes": REQUIRED_CONSECUTIVE_SCHEDULED_SUCCESSES,
        "seven_run_proof_ready": consecutive >= REQUIRED_CONSECUTIVE_SCHEDULED_SUCCESSES,
    }


def snapshot_payload(run_log: list[dict], run_id: str) -> dict:
    """État déterministe publiable dans status.json (sans horloge courante)."""
    latest: dict[str, object] = next(
        (
            row for row in reversed(store.load_production_metrics())
            if row.get("Run_ID") == run_id and row.get("Published") == "true"
        ),
        {},
    )
    incidents = store.load_incidents()
    sector_unknown = sum(row.Secteur == config.SECTOR_UNKNOWN for row in incidents)
    location_unknown = sum(row.Localisation == config.LOC_INCONNU for row in incidents)
    return {
        "scheduled_reliability": scheduled_reliability(run_log),
        "targets": {
            "freshness_hours": FRESHNESS_TARGET_HOURS,
            "scheduled_success_pct": SCHEDULED_SUCCESS_TARGET_PCT,
            "sector_unknown_pct": SECTOR_UNKNOWN_TARGET_PCT,
            "location_unknown_pct": LOCATION_UNKNOWN_TARGET_PCT,
        },
        "quality": {
            "sector_unknown_pct": _pct(sector_unknown, len(incidents)),
            "location_unknown_pct": _pct(location_unknown, len(incidents)),
            "potential_duplicate_pairs": int(_float(latest.get("Potential_Duplicate_Pairs"))),
            "potential_duplicate_rate_pct": _float(latest.get("Potential_Duplicate_Rate_Pct")),
            "missed_duplicate_candidate_pairs": _optional_int(
                latest.get("Missed_Duplicate_Candidate_Pairs")
            ),
            "weak_merge_review_pairs": _optional_int(latest.get("Weak_Merge_Review_Pairs")),
            "validated_same_not_grouped_pairs": _optional_int(
                latest.get("Validated_Same_Not_Grouped_Pairs")
            ),
            "pending_review_pairs": _optional_int(latest.get("Pending_Review_Pairs")),
            "corpus_false_positive_rate_pct": _float(latest.get("Corpus_False_Positive_Rate_Pct")),
            "corpus_false_negatives": int(_float(latest.get("Corpus_False_Negatives"))),
            "corpus_classification_errors": int(_float(latest.get("Corpus_Classification_Errors"))),
            "dedup_known_false_merges": int(_float(latest.get("Dedup_Known_False_Merges"))),
        },
        "performance": {
            "duration_seconds": _float(latest.get("Duration_s")),
            "requests": int(_float(latest.get("Requests"))),
            "llm_calls": int(_float(latest.get("LLM_Calls"))),
            "llm_cost_usd": _float(latest.get("LLM_Cost_USD")),
        },
    }


def _sector_status_groups(rows: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    inferred = [row for row in rows if row.get("Status") in {"inferred", "inferred_low"}]
    referenced = [row for row in rows if row.get("Status") == "referenced"]
    low = [row for row in rows if row.get("Status") == "inferred_low"]
    return inferred, referenced, low


def _dedup_alert_reasons(snapshot: dict, latest: dict) -> list[str]:
    """Motifs d'alerte issus de la revue de déduplication du run publié."""
    reasons: list[str] = []
    dedup_rows = store.load_dedup_ai_daily_usage()
    current: dict[str, object] = next((row for row in reversed(dedup_rows)
                                       if row.get("Run_ID") == snapshot.get("Run_ID")), {})
    if current.get("Status") in {"LLM_DISABLED", "LLM_ERROR", "BUDGET_BLOCKED",
                                 "CAPACITY_LIMIT", "REVIEW_REQUIRED"}:
        reasons.append(f"revue dédup dégradée : {current['Status']}")
    if _float(current.get("Review_Required")) > 0:
        reasons.append(f"paires dédup en attente : {current['Review_Required']}")
    missed_pairs = _optional_int(latest.get("Missed_Duplicate_Candidate_Pairs"))
    same_not_grouped = _optional_int(latest.get("Validated_Same_Not_Grouped_Pairs"))
    pending_pairs = _optional_int(latest.get("Pending_Review_Pairs"))
    if missed_pairs:
        reasons.append(f"doublons potentiellement manqués : {missed_pairs}")
    if same_not_grouped:
        reasons.append(f"décisions SAME non regroupées : {same_not_grouped}")
    if pending_pairs and _float(current.get("Review_Required")) <= 0:
        reasons.append(f"paires dédup en attente : {pending_pairs}")
    return reasons


def health_payload(*, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.UTC)
    snapshot = store.load_snapshot()
    snapshot_at = _parse_datetime(snapshot.get("As_Of", ""))
    exact_age_hours = None if snapshot_at is None else max(
        0.0,
        (now.astimezone(dt.UTC) - snapshot_at.astimezone(dt.UTC)).total_seconds() / 3600,
    )
    freshness_ok = exact_age_hours is not None and exact_age_hours < FRESHNESS_TARGET_HOURS
    age_hours = None if exact_age_hours is None else round(exact_age_hours, 2)

    metrics = store.load_production_metrics()
    latest: dict[str, object] = next(
        (row for row in reversed(metrics) if row.get("Published") == "true"), {}
    )
    reliability = scheduled_reliability(store.load_run_log())
    sector_rows = store.load_sector_resolution()
    inferred_rows, referenced_rows, low_rows = _sector_status_groups(sector_rows)
    reasons = _dedup_alert_reasons(snapshot, latest)
    qualification_payload = qualification.payload(str(snapshot.get("Run_ID", "") or ""))
    if qualification_payload["state"] == qualification.STATE_PARTIAL:
        # Le run est publié — les contrôles d'intégrité restent bloquants et
        # ne sont pas touchés — mais son verdict de qualification doit le dire.
        detail = " ; ".join(qualification_payload["reasons"])
        reasons.append(
            f"{qualification.INCOMPLETE_LABEL}" + (f" : {detail}" if detail else "")
        )
    if age_hours is None:
        reasons.append("fraîcheur du snapshot inconnue")
    elif not freshness_ok:
        reasons.append(f"snapshot âgé de {age_hours:.1f} h (cible < {FRESHNESS_TARGET_HOURS:.0f} h)")

    incidents = store.load_incidents()
    sector_unknown_pct = _pct(
        sum(row.Secteur == config.SECTOR_UNKNOWN for row in incidents), len(incidents)
    )
    location_unknown_pct = _pct(
        sum(row.Localisation == config.LOC_INCONNU for row in incidents), len(incidents)
    )
    if sector_unknown_pct >= 0 and sector_unknown_pct >= SECTOR_UNKNOWN_TARGET_PCT:
        reasons.append(f"secteur inconnu {sector_unknown_pct:.2f} % (cible < {SECTOR_UNKNOWN_TARGET_PCT:.0f} %)")
    if location_unknown_pct >= 0 and location_unknown_pct >= LOCATION_UNKNOWN_TARGET_PCT:
        reasons.append(f"localisation inconnue {location_unknown_pct:.2f} % (cible < {LOCATION_UNKNOWN_TARGET_PCT:.0f} %)")
    if reliability["observed"] and reliability["success_rate_pct"] < SCHEDULED_SUCCESS_TARGET_PCT:
        reasons.append(
            f"succès planifié {reliability['success_rate_pct']:.2f} % "
            f"(cible ≥ {SCHEDULED_SUCCESS_TARGET_PCT:.0f} %)"
        )

    return {
        "alert": bool(reasons),
        "alert_reasons": reasons,
        "qualification": qualification_payload,
        "freshness": {
            "snapshot_as_of": snapshot.get("As_Of", ""),
            "age_hours": age_hours,
            "target_hours": FRESHNESS_TARGET_HOURS,
            "ok": freshness_ok,
        },
        "scheduled_reliability": reliability,
        "quality": {
            "sector_unknown_pct": None if sector_unknown_pct < 0 else sector_unknown_pct,
            "sector_unknown_target_pct": SECTOR_UNKNOWN_TARGET_PCT,
            "sector_inferred_items": len(inferred_rows),
            "sector_referenced_items": len(referenced_rows),
            "sector_non_confirmed_items": len(inferred_rows) + len(referenced_rows),
            "sector_low_confidence_items": len(low_rows),
            "location_unknown_pct": None if location_unknown_pct < 0 else location_unknown_pct,
            "location_unknown_target_pct": LOCATION_UNKNOWN_TARGET_PCT,
            "potential_duplicate_pairs": int(_float(latest.get("Potential_Duplicate_Pairs"))),
            "potential_duplicate_rate_pct": _float(latest.get("Potential_Duplicate_Rate_Pct")),
            "missed_duplicate_candidate_pairs": _optional_int(
                latest.get("Missed_Duplicate_Candidate_Pairs")
            ),
            "weak_merge_review_pairs": _optional_int(latest.get("Weak_Merge_Review_Pairs")),
            "validated_same_not_grouped_pairs": _optional_int(
                latest.get("Validated_Same_Not_Grouped_Pairs")
            ),
            "pending_review_pairs": _optional_int(latest.get("Pending_Review_Pairs")),
            "corpus_false_positive_rate_pct": _float(latest.get("Corpus_False_Positive_Rate_Pct")),
            "corpus_false_negatives": int(_float(latest.get("Corpus_False_Negatives"))),
            "corpus_classification_errors": int(_float(latest.get("Corpus_Classification_Errors"))),
            "dedup_known_false_merges": int(_float(latest.get("Dedup_Known_False_Merges"))),
        },
        "performance": {
            "duration_seconds": _float(latest.get("Duration_s")),
            "requests": int(_float(latest.get("Requests"))),
            "llm_calls": int(_float(latest.get("LLM_Calls"))),
            "llm_cost_usd": _float(latest.get("LLM_Cost_USD")),
        },
    }


def markdown_report(payload: dict) -> str:
    fresh = payload["freshness"]
    reliability = payload["scheduled_reliability"]
    quality = payload["quality"]
    perf = payload["performance"]
    age = "inconnue" if fresh["age_hours"] is None else f"{fresh['age_hours']:.1f} h"
    scheduled_rate = (
        "n.d."
        if reliability["success_rate_pct"] is None
        else f"{reliability['success_rate_pct']:.2f} %"
    )
    sector_unknown = (
        "n.d."
        if quality["sector_unknown_pct"] is None
        else f"{quality['sector_unknown_pct']:.2f} %"
    )
    location_unknown = (
        "n.d."
        if quality["location_unknown_pct"] is None
        else f"{quality['location_unknown_pct']:.2f} %"
    )
    qual = payload.get("qualification") or {}
    qualification_line = "- Qualification : **{}**{}".format(
        qual.get("state") or "n.d.",
        f" — {qual['label']}" if qual.get("label") else "",
    )
    lines = [
        "## Production — fiabilité quotidienne",
        qualification_line,
        f"- Fraîcheur : **{age}** (cible < {fresh['target_hours']:.0f} h)",
        f"- Succès planifiés : **{scheduled_rate}** sur {reliability['observed']} run(s) observé(s) (cible ≥ {reliability['target_pct']:.0f} %)",
        f"- Série planifiée : **{reliability['consecutive_successes']}/{reliability['required_consecutive_successes']}** succès consécutifs réels",
        f"- Secteur inconnu : **{sector_unknown}** (cible < {quality['sector_unknown_target_pct']:.0f} %)",
        f"- Localisation inconnue : **{location_unknown}** (cible < {quality['location_unknown_target_pct']:.0f} %)",
        "- Doublons potentiellement manqués : **{}**".format(
            quality["missed_duplicate_candidate_pairs"]
            if quality["missed_duplicate_candidate_pairs"] is not None else "n.d."
        ),
        "- Fusions faibles à vérifier : **{}**".format(
            quality["weak_merge_review_pairs"]
            if quality["weak_merge_review_pairs"] is not None else "n.d."
        ),
        "- SAME validés non regroupés : **{}**".format(
            quality["validated_same_not_grouped_pairs"]
            if quality["validated_same_not_grouped_pairs"] is not None else "n.d."
        ),
        "- Paires en attente : **{}**".format(
            quality["pending_review_pairs"]
            if quality["pending_review_pairs"] is not None else "n.d."
        ),
        f"- Corpus : faux positifs **{quality['corpus_false_positive_rate_pct']:.2f} %**, faux négatifs **{quality['corpus_false_negatives']}**, erreurs de classement **{quality['corpus_classification_errors']}**",
        f"- Run : **{perf['duration_seconds']:.1f} s**, {perf['requests']} requêtes, {perf['llm_calls']} appels LLM, **${perf['llm_cost_usd']:.6f}**",
    ]
    if payload["alert_reasons"]:
        lines.append("- Alertes : **" + " ; ".join(payload["alert_reasons"]) + "**")
    return "\n".join(lines)
