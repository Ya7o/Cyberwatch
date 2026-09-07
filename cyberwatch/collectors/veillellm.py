"""Import déterministe du snapshot régional produit par Veille LLM.

La routine conserve à la fois les incidents publiables et les signaux encore
incertains. Seuls les enregistrements explicitement admis ``ACCEPTED`` entrent
dans la base : une panne, un incident informatique ou un sabotage physique sans
preuve cyber reste auditable dans le snapshot sous ``CANDIDATE``.
"""

from __future__ import annotations

import json

from .. import config, status, store
from ..normalize import date_or_empty, organisation_key, searchable
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window


SNAPSHOT_SCHEMA = "cyberwatch-veille-v2"
ADMISSION_ACCEPTED = "ACCEPTED"
ADMISSION_CANDIDATE = "CANDIDATE"
ADMISSIONS = {ADMISSION_ACCEPTED, ADMISSION_CANDIDATE}
TERRITORIES = {config.LOC_REUNION, config.LOC_MAYOTTE}
VALID_THREATS = set(config.THREATS) | {config.THREAT_ACCOUNT}
PUBLISHABLE_THREATS = VALID_THREATS - {config.THREAT_UNKNOWN}


def _load_snapshot(spec: SourceSpec) -> tuple[dict, dict, str, object, list]:
    relative = str(spec.params.get("path") or "").strip()
    if not relative:
        raise ValueError("Chemin Veille LLM absent")
    root = store.ROOT.resolve()
    path = (root / relative).resolve()
    if root not in path.parents:
        raise ValueError("Chemin Veille LLM hors dépôt")
    if not path.is_file():
        raise FileNotFoundError(relative)

    data = json.loads(path.read_text(encoding="utf-8"))
    metadata = data.get("metadata") or {}
    if metadata.get("schema") != SNAPSHOT_SCHEMA:
        raise ValueError(
            f"schema Veille LLM invalide: {metadata.get('schema')!r}; "
            f"attendu={SNAPSHOT_SCHEMA!r}"
        )
    generated_at = str(metadata.get("generated_at") or "").strip()
    generated_date = date_or_empty(generated_at[:10])
    if generated_date is None:
        raise ValueError("metadata.generated_at absent ou invalide")
    scope = metadata.get("scope")
    if not isinstance(scope, list) or set(scope) != TERRITORIES or len(scope) != 2:
        raise ValueError("metadata.scope doit contenir La Réunion et Mayotte")
    records = data.get("records")
    if not isinstance(records, list):
        raise ValueError("records doit être une liste")
    declared = metadata.get("record_count")
    if declared is not None and int(declared) != len(records):
        raise ValueError(f"record_count incohérent: {declared} déclaré, {len(records)} lu")
    return data, metadata, generated_at, generated_date, records


def _validate_record(record: object, index: int) -> dict:
    if not isinstance(record, dict):
        raise ValueError(f"incident #{index} invalide")
    values = {
        "date": str(record.get("date") or "").strip(),
        "organisation": str(record.get("organisation") or "").strip(),
        "territory": str(record.get("territoire") or "").strip(),
        "localisation": str(record.get("localisation") or "").strip(),
        "threat": str(record.get("type_menace") or "").strip(),
        "sector": str(record.get("secteur") or "").strip(),
        "admission": str(record.get("admission") or "").strip().upper(),
        "admission_reason": str(record.get("admission_reason") or "").strip(),
    }
    if date_or_empty(values["date"]) is None:
        raise ValueError(f"date invalide incident #{index}: {values['date']!r}")
    if not values["organisation"] or not values["territory"] or not values["threat"]:
        raise ValueError(f"champs obligatoires absents incident #{index}")
    if values["territory"] not in TERRITORIES:
        raise ValueError(f"territoire invalide incident #{index}: {values['territory']!r}")
    if values["sector"] not in config.SECTORS:
        raise ValueError(f"secteur invalide incident #{index}: {values['sector']!r}")
    if values["threat"] not in VALID_THREATS:
        raise ValueError(f"menace invalide incident #{index}: {values['threat']!r}")
    if values["admission"] not in ADMISSIONS or not values["admission_reason"]:
        raise ValueError(f"admission invalide incident #{index}")
    if values["admission"] == ADMISSION_ACCEPTED and values["threat"] not in PUBLISHABLE_THREATS:
        raise ValueError(f"incident #{index} accepté sans menace cyber qualifiée: {values['threat']!r}")

    raw_score = record.get("score_cyberattaque")
    if isinstance(raw_score, bool):
        raise ValueError(f"score invalide incident #{index}")
    try:
        values["score"] = int(raw_score)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"score invalide incident #{index}") from exc
    if not 0 <= values["score"] <= 100:
        raise ValueError(f"score hors bornes incident #{index}: {values['score']}")
    raw_evidence = record.get("sources") or []
    if not isinstance(raw_evidence, list) or not raw_evidence:
        raise ValueError(f"aucune source de référence incident #{index}")
    values["evidence"] = [
        str(url).strip() for url in raw_evidence
        if str(url).strip().startswith(("https://", "http://"))
    ]
    if len(values["evidence"]) != len(raw_evidence) or len(values["evidence"]) != len(set(values["evidence"])):
        raise ValueError(f"URLs de référence invalides incident #{index}")
    return values


def _entry_from_record(record: dict, values: dict) -> RawEntry:
    actor = str(record.get("acteur") or "").strip()
    summary_parts = [
        str(record.get("statut") or "").strip(),
        str(record.get("synthese") or "").strip(),
        str(record.get("impact_connu") or "").strip(),
        f"Score Veille LLM: {values['score']}/100",
    ]
    if actor:
        summary_parts.append(f"Acteur: {actor}")
    metadata = {
        "admission": values["admission"], "admission_reason": values["admission_reason"],
        "localisation": values["localisation"], "acteur": actor,
        "statut": str(record.get("statut") or "").strip(),
        "score_cyberattaque": values["score"],
        "impact_connu": str(record.get("impact_connu") or "").strip(),
        "synthese": str(record.get("synthese") or "").strip(),
        "sources": values["evidence"],
        "evolution": str(record.get("evolution") or "").strip(),
        "secteur": values["sector"],
    }
    return RawEntry(
        title=f"{values['organisation']} : {values['threat']}",
        url=values["evidence"][0], published=values["date"], event_date=values["date"],
        organisation=values["organisation"], sector=values["sector"],
        location=values["territory"], threat=values["threat"],
        summary=". ".join(part for part in summary_parts if part),
        content="Références documentaires: " + " | ".join(values["evidence"]),
        source_metadata=metadata,
    )


class VeilleLlmCollector(Collector):
    """Lit le snapshot complet pour inclure les découvertes historiques tardives."""

    name = "veillellm"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        _, metadata, generated_at, generated_date, records = _load_snapshot(spec)

        entries: list[RawEntry] = []
        future = 0
        requested_window_hits = 0
        admission_counts = {value: 0 for value in ADMISSIONS}
        seen_records: set[tuple[str, str, str, str]] = set()

        for index, record in enumerate(records, start=1):
            values = _validate_record(record, index)
            admission_counts[values["admission"]] += 1
            record_key = (
                values["date"], organisation_key(values["organisation"]),
                values["territory"], searchable(values["localisation"]),
            )
            if record_key in seen_records:
                raise ValueError(f"record dupliqué incident #{index}: {record_key!r}")
            seen_records.add(record_key)
            if values["date"] > window.end:
                future += 1
                continue
            if values["admission"] != ADMISSION_ACCEPTED:
                continue
            if window.contains(values["date"]):
                requested_window_hits += 1
            entries.append(_entry_from_record(record, values))

        declared_accepted = metadata.get("accepted_count")
        declared_candidates = metadata.get("candidate_count")
        if declared_accepted is None or int(declared_accepted) != admission_counts[ADMISSION_ACCEPTED]:
            raise ValueError("metadata.accepted_count incohérent")
        if declared_candidates is None or int(declared_candidates) != admission_counts[ADMISSION_CANDIDATE]:
            raise ValueError("metadata.candidate_count incohérent")

        max_age = int(spec.params.get("max_snapshot_age_days", 2))
        end_date = date_or_empty(window.end)
        freshness_days = max(0, (end_date - generated_date).days) if end_date else 0
        fresh = freshness_days <= max_age

        return CollectResult(
            entries=entries,
            reached_boundary=fresh,
            units_done=len(records),
            units_expected=len(records),
            calls=0,
            reason_code=status.REASON_OK if fresh else status.REASON_INCOMPLETE,
            access_method="repository_json",
            comment=(
                f"snapshot_records={len(records)}; admitted="
                f"{admission_counts[ADMISSION_ACCEPTED]}; candidates="
                f"{admission_counts[ADMISSION_CANDIDATE]}; materialized={len(entries)}; "
                f"future={future}; requested_window_hits={requested_window_hits}; "
                f"generated_at={generated_at}; freshness_days={freshness_days}; "
                f"max_age_days={max_age}"
            ),
            items_seen=admission_counts[ADMISSION_ACCEPTED],
            items_in_window=requested_window_hits,
        )
