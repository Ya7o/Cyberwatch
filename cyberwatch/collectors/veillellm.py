"""Import déterministe du snapshot régional produit par Veille LLM.

La routine conserve à la fois les incidents publiables et les signaux encore
incertains. Seuls les enregistrements explicitement admis ``ACCEPTED`` entrent
dans la base : une panne, un incident informatique ou un sabotage physique sans
preuve cyber reste auditable dans le snapshot sous ``CANDIDATE``.
"""

from __future__ import annotations

import json

from .. import config, status, store
from ..normalize import date_or_empty, organisation_key
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window


SNAPSHOT_SCHEMA = "cyberwatch-veille-v2"
ADMISSION_ACCEPTED = "ACCEPTED"
ADMISSION_CANDIDATE = "CANDIDATE"
ADMISSIONS = {ADMISSION_ACCEPTED, ADMISSION_CANDIDATE}
TERRITORIES = {config.LOC_REUNION, config.LOC_MAYOTTE}
VALID_THREATS = set(config.THREATS) | {config.THREAT_ACCOUNT}
PUBLISHABLE_THREATS = VALID_THREATS - {config.THREAT_UNKNOWN}


class VeilleLlmCollector(Collector):
    """Lit le snapshot complet pour inclure les découvertes historiques tardives."""

    name = "veillellm"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
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
            raise ValueError(
                f"record_count incohérent: {declared} déclaré, {len(records)} lu"
            )

        entries: list[RawEntry] = []
        future = 0
        requested_window_hits = 0
        admission_counts = {value: 0 for value in ADMISSIONS}
        seen_records: set[tuple[str, str, str]] = set()

        for index, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                raise ValueError(f"incident #{index} invalide")

            date = str(record.get("date") or "").strip()
            organisation = str(record.get("organisation") or "").strip()
            territory = str(record.get("territoire") or "").strip()
            threat = str(record.get("type_menace") or "").strip()
            sector = str(record.get("secteur") or "").strip()
            admission = str(record.get("admission") or "").strip().upper()
            admission_reason = str(record.get("admission_reason") or "").strip()
            if date_or_empty(date) is None:
                raise ValueError(f"date invalide incident #{index}: {date!r}")
            if not organisation or not territory or not threat:
                raise ValueError(f"champs obligatoires absents incident #{index}")
            if territory not in TERRITORIES:
                raise ValueError(f"territoire invalide incident #{index}: {territory!r}")
            if sector not in config.SECTORS:
                raise ValueError(f"secteur invalide incident #{index}: {sector!r}")
            if threat not in VALID_THREATS:
                raise ValueError(f"menace invalide incident #{index}: {threat!r}")
            if admission not in ADMISSIONS or not admission_reason:
                raise ValueError(f"admission invalide incident #{index}")
            if admission == ADMISSION_ACCEPTED and threat not in PUBLISHABLE_THREATS:
                raise ValueError(
                    f"incident #{index} accepté sans menace cyber qualifiée: {threat!r}"
                )
            admission_counts[admission] += 1

            record_key = (date, organisation_key(organisation), territory)
            if record_key in seen_records:
                raise ValueError(f"record dupliqué incident #{index}: {record_key!r}")
            seen_records.add(record_key)

            raw_score = record.get("score_cyberattaque")
            if isinstance(raw_score, bool):
                raise ValueError(f"score invalide incident #{index}")
            try:
                score = int(raw_score)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"score invalide incident #{index}") from exc
            if not 0 <= score <= 100:
                raise ValueError(f"score hors bornes incident #{index}: {score}")

            raw_evidence = record.get("sources") or []
            if not isinstance(raw_evidence, list) or not raw_evidence:
                raise ValueError(f"aucune source de référence incident #{index}")
            evidence = [
                str(url).strip() for url in raw_evidence
                if str(url).strip().startswith(("https://", "http://"))
            ]
            if len(evidence) != len(raw_evidence) or len(evidence) != len(set(evidence)):
                raise ValueError(f"URLs de référence invalides incident #{index}")

            if date > window.end:
                future += 1
                continue
            if admission != ADMISSION_ACCEPTED:
                continue
            # Le score reste une information affichable (transmise dans le
            # résumé ci-dessous). L'admission explicite, déjà validée, est le
            # seul garde de publication.
            if window.contains(date):
                requested_window_hits += 1

            summary_parts = [
                str(record.get("statut") or "").strip(),
                str(record.get("synthese") or "").strip(),
                str(record.get("impact_connu") or "").strip(),
                f"Score Veille LLM: {score}/100",
            ]
            actor = str(record.get("acteur") or "").strip()
            if actor:
                summary_parts.append(f"Acteur: {actor}")

            # Champs bruts du record, préservés pour la couche `source_facts`
            # (§13 METHODOLOGY.md) sans changer `summary`/`content` historiques
            # ci-dessous : `evolution` n'était même pas lu auparavant.
            source_metadata = {
                "admission": admission,
                "admission_reason": admission_reason,
                "localisation": str(record.get("localisation") or "").strip(),
                "acteur": actor,
                "statut": str(record.get("statut") or "").strip(),
                "score_cyberattaque": score,
                "impact_connu": str(record.get("impact_connu") or "").strip(),
                "synthese": str(record.get("synthese") or "").strip(),
                "sources": evidence,
                "evolution": str(record.get("evolution") or "").strip(),
                "secteur": str(record.get("secteur") or "").strip(),
            }

            entries.append(RawEntry(
                title=f"{organisation} : {threat}",
                # Une ligne publiée pointe vers sa preuve principale. Le JSON
                # versionné reste la provenance analytique de la source, mais
                # n'est pas présenté comme la source documentaire de l'incident.
                url=evidence[0],
                published=date,
                event_date=date,
                organisation=organisation,
                sector=sector,
                location=territory,
                threat=threat,
                summary=". ".join(part for part in summary_parts if part),
                content="Références documentaires: " + " | ".join(evidence),
                source_metadata=source_metadata,
            ))

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
