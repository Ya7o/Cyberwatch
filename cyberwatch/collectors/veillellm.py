"""Import déterministe du snapshot JSON produit par Veille LLM.

La source est analytique : elle peut ajouter ou enrichir un incident, mais ne
constitue pas une corroboration éditoriale indépendante lorsqu'une source
directe couvre déjà le même événement.
"""

from __future__ import annotations

import json

from .. import store
from ..normalize import date_or_empty
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window


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
        records = data.get("incidents")
        if not isinstance(records, list):
            raise ValueError("incidents doit être une liste")

        declared = metadata.get("record_count")
        if declared is not None and int(declared) != len(records):
            raise ValueError(
                f"record_count incohérent: {declared} déclaré, {len(records)} lu"
            )

        min_score = int(spec.params.get("min_score", 50))
        entries: list[RawEntry] = []
        weak = 0
        future = 0
        requested_window_hits = 0

        for index, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                raise ValueError(f"incident #{index} invalide")

            date = str(record.get("date") or "").strip()
            organisation = str(record.get("organisation") or "").strip()
            territory = str(record.get("territoire") or "").strip()
            threat = str(record.get("type_menace") or "").strip()
            if date_or_empty(date) is None:
                raise ValueError(f"date invalide incident #{index}: {date!r}")
            if not organisation or not territory or not threat:
                raise ValueError(f"champs obligatoires absents incident #{index}")

            raw_score = record.get("score_cyberattaque")
            if isinstance(raw_score, bool):
                raise ValueError(f"score invalide incident #{index}")
            try:
                score = int(raw_score)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"score invalide incident #{index}") from exc
            if not 0 <= score <= 100:
                raise ValueError(f"score hors bornes incident #{index}: {score}")

            evidence = record.get("sources") or []
            if not isinstance(evidence, list) or not evidence:
                raise ValueError(f"aucune source de référence incident #{index}")
            evidence = [
                str(url).strip() for url in evidence
                if str(url).strip().startswith(("https://", "http://"))
            ]
            if not evidence:
                raise ValueError(f"aucune URL de référence valide incident #{index}")

            if date > window.end:
                future += 1
                continue
            if score < min_score:
                weak += 1
                continue
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

            entries.append(RawEntry(
                title=f"{organisation} : {threat}",
                url=spec.start_url,
                published=date,
                event_date=date,
                organisation=organisation,
                sector=str(record.get("secteur") or "").strip(),
                location=territory,
                threat=threat,
                summary=". ".join(part for part in summary_parts if part),
                content="Références documentaires: " + " | ".join(evidence),
            ))

        return CollectResult(
            entries=entries,
            reached_boundary=True,
            units_done=len(records),
            units_expected=len(records),
            calls=0,
            access_method="repository_json",
            comment=(
                f"snapshot_records={len(records)}; accepted={len(entries)}; "
                f"weak_below_{min_score}={weak}; future={future}; "
                f"requested_window_hits={requested_window_hits}"
            ),
            items_seen=len(records),
            items_in_window=requested_window_hits,
        )
