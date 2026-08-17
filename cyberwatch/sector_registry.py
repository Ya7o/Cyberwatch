"""Registre canonique organisation -> secteur et file de qualification.

Le registre n'est pas une nouvelle heuristique de texte. Il agrège des preuves
explicites déjà disponibles et sépare strictement :

- ``AUTO`` : canaux versionnés autorisés à compléter un ``Inconnu`` ;
- ``REVIEW`` : candidat utile mais non démontré assez précis ;
- ``CONFLICT`` : plusieurs secteurs incompatibles, aucune application.

Les applications sont persistées et rejouées de façon réversible : un item qui
a été complété par le registre est restauré à sa valeur précédente avant chaque
nouvelle qualification. Il ne peut donc jamais devenir sa propre preuve au run
suivant.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from . import config, org_enrichment, sector as sector_policy, store
from .model import Item
from .normalize import organisation_key, searchable

DECISION_AUTO = "AUTO"
DECISION_REVIEW = "REVIEW"
DECISION_CONFLICT = "CONFLICT"

DEFAULT_POLICY = {
    "schema_version": 1,
    "minimum_precision_pct": 95.0,
    "minimum_cases": 10,
    "channels": {
        "manual_validation": {"enabled": True, "requires_golden": False},
        "manual_reference": {"enabled": True, "requires_golden": False},
        "structured_source": {"enabled": True, "requires_golden": False},
        "consensus_multi_source": {"enabled": False, "requires_golden": True},
        "official_subject_activity": {"enabled": False, "requires_golden": True},
        "registry_exact_naf": {"enabled": False, "requires_golden": True},
        "registry_llm": {"enabled": False, "requires_golden": True},
        "legacy_official_site": {"enabled": False, "requires_golden": True},
        "known_item_single": {"enabled": False, "requires_golden": True},
    },
}

# Le choix d'une preuve primaire est purement descriptif. L'autorisation AUTO
# vient exclusivement du fichier de politique versionné.
_CHANNEL_PRIORITY = {
    "manual_validation": 0,
    "manual_reference": 1,
    "structured_source": 2,
    "consensus_multi_source": 3,
    "official_subject_activity": 4,
    "registry_exact_naf": 5,
    "registry_llm": 6,
    "legacy_official_site": 7,
    "known_item_single": 8,
}


@dataclass(frozen=True)
class Candidate:
    organisation_key: str
    organisation: str
    sector: str
    channel: str
    source: str = ""
    source_id: str = ""
    item_id: str = ""
    evidence_url: str = ""
    evidence_text: str = ""


def load_policy(path: Path | None = None) -> dict:
    target = path or store.SECTOR_AUTO_POLICY_JSON
    if not target.exists():
        return json.loads(json.dumps(DEFAULT_POLICY))
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return json.loads(json.dumps(DEFAULT_POLICY))
    if not isinstance(payload, dict):
        return json.loads(json.dumps(DEFAULT_POLICY))
    merged = json.loads(json.dumps(DEFAULT_POLICY))
    merged.update({k: v for k, v in payload.items() if k != "channels"})
    channels = payload.get("channels")
    if isinstance(channels, dict):
        for name, value in channels.items():
            if isinstance(value, dict):
                merged["channels"].setdefault(name, {}).update(value)
    return merged


def channel_enabled(channel: str, policy: dict | None = None) -> bool:
    policy = policy or load_policy()
    value = (policy.get("channels") or {}).get(channel) or {}
    return bool(value.get("enabled", False))


def org_record_channel(record: org_enrichment.OrgEnrichmentRecord | dict) -> str:
    def get(name: str) -> str:
        if isinstance(record, dict):
            return str(record.get(name) or "")
        return str(getattr(record, name, "") or "")

    via = get("Validated_Via")
    if via == "official_subject_activity":
        return "official_subject_activity"
    if via == "deterministic":
        return "registry_exact_naf"
    if via == "llm":
        return "registry_llm"
    if via == "official_site":
        return "legacy_official_site"
    return "registry_exact_naf"


def org_record_auto_allowed(
    record: org_enrichment.OrgEnrichmentRecord | dict,
    policy: dict | None = None,
) -> bool:
    return channel_enabled(org_record_channel(record), policy)


def _candidate(
    key: str,
    organisation: str,
    sector: str,
    channel: str,
    **kwargs,
) -> Candidate | None:
    key = organisation_key(key or organisation)
    if not key or sector not in config.SECTORS or sector == config.SECTOR_UNKNOWN:
        return None
    return Candidate(key, organisation, sector, channel, **kwargs)


def _manual_candidates(reference: dict) -> list[Candidate]:
    result: list[Candidate] = []
    for key, entry in reference.items():
        candidate = _candidate(
            key,
            getattr(entry, "organisation", "") or key,
            getattr(entry, "sector", ""),
            "manual_reference",
            source="enrichment_reference.csv",
            evidence_url=getattr(entry, "validation_url", ""),
            evidence_text=getattr(entry, "reason", ""),
        )
        if candidate:
            result.append(candidate)
    return result


def _structured_candidates(items: list[Item], source_fact_rows: list[dict]) -> list[Candidate]:
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    result: list[Candidate] = []
    seen: set[tuple[str, str, str]] = set()
    for row in source_fact_rows:
        if row.get("Source_ID") != "RANSOMWARE_LIVE":
            continue
        item = by_id.get((row.get("Item_ID") or "").strip())
        if item is None:
            continue
        raw = (row.get("Source_Sector_Raw") or "").strip()
        sector = sector_policy.classify_source_sector(raw)
        marker = (item.Item_ID, raw, sector)
        if marker in seen:
            continue
        seen.add(marker)
        candidate = _candidate(
            item.Organisation_Key,
            item.Organisation_Raw,
            sector,
            "structured_source",
            source="ransomware.live:sector",
            source_id=item.Source_ID,
            item_id=item.Item_ID,
            evidence_url=item.URL,
            evidence_text=raw,
        )
        if candidate:
            result.append(candidate)
    return result


def _existing_manual_candidates(rows: list[dict]) -> list[Candidate]:
    result: list[Candidate] = []
    for row in rows:
        if row.get("Evidence_Type") != "manual_validation":
            continue
        candidate = _candidate(
            row.get("Organisation_Key", ""),
            row.get("Organisation", ""),
            row.get("Sector", ""),
            "manual_validation",
            source=row.get("Evidence_Sources", "manual_validation"),
            evidence_url=(row.get("Evidence_URLs") or "").split(" | ")[0],
            evidence_text=row.get("Evidence_Text", ""),
        )
        if candidate:
            result.append(candidate)
    return result


def _known_item_candidates(items: list[Item], excluded_item_ids: set[str]) -> list[Candidate]:
    grouped: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        if (
            item.Item_ID in excluded_item_ids
            or not item.Organisation_Key
            or item.Sector == config.SECTOR_UNKNOWN
            or item.Sector not in config.SECTORS
        ):
            continue
        grouped[item.Organisation_Key].append(item)

    result: list[Candidate] = []
    for key, rows in grouped.items():
        by_sector: dict[str, list[Item]] = defaultdict(list)
        for item in rows:
            by_sector[item.Sector].append(item)
        if len(by_sector) == 1:
            sector, supporting = next(iter(by_sector.items()))
            source_ids = {item.Source_ID for item in supporting if item.Source_ID}
            channel = "consensus_multi_source" if len(source_ids) >= 2 else "known_item_single"
            first = sorted(supporting, key=lambda item: (item.Source_ID, item.Item_ID))[0]
            candidate = _candidate(
                key,
                first.Organisation_Raw,
                sector,
                channel,
                source=" | ".join(sorted(source_ids)),
                source_id=" | ".join(sorted(source_ids)),
                item_id=" | ".join(sorted(item.Item_ID for item in supporting if item.Item_ID)),
                evidence_url=" | ".join(sorted({item.URL for item in supporting if item.URL})),
                evidence_text=(
                    f"{len(supporting)} item(s) connu(s), "
                    f"{len(source_ids)} source(s), même secteur"
                ),
            )
            if candidate:
                result.append(candidate)
        else:
            # Plusieurs secteurs connus pour la même identité : chaque valeur
            # devient un candidat REVIEW et la résolution produira CONFLICT.
            for sector, supporting in sorted(by_sector.items()):
                first = sorted(supporting, key=lambda item: (item.Source_ID, item.Item_ID))[0]
                candidate = _candidate(
                    key,
                    first.Organisation_Raw,
                    sector,
                    "known_item_single",
                    source=" | ".join(sorted({item.Source_ID for item in supporting})),
                    item_id=" | ".join(sorted(item.Item_ID for item in supporting if item.Item_ID)),
                    evidence_text="Secteur déjà présent sur une occurrence canonique",
                )
                if candidate:
                    result.append(candidate)
    return result


def _cache_candidates(rows: list[dict]) -> list[Candidate]:
    result: list[Candidate] = []
    for row in rows:
        if row.get("Match_Status") != org_enrichment.MATCHED:
            continue
        sector = (row.get("Validated_Sector") or "").strip()
        channel = org_record_channel(row)
        if not sector:
            sector = org_enrichment.sector_for_activity_label(row.get("Activity_Label", ""))
            channel = "registry_exact_naf"
        candidate = _candidate(
            row.get("Organisation_Key", ""),
            row.get("Query_Name", "") or row.get("Matched_Name", ""),
            sector,
            channel,
            source=row.get("Evidence_Source", ""),
            evidence_url=row.get("Evidence_URL", ""),
            evidence_text=row.get("Activity_Label", ""),
        )
        if candidate:
            result.append(candidate)
    return result


def _preferred(candidates: list[Candidate]) -> Candidate:
    return sorted(
        candidates,
        key=lambda row: (
            _CHANNEL_PRIORITY.get(row.channel, 99),
            row.source,
            row.evidence_url,
            row.item_id,
        ),
    )[0]


def build_registry(
    items: list[Item],
    reference: dict,
    *,
    source_fact_rows: list[dict] | None = None,
    org_cache_rows: list[dict] | None = None,
    existing_rows: list[dict] | None = None,
    previous_applications: list[dict] | None = None,
    policy: dict | None = None,
) -> list[dict]:
    """Construit le registre à partir de preuves indépendantes et versionnées."""
    source_fact_rows = source_fact_rows if source_fact_rows is not None else store.read_csv(store.SOURCE_FACTS_CSV)
    org_cache_rows = org_cache_rows if org_cache_rows is not None else store.load_org_enrichment_cache()
    existing_rows = existing_rows if existing_rows is not None else store.load_organisation_sector_registry()
    previous_applications = previous_applications if previous_applications is not None else store.load_sector_registry_applications()
    policy = policy or load_policy()

    excluded = {
        row.get("Item_ID", "")
        for row in previous_applications
        if row.get("Decision") in {"APPLIED", "PRESERVED"}
    }
    candidates = []
    candidates.extend(_existing_manual_candidates(existing_rows))
    candidates.extend(_manual_candidates(reference))
    candidates.extend(_structured_candidates(items, source_fact_rows))
    candidates.extend(_known_item_candidates(items, excluded))
    candidates.extend(_cache_candidates(org_cache_rows))

    display_names = defaultdict(Counter)
    for item in items:
        if item.Organisation_Key and item.Organisation_Raw:
            display_names[item.Organisation_Key][item.Organisation_Raw] += 1

    grouped: dict[str, list[Candidate]] = defaultdict(list)
    dedup: set[tuple] = set()
    for row in candidates:
        marker = (
            row.organisation_key, row.sector, row.channel, row.source,
            row.item_id, row.evidence_url, row.evidence_text,
        )
        if marker in dedup:
            continue
        dedup.add(marker)
        grouped[row.organisation_key].append(row)

    output: list[dict] = []
    for key in sorted(grouped):
        rows = grouped[key]
        auto_rows = [row for row in rows if channel_enabled(row.channel, policy)]
        auto_sectors = sorted({row.sector for row in auto_rows})
        all_sectors = sorted({row.sector for row in rows})

        if len(auto_sectors) > 1:
            decision = DECISION_CONFLICT
            sector = config.SECTOR_UNKNOWN
            primary = _preferred(auto_rows)
        elif len(auto_sectors) == 1:
            decision = DECISION_AUTO
            sector = auto_sectors[0]
            primary = _preferred([row for row in auto_rows if row.sector == sector])
        elif len(all_sectors) == 1:
            decision = DECISION_REVIEW
            sector = all_sectors[0]
            primary = _preferred(rows)
        else:
            decision = DECISION_CONFLICT
            sector = config.SECTOR_UNKNOWN
            primary = _preferred(rows)

        sources = sorted({row.source for row in rows if row.source})
        source_ids: set[str] = set()
        item_ids: set[str] = set()
        urls: set[str] = set()
        channels = sorted({row.channel for row in rows})
        for row in rows:
            source_ids.update(part.strip() for part in row.source_id.split(" | ") if part.strip())
            item_ids.update(part.strip() for part in row.item_id.split(" | ") if part.strip())
            urls.update(part.strip() for part in row.evidence_url.split(" | ") if part.strip())
        organisation = primary.organisation
        if display_names.get(key):
            organisation = sorted(
                display_names[key].items(), key=lambda pair: (-pair[1], pair[0])
            )[0][0]

        output.append({
            "Organisation_Key": key,
            "Organisation": organisation,
            "Sector": sector,
            "Decision": decision,
            "Confidence": "HIGH" if decision == DECISION_AUTO else "",
            "Evidence_Type": primary.channel,
            "Evidence_Types": " | ".join(channels),
            "Evidence_Sources": " | ".join(sources),
            "Evidence_URLs": " | ".join(sorted(urls)),
            "Evidence_Text": primary.evidence_text,
            "Candidate_Sectors": " | ".join(all_sectors),
            "Source_Count": str(len(source_ids)),
            "Evidence_Count": str(len(rows)),
            "Supporting_Item_IDs": " | ".join(sorted(item_ids)),
            "Policy_Auto_Enabled": "1" if decision == DECISION_AUTO else "0",
        })
    return output


def restore_registry_applications(items: list[Item], rows: list[dict] | None = None) -> int:
    """Annule les valeurs dérivées du registre avant de le recalculer."""
    rows = rows if rows is not None else store.load_sector_registry_applications()
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    restored = 0
    for row in rows:
        if row.get("Decision") not in {"APPLIED", "PRESERVED"}:
            continue
        item = by_id.get(row.get("Item_ID", ""))
        if item is None:
            continue
        previous = row.get("Previous_Sector") or config.SECTOR_UNKNOWN
        final = row.get("Final_Sector") or ""
        if final and item.Sector == final:
            item.Sector = previous
            restored += 1
    return restored


def apply_registry(
    items: list[Item],
    registry_rows: list[dict],
) -> tuple[int, list[dict], int]:
    """Complète uniquement les inconnus depuis les lignes AUTO du registre."""
    auto = {
        row.get("Organisation_Key", ""): row
        for row in registry_rows
        if row.get("Decision") == DECISION_AUTO
        and row.get("Sector") in config.SECTORS
        and row.get("Sector") != config.SECTOR_UNKNOWN
    }
    changed = 0
    known_conflicts = 0
    applications: list[dict] = []
    for item in items:
        row = auto.get(item.Organisation_Key)
        if row is None:
            continue
        candidate = row["Sector"]
        if item.Sector == config.SECTOR_UNKNOWN:
            previous = item.Sector
            item.Sector = candidate
            changed += 1
            applications.append({
                "Item_ID": item.Item_ID,
                "Organisation_Key": item.Organisation_Key,
                "Organisation": item.Organisation_Raw,
                "Previous_Sector": previous,
                "Final_Sector": candidate,
                "Evidence_Type": row.get("Evidence_Type", ""),
                "Evidence_URLs": row.get("Evidence_URLs", ""),
                "Decision": "APPLIED",
            })
        elif item.Sector != candidate:
            known_conflicts += 1
    applications.sort(key=lambda row: row["Item_ID"])
    return changed, applications, known_conflicts


def _source_raw_by_item(source_fact_rows: list[dict]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for row in source_fact_rows:
        item_id = (row.get("Item_ID") or "").strip()
        raw = (row.get("Source_Sector_Raw") or "").strip()
        if item_id and raw:
            result[item_id].add(raw)
    return result


def build_enrichment_queue(
    items: list[Item],
    registry_rows: list[dict],
    *,
    source_fact_rows: list[dict] | None = None,
    challenger_provenance: list[dict] | None = None,
) -> list[dict]:
    """Classe les organisations encore inconnues par prochain levier utile."""
    source_fact_rows = source_fact_rows if source_fact_rows is not None else store.read_csv(store.SOURCE_FACTS_CSV)
    challenger_provenance = challenger_provenance or []
    raw_by_item = _source_raw_by_item(source_fact_rows)
    registry = {row.get("Organisation_Key", ""): row for row in registry_rows}
    item_by_id = {item.Item_ID: item for item in items if item.Item_ID}

    challengers: dict[str, list[dict]] = defaultdict(list)
    for row in challenger_provenance:
        if row.get("Field") != "Sector":
            continue
        candidate = row.get("Candidate_Value", "")
        if candidate not in config.SECTORS or candidate == config.SECTOR_UNKNOWN:
            continue
        item = item_by_id.get(row.get("Item_ID", ""))
        if item is not None:
            challengers[item.Organisation_Key].append(row)

    grouped: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        if item.Sector == config.SECTOR_UNKNOWN and item.Organisation_Key:
            grouped[item.Organisation_Key].append(item)

    rank = {
        "REGISTRY_CONFLICT": 1,
        "OFFICIAL_EVIDENCE_REVIEW": 2,
        "CONSENSUS_REVIEW": 3,
        "KNOWN_ITEM_REVIEW": 4,
        "RAW_SECTOR_UNMAPPED": 5,
        "JSON_CHALLENGER": 6,
        "NO_EVIDENCE": 7,
    }
    queue: list[dict] = []
    for key, rows in grouped.items():
        reg = registry.get(key, {})
        decision = reg.get("Decision", "")
        channel = reg.get("Evidence_Type", "")
        category = "NO_EVIDENCE"
        if decision == DECISION_CONFLICT:
            category = "REGISTRY_CONFLICT"
        elif decision == DECISION_REVIEW and channel == "official_subject_activity":
            category = "OFFICIAL_EVIDENCE_REVIEW"
        elif decision == DECISION_REVIEW and channel == "consensus_multi_source":
            category = "CONSENSUS_REVIEW"
        elif decision == DECISION_REVIEW:
            category = "KNOWN_ITEM_REVIEW"

        raw_values: set[str] = set()
        for item in rows:
            raw_values.update(raw_by_item.get(item.Item_ID, set()))
        unmapped_raw = sorted(
            raw for raw in raw_values
            if sector_policy.classify_source_sector(raw) == config.SECTOR_UNKNOWN
        )
        if category == "NO_EVIDENCE" and unmapped_raw:
            category = "RAW_SECTOR_UNMAPPED"
        challenger_rows = challengers.get(key, [])
        if category == "NO_EVIDENCE" and challenger_rows:
            category = "JSON_CHALLENGER"

        candidate_sectors = {
            part.strip()
            for part in (reg.get("Candidate_Sectors") or "").split(" | ")
            if part.strip() and part.strip() != config.SECTOR_UNKNOWN
        }
        candidate_sectors.update(
            row.get("Candidate_Value", "") for row in challenger_rows
            if row.get("Candidate_Value")
        )
        urls = {
            item.URL for item in rows if item.URL
        }
        urls.update(
            part.strip()
            for part in (reg.get("Evidence_URLs") or "").split(" | ")
            if part.strip()
        )
        sources = sorted({item.Source_ID for item in rows if item.Source_ID})
        display = Counter(item.Organisation_Raw for item in rows if item.Organisation_Raw)
        organisation = sorted(display.items(), key=lambda pair: (-pair[1], pair[0]))[0][0]
        queue.append({
            "Priority": "",
            "Organisation_Key": key,
            "Organisation": organisation,
            "Unknown_Items": str(len(rows)),
            "Sources": " | ".join(sources),
            "Category": category,
            "Candidate_Sectors": " | ".join(sorted(candidate_sectors)),
            "Raw_Sector_Values": " | ".join(unmapped_raw),
            "Evidence_Type": reg.get("Evidence_Type", ""),
            "Evidence_URLs": " | ".join(sorted(urls)),
            "Evidence_Text": reg.get("Evidence_Text", ""),
            "Registry_Decision": decision,
            "Reason": (
                "auto-disabled candidate" if decision == DECISION_REVIEW
                else "conflicting candidates" if decision == DECISION_CONFLICT
                else "no trusted sector evidence yet"
            ),
        })

    queue.sort(
        key=lambda row: (
            rank.get(row["Category"], 99),
            -int(row["Unknown_Items"] or 0),
            row["Organisation_Key"],
        )
    )
    for index, row in enumerate(queue, 1):
        row["Priority"] = str(index)
    return queue


def registry_summary(registry_rows: list[dict], queue_rows: list[dict], applications: list[dict]) -> dict:
    decisions = Counter(row.get("Decision", "") for row in registry_rows)
    channels = Counter(row.get("Evidence_Type", "") for row in registry_rows)
    categories = Counter(row.get("Category", "") for row in queue_rows)
    return {
        "registry_rows": len(registry_rows),
        "auto_rows": decisions.get(DECISION_AUTO, 0),
        "review_rows": decisions.get(DECISION_REVIEW, 0),
        "conflict_rows": decisions.get(DECISION_CONFLICT, 0),
        "applications": len(applications),
        "queue_organisations": len(queue_rows),
        "registry_channels": dict(sorted(channels.items())),
        "queue_categories": dict(sorted(categories.items())),
    }
