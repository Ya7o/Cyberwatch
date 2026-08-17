"""Orchestration d'un run : collecte, normalisation, reconstruction, journaux.

Le runner applique les algorithmes `CREATE` (§24), `MAJ` (§25) et `REPLAY` (§26),
et produit les journaux `RUN_SOURCES` et `RUN_LOG` ainsi que l'état de veille
`ENTITY_WATCH`.

Principe de robustesse : **aucune source ne peut faire échouer un run**. Toute
exception est convertie en statut `FAIL` documenté, et les données déjà
collectées sont conservées.
"""

from __future__ import annotations

import datetime as dt
import time
from collections import defaultdict
import os
import subprocess
from dataclasses import dataclass, field

from . import ai, config, enrichment, identity, incident_identity, org_enrichment, sector as sector_policy, source_facts, source_facts_ai, sources, status, store, watchlists
from .qualification import qualify
from .collectors import get_collector
from .collectors.cyberattaque_org import (
    is_negated_incident,
    is_obvious_multi,
    organisation_from_cyberattaque_entry,
)
from .collectors.base import CollectResult, RawEntry, SourceSpec, Window
from .dedup import build_incidents, merge_items
from .http import Budget, HttpClient
from .model import Incident, Item
from .normalize import (
    classify_location,
    searchable,
    classify_threat,
    clean_organisation,
    extract_activity_description,
    find_known_entity,
    looks_cyber,
    organisation_from_entry_title,
    organisation_from_title,
    organisation_key,
)

MODE_CREATE = "CREATE"
MODE_MAJ = "MAJ"
MODE_REPLAY = "REPLAY"
MODE_DIAGNOSE = "DIAGNOSE"


def _local_title_names_a_victim(entry: RawEntry, organisation: str) -> bool:
    """Évite de transformer une alerte préventive en incident subi.

    Les médias locaux citent souvent une mairie parce qu'elle alerte ses
    administrés contre une arnaque. Une entité reconnue dans ce contexte n'est
    pas une victime. Pour les sources à ``require_victim``, une relation doit
    donc être visible dans le titre : cyberattaque/incident visant l'entité,
    ou formulation explicite de victime. Le corps reste disponible pour
    extraire l'organisation mais ne peut pas à lui seul inverser ce sens.
    """
    title = searchable(entry.title)
    org = searchable(organisation)
    if not title or not org:
        return False
    body = searchable(f"{entry.summary} {entry.content}")
    if org in body and any(marker in body for marker in (
        "victime d une cyberattaque", "victime d une attaque informatique",
        "a subi une cyberattaque", "a ete cyberattaque",
    )):
        return True
    warning = any(marker in title for marker in (
        "alerte", "met en garde", "faux profil", "faux numero", "escroc", "escroquer",
    ))
    incident = any(marker in title for marker in (
        "cyberattaque", "incident de cybersecurite", "attaque informatique",
        "piratage", "rancongiciel", "ransomware", "victime",
    ))
    return incident and not (warning and "victime" not in title)


def code_commit() -> str:
    if os.getenv("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=store.ROOT, text=True
        ).strip()
    except Exception:
        return ""


def save_snapshot_provenance(
    items: list[Item], incidents: list[Incident], *, operation: str,
    run_id: str = "", mode: str = "", as_of: str = "",
    target_start: str = "", target_end: str = "",
) -> dict:
    """Enregistre la provenance du snapshot déjà écrit sur disque."""
    payload = {
        "As_Of": as_of,
        "Operation": operation,
        "Run_ID": run_id,
        "Mode": mode,
        "Target_Start": target_start,
        "Target_End": target_end,
        "Items_Count": len(items),
        "Incidents_Count": len(incidents),
        "Items_Hash": identity.items_hash(items),
        "Incidents_Hash": identity.incidents_hash(incidents),
        "Code_Commit": code_commit(),
        "Sources_Active": sorted(spec.source_id for spec in sources.ALL_SOURCES if spec.active),
        "Baseline": False,
    }
    store.save_snapshot(payload)
    return payload


def repair_item_integrity(items: list[Item]) -> tuple[list[Item], dict[str, int]]:
    """Répare les IDs et élimine seulement les doublons de clé exacte."""
    groups: dict[tuple[str, str, str, str], list[Item]] = defaultdict(list)
    for item in items:
        groups[(item.Source_ID, item.Published_Date, item.Organisation_Key, item.URL)].append(item)

    repaired: list[Item] = []
    dropped = 0
    changed = 0
    for key in sorted(groups):
        candidates = groups[key]
        if len(candidates) > 1:
            dropped += len(candidates) - 1
        def quality(item: Item) -> tuple:
            values = item.to_row()
            populated = sum(bool(value) for name, value in values.items() if name != "Item_ID")
            return (-populated, tuple(values[name] for name in sorted(values)))
        item = sorted(candidates, key=quality)[0]
        expected = identity.item_id(
            item.Source_ID, item.Published_Date, item.Organisation_Key,
            item.URL, item.Source_Item_ID,
        )
        if item.Item_ID != expected:
            changed += 1
            item.Item_ID = expected
        repaired.append(item)
    return identity.sort_items(repaired), {"ids_repaired": changed, "duplicates_removed": dropped}


@dataclass
class RunContext:
    run_id: str
    as_of: str
    target_start: str
    target_end: str
    mode: str
    layers: list[str]
    method_id: str = config.METHOD_ID

    @property
    def window(self) -> Window:
        return Window(self.target_start, self.target_end)


def make_run_context(
    mode: str,
    as_of: str | None = None,
    target_start: str | None = None,
    layers: list[str] | None = None,
) -> RunContext:
    now = (
        dt.datetime.fromisoformat(as_of)
        if as_of
        else dt.datetime.now(dt.timezone(dt.timedelta(hours=4)))
    )
    as_of_iso = now.isoformat()
    end = now.date().isoformat()

    if target_start:
        start = target_start
    elif mode == MODE_MAJ:
        anchor = _last_run_as_of() or _snapshot_as_of()
        if anchor is None:
            raise ValueError(
                "Snapshot valide mais As_Of exploitable absent : MAJ impossible."
            )
        start = (anchor - dt.timedelta(days=config.MAJ_OVERLAP_DAYS)).isoformat()
    else:
        start = dt.date(now.year, 1, 1).isoformat()

    base_run_id = now.strftime("RUN-%Y%m%dT%H%M%S")
    existing_run_ids = {row.get("Run_ID", "") for row in store.load_run_log()}
    sequence = 1
    run_id = base_run_id
    while run_id in existing_run_ids:
        sequence += 1
        run_id = f"{base_run_id}-{sequence}"
    return RunContext(
        run_id=run_id,
        as_of=as_of_iso,
        target_start=start,
        target_end=end,
        mode=mode,
        layers=layers or config.LAYER_GROUPS["all"],
    )


def _last_run_as_of() -> dt.date | None:
    rows = store.load_run_log()
    if not rows:
        return None
    stamps = sorted(row.get("As_Of", "") for row in rows if row.get("As_Of"))
    if not stamps:
        return None
    try:
        return dt.datetime.fromisoformat(stamps[-1]).date()
    except ValueError:
        return None


def _snapshot_as_of() -> dt.date | None:
    value = store.load_snapshot().get("As_Of", "")
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value).date()
    except ValueError:
        return None


def entry_to_item(
    entry: RawEntry,
    spec: SourceSpec,
    as_of: str,
    known_orgs: dict[str, str],
    entity_index: dict,
    territories: dict[str, str] | None = None,
    reference: dict[str, enrichment.Enrichment] | None = None,
    sector_stats: dict | None = None,
) -> Item | None:
    """Convertit une entrée brute en item normalisé, ou `None` si hors périmètre."""
    territories = territories or {}

    if not entry.published:
        return None

    text = f"{entry.title} {entry.summary}"
    if spec.params.get("include_content"):
        text = f"{text} {entry.content}"

    scope_is_cyber = spec.default_threat or spec.params.get("scope_is_cyber")
    if not scope_is_cyber and not looks_cyber(text):
        return None

    if spec.source_id == "CYBERATTAQUE_ORG":
        if is_negated_incident(entry.title, entry.summary, entry.content):
            return None
        if is_obvious_multi(entry.title, entry.summary, entry.content):
            return None
        organisation = clean_organisation(entry.organisation) or organisation_from_cyberattaque_entry(entry, known_orgs)
    else:
        organisation = clean_organisation(entry.organisation) or organisation_from_title(entry.title)

    if not organisation and spec.params.get("title_is_organisation"):
        organisation = organisation_from_entry_title(entry.title)

    if not organisation and spec.source_id != "CYBERATTAQUE_ORG":
        organisation = find_known_entity(text, known_orgs)

    if (spec.source_id == "CYBERATTAQUE_ORG" or spec.params.get("require_victim")) and not organisation:
        return None
    if spec.params.get("require_victim") and not _local_title_names_a_victim(entry, organisation):
        return None

    sector_hint = ""
    if entry.entity:
        watched = entity_index.get(entry.entity)
        if watched is not None:
            sector_hint = watched.sector_hint

    threat = classify_threat(text, default=spec.default_threat)

    # Les secteurs structurés sont normalisés sans passer par les règles de
    # texte libre. Une catégorie source trop large reste volontairement Inconnu.
    sector = sector_policy.classify_source_sector(entry.sector)
    location = classify_location(given=entry.location)

    if sector_stats is not None and sector != config.SECTOR_UNKNOWN:
        sector_stats["resolved_native"] = sector_stats.get("resolved_native", 0) + 1
    sector_was_unknown = sector == config.SECTOR_UNKNOWN
    if sector_stats is not None and sector_was_unknown:
        sector_stats["initial_unknown"] = sector_stats.get("initial_unknown", 0) + 1

    sector, location = enrichment.enrich_unknowns(organisation, sector, location, reference or {})
    resolved_by_reference = sector_was_unknown and sector != config.SECTOR_UNKNOWN

    if sector_stats is not None and resolved_by_reference:
        sector_stats["resolved_reference"] = sector_stats.get("resolved_reference", 0) + 1

    # Trois preuves déterministes distinctes, jamais mélangées : hint structuré,
    # nom d'organisation avec vocabulaire nominatif strict, puis description
    # d'activité explicitement extraite. Le récit cyber complet n'est jamais
    # passé aux règles Sector.
    if sector == config.SECTOR_UNKNOWN and sector_hint:
        sector = sector_policy.classify_source_sector(sector_hint)
    if sector == config.SECTOR_UNKNOWN:
        sector = sector_policy.classify_sector_name(organisation)
    if sector == config.SECTOR_UNKNOWN:
        activity_description = extract_activity_description(text)
        if activity_description:
            sector = sector_policy.classify_sector_activity(activity_description)
    if (
        sector_stats is not None
        and sector_was_unknown
        and not resolved_by_reference
        and sector != config.SECTOR_UNKNOWN
    ):
        sector_stats["resolved_deterministic"] = sector_stats.get("resolved_deterministic", 0) + 1

    if location == config.LOC_INCONNU:
        # Stabilisation Location v0.7.32 : le défaut source reste différé pour
        # laisser un match entreprise exact fournir 974/976 en priorité.
        location = classify_location(
            text, organisation,
            entity=territories.get(searchable(organisation), ""),
        )

    key = organisation_key(organisation)

    return Item(
        Item_ID=identity.item_id(
            spec.source_id,
            entry.published,
            key,
            entry.url,
            entry.source_item_id,
        ),
        Source_ID=spec.source_id,
        Source_Item_ID=entry.source_item_id,
        Published_Date=entry.published,
        Event_Date=entry.event_date,
        Organisation_Raw=organisation,
        Organisation_Key=key,
        Threat_Raw=entry.threat,
        Threat=threat,
        Sector=sector,
        Location=location,
        Title=entry.title,
        URL=entry.url,
        Collected_As_Of=as_of,
    )



def _verify_native_ransomware_sector(
    item: Item,
    entry: RawEntry,
    spec: SourceSpec,
    ai_state: ai.AiRunState,
) -> None:
    """Corrige un secteur ransomware.live uniquement avec une preuve plus forte.

    Le secteur structuré de ransomware.live reste le fallback de couverture.
    En revanche, s'il contredit un registre exact validé ou une preuve de site
    officiel déjà acceptée, la preuve organisationnelle gagne. Une absence de
    match, une ambiguïté ou un NAF non mappable ne dégrade jamais le secteur
    source en ``Inconnu``.
    """
    if spec.source_id != "RANSOMWARE_LIVE":
        return
    if not entry.sector or item.Sector == config.SECTOR_UNKNOWN:
        return
    if not ai_state.org_enrichment.enabled:
        return

    native_sector = sector_policy.classify_source_sector(entry.sector)
    if native_sector == config.SECTOR_UNKNOWN or item.Sector != native_sector:
        return

    record = org_enrichment.resolve(
        item.Organisation_Key,
        item.Organisation_Raw,
        item.Collected_As_Of,
        ai_state.org_enrichment,
    )
    if record is None or record.Match_Status != org_enrichment.MATCHED:
        return

    candidate = record.Validated_Sector
    if not candidate and record.Activity_Label:
        candidate = org_enrichment.sector_for_activity_label(record.Activity_Label)
    if candidate and candidate != config.SECTOR_UNKNOWN and candidate != item.Sector:
        item.Sector = candidate


def _resolve_history_status(result: CollectResult, source_status: str, window: Window) -> tuple[str, str]:
    """Couverture historique réelle (§stabilisation pré-release), orthogonale
    à `Status`/`Coverage` : générique, ne dépend d'aucun `source_id` — ne
    devient `TRUNCATED` que si un collecteur a explicitement renseigné
    `oldest_available_date` (aujourd'hui seul `feed.py` le fait, via
    `feed_has_no_pagination`) et que celle-ci est postérieure au début de la
    fenêtre demandée malgré un `Status=OK`."""
    if not result.oldest_available_date:
        return status.HISTORY_UNKNOWN, ""
    if source_status != status.OK:
        return status.HISTORY_UNKNOWN, result.oldest_available_date
    if result.oldest_available_date > window.start:
        return status.HISTORY_TRUNCATED, result.oldest_available_date
    return status.HISTORY_COMPLETE, result.oldest_available_date


def run_source(
    client: HttpClient,
    spec: SourceSpec,
    context: RunContext,
    known_orgs: dict[str, str],
    entity_index: dict,
    territories: dict[str, str] | None = None,
    reference: dict[str, enrichment.Enrichment] | None = None,
    ai_state: ai.AiRunState | None = None,
    sector_stats: dict | None = None,
    fact_rows: list[dict] | None = None,
) -> tuple[status.SourceOutcome, list[Item], list[dict]]:
    outcome = status.SourceOutcome(source_id=spec.source_id, layer=spec.layer)

    if not spec.active:
        outcome.status = status.SKIPPED
        outcome.coverage = 0
        outcome.reason_code = status.REASON_SOURCE_INACTIVE
        return outcome, [], []

    if spec.layer not in context.layers:
        outcome.status = status.SKIPPED
        outcome.coverage = 0
        outcome.reason_code = status.REASON_LAYER_NOT_SCHEDULED
        return outcome, [], []

    started = time.monotonic()
    collector = get_collector(spec.collector)
    collect_started = time.monotonic()

    try:
        result = collector.collect(client, spec, context.window)
    except Exception as exc:
        outcome.collect_duration_seconds = round(time.monotonic() - collect_started, 3)
        outcome.status = status.FAIL
        outcome.coverage = 0
        outcome.reason_code = status.REASON_PARSE_ERROR
        outcome.comment = f"{type(exc).__name__}: {exc}"[:300]
        outcome.duration_seconds = round(time.monotonic() - started, 1)
        return outcome, [], []

    outcome.collect_duration_seconds = round(time.monotonic() - collect_started, 3)
    processing_started = time.monotonic()
    if ai_state is not None:
        org_state = ai_state.org_enrichment
        perf_before = {
            "org_registry_duration": org_state.duration_seconds,
            "org_registry_calls": org_state.calls_attempted,
            "official_duration": org_state.official_site_duration_seconds,
            "official_calls": org_state.official_site_attempted,
            "qual_llm_duration": ai_state.llm_duration_seconds,
            "qual_llm_calls": ai_state.calls_attempted,
            "qual_llm_cost": ai_state.estimated_cost_usd,
        }
    else:
        perf_before = {
            "org_registry_duration": 0.0, "org_registry_calls": 0,
            "official_duration": 0.0, "official_calls": 0,
            "qual_llm_duration": 0.0, "qual_llm_calls": 0, "qual_llm_cost": 0.0,
        }
    source_facts_before = source_facts_ai.runtime_stats()

    items: list[Item] = []
    requires_victim = bool(spec.params.get("require_victim"))
    articles_cyber = 0
    articles_rejected_no_victim = 0
    cyberattaque_rejected_negated = 0
    cyberattaque_rejected_multi = 0
    cyberattaque_rejected_no_victim = 0
    for entry in result.entries:
        if requires_victim and looks_cyber(entry.title, entry.summary, entry.content):
            articles_cyber += 1
        if spec.source_id == "CYBERATTAQUE_ORG" and is_negated_incident(entry.title, entry.summary, entry.content):
            cyberattaque_rejected_negated += 1
            continue
        if spec.source_id == "CYBERATTAQUE_ORG" and is_obvious_multi(entry.title, entry.summary, entry.content):
            cyberattaque_rejected_multi += 1
            continue
        item = entry_to_item(
            entry, spec, context.as_of, known_orgs, entity_index, territories, reference,
            sector_stats,
        )
        if item is not None:
            items.append(item)
            if ai_state is not None:
                _verify_native_ransomware_sector(item, entry, spec, ai_state)
                ai.qualify_item(item, entry, spec, ai_state)
            # Stabilisation Location v0.7.32 : hors pipeline IA, le défaut de
            # source reste le dernier recours après l'enrichissement potentiel.
            if (
                item.Location == config.LOC_INCONNU
                and spec.location_rule in config.LOCATIONS
                and spec.location_rule != config.LOC_INCONNU
            ):
                item.Location = spec.location_rule
            if fact_rows is not None:
                fact = source_facts.extract_source_fact(item, entry, spec)
                if fact is not None:
                    fact_rows.append(fact)
        elif requires_victim:
            articles_rejected_no_victim += 1
        elif spec.source_id == "CYBERATTAQUE_ORG":
            cyberattaque_rejected_no_victim += 1

    outcome.processing_duration_seconds = round(time.monotonic() - processing_started, 3)
    if ai_state is not None:
        org_state = ai_state.org_enrichment
        outcome.org_registry_duration_seconds = round(
            max(0.0, org_state.duration_seconds - perf_before["org_registry_duration"]), 3
        )
        outcome.org_registry_calls = max(0, org_state.calls_attempted - perf_before["org_registry_calls"])
        outcome.org_official_site_duration_seconds = round(
            max(0.0, org_state.official_site_duration_seconds - perf_before["official_duration"]), 3
        )
        outcome.org_official_site_calls = max(0, org_state.official_site_attempted - perf_before["official_calls"])
        outcome.qualification_llm_duration_seconds = round(
            max(0.0, ai_state.llm_duration_seconds - perf_before["qual_llm_duration"]), 3
        )
        outcome.qualification_llm_calls = max(0, ai_state.calls_attempted - perf_before["qual_llm_calls"])
        outcome.qualification_llm_cost_usd = round(
            max(0.0, ai_state.estimated_cost_usd - perf_before["qual_llm_cost"]), 6
        )
    source_facts_after = source_facts_ai.runtime_stats()
    outcome.source_facts_llm_duration_seconds = round(max(
        0.0,
        float(source_facts_after.get("total_duration_seconds", 0.0))
        - float(source_facts_before.get("total_duration_seconds", 0.0)),
    ), 3)
    outcome.source_facts_llm_calls = max(
        0,
        int(source_facts_after.get("calls_attempted", 0))
        - int(source_facts_before.get("calls_attempted", 0)),
    )
    outcome.source_facts_llm_cost_usd = round(max(
        0.0,
        float(source_facts_after.get("estimated_cost_usd", 0.0))
        - float(source_facts_before.get("estimated_cost_usd", 0.0)),
    ), 6)
    measured_external = (
        outcome.org_registry_duration_seconds
        + outcome.org_official_site_duration_seconds
        + outcome.qualification_llm_duration_seconds
        + outcome.source_facts_llm_duration_seconds
    )
    outcome.other_processing_duration_seconds = round(
        max(0.0, outcome.processing_duration_seconds - measured_external), 3
    )

    source_status, coverage = result.resolve()
    outcome.status = source_status
    outcome.coverage = coverage
    outcome.reason_code = result.reason_code
    outcome.history_status, outcome.oldest_available_date = _resolve_history_status(
        result, source_status, context.window
    )
    outcome.units_done = result.units_done
    outcome.units_expected = result.units_expected
    outcome.calls = result.calls
    outcome.items_seen = result.items_seen if result.items_seen is not None else len(result.entries)
    outcome.items_in_window = result.items_in_window if result.items_in_window is not None else len(result.entries)
    outcome.items_collected = len(items)
    outcome.access_method = result.access_method
    outcome.comment = result.comment
    if spec.params.get("local_media_metrics"):
        extra = (
            f"articles_cyber={articles_cyber}; victims_identified={len(items)}; "
            f"items_created={len(items)}; articles_rejected_no_victim={articles_rejected_no_victim}"
        )
        outcome.comment = f"{outcome.comment}; {extra}" if outcome.comment else extra
    if spec.source_id == "CYBERATTAQUE_ORG":
        extra = (
            f"victims_identified={len(items)}; articles_rejected_no_victim={cyberattaque_rejected_no_victim}; "
            f"articles_rejected_negated={cyberattaque_rejected_negated}; articles_rejected_multi={cyberattaque_rejected_multi}"
        )
        outcome.comment = f"{outcome.comment}; {extra}" if outcome.comment else extra
    outcome.duration_seconds = round(time.monotonic() - started, 1)
    if items:
        latest_item = max(items, key=lambda i: (i.Published_Date, i.Item_ID))
        outcome.latest_item_date = latest_item.Published_Date
        outcome.latest_item_org = latest_item.Organisation_Raw
    else:
        outcome.latest_item_date = ""
        outcome.latest_item_org = ""

    watch_rows = []
    for row in result.watch_rows:
        row["source_id"] = spec.source_id
        watch_rows.append(row)

    return outcome, items, watch_rows


def build_entity_watch(
    watch_rows: list[dict],
    incidents: list[Incident],
    as_of: str,
    previous: list[dict],
) -> list[dict]:
    from .normalize import searchable

    previous_by_entity = {row.get("Entity", ""): row for row in previous}
    queried = {row["entity"]: row for row in watch_rows}

    last_incident: dict[str, Incident] = {}
    for incident in incidents:
        key = searchable(incident.Organisation)
        current = last_incident.get(key)
        if current is None or incident.Date > current.Date:
            last_incident[key] = incident

    rows = []
    for entity in watchlists.ALL_ENTITIES:
        previous_row = previous_by_entity.get(entity.name, {})
        result = queried.get(entity.name)

        if result:
            last_queried = as_of
            query_status = result["status"]
            items_found = result["items_found"]
        else:
            last_queried = previous_row.get("Last_Queried", "")
            query_status = previous_row.get("Query_Status", status.SKIPPED)
            items_found = previous_row.get("Items_Found", 0)

        incident = last_incident.get(searchable(entity.name))
        for alias in entity.aliases:
            if incident is not None:
                break
            incident = last_incident.get(searchable(alias))

        rows.append({
            "Entity": entity.name,
            "Entity_Key": organisation_key(entity.name),
            "Territory": entity.territory,
            "Type": entity.kind,
            "Sector_Hint": entity.sector_hint,
            "Last_Queried": last_queried,
            "Query_Status": query_status,
            "Items_Found": items_found,
            "Last_Incident_Date": incident.Date if incident else "",
            "Last_Incident_ID": incident.Incident_ID if incident else "",
        })

    return sorted(rows, key=lambda row: (row["Territory"], row["Type"], row["Entity"]))


def pre_export_checks(
    items: list[Item],
    incidents: list[Incident],
    outcomes: list[status.SourceOutcome],
    expected_source_ids: set[str] | None = None,
) -> list[str]:
    problems: list[str] = []

    item_ids = [i.Item_ID for i in items]
    if len(item_ids) != len(set(item_ids)):
        problems.append("Item_ID dupliqué détecté dans ITEMS")

    natural_keys: dict[tuple[str, str, str, str], list[Item]] = defaultdict(list)
    for item in items:
        expected = identity.item_id(
            item.Source_ID,
            item.Published_Date,
            item.Organisation_Key,
            item.URL,
            item.Source_Item_ID,
        )
        if item.Item_ID != expected:
            problems.append(f"Item_ID invalide : {item.Item_ID}")
        natural_keys[(item.Source_ID, item.Published_Date, item.Organisation_Key, item.URL)].append(item)

    duplicate_keys = {key: entries for key, entries in natural_keys.items() if len(entries) > 1}
    for key, entries in duplicate_keys.items():
        problems.append("Clé naturelle dupliquée : " + " | ".join(key) + f" ({len(entries)} items)")

    incident_ids = [i.Incident_ID for i in incidents]
    if len(incident_ids) != len(set(incident_ids)):
        problems.append("Incident_ID dupliqué détecté dans INCIDENTS")

    for incident in incidents:
        if not incident.Sources:
            problems.append(f"Incident sans source : {incident.Incident_ID}")

    duplicated_org_dates = {
        (item.Organisation_Key, item.best_date)
        for entries in duplicate_keys.values()
        for item in entries
    }
    for incident in incidents:
        if ((organisation_key(incident.Organisation), incident.Date) in duplicated_org_dates
                and incident.Items_Count > 1):
            problems.append(f"Incident potentiellement gonflé : {incident.Incident_ID}")
            break

    seen_sources = {o.source_id for o in outcomes}
    expected_source_ids = expected_source_ids or {spec.source_id for spec in sources.ALL_SOURCES if spec.active}
    for spec in sources.ALL_SOURCES:
        if spec.source_id in expected_source_ids and spec.source_id not in seen_sources:
            problems.append(f"Source active sans ligne RUN_SOURCES : {spec.source_id}")

    for outcome in outcomes:
        if outcome.status == status.OK and outcome.coverage < 100:
            problems.append(f"Statut OK sans couverture complète : {outcome.source_id}")

    return problems


@dataclass
class RunReport:
    context: RunContext
    outcomes: list[status.SourceOutcome] = field(default_factory=list)
    items: list[Item] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    new_items: int = 0
    new_incidents: int = 0
    items_hash: str = ""
    incidents_hash: str = ""
    overall: str = status.OK
    problems: list[str] = field(default_factory=list)
    duration: float = 0.0
    requests: int = 0
    ai_usage: dict = field(default_factory=dict)
    source_facts: list[dict] = field(default_factory=list)
    qualification_provenance: list[dict] = field(default_factory=list)
    incident_id_registry: list[dict] = field(default_factory=list)


def outcome_blocks_snapshot(outcome: status.SourceOutcome, spec: SourceSpec) -> bool:
    if outcome.status == status.OK:
        return False
    return not (
        outcome.status == status.PARTIAL
        and spec.params.get("publication_contract") == "live_watch"
    )


def execute(
    context: RunContext,
    offline: bool = False,
    persist: bool = True,
) -> RunReport:
    started = time.monotonic()
    report = RunReport(context=context)

    previous_incidents = store.load_incidents()
    previous_ids = {i.Incident_ID for i in previous_incidents}

    snapshot_items = store.load_items()
    existing_items = [] if context.mode == MODE_CREATE else snapshot_items
    existing_item_ids = {item.Item_ID for item in existing_items}

    if offline:
        report.items = existing_items
    else:
        run_budget = Budget(config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN, "run")
        client = HttpClient(run_budget=run_budget)
        known_orgs = watchlists.known_organisations()
        entity_index = watchlists.entity_index()
        territories = watchlists.entity_territories()
        reference = enrichment.load_reference()
        ai_state = ai.start_run()
        sector_stats = {"initial_unknown": 0, "resolved_reference": 0, "resolved_deterministic": 0}

        collected: list[Item] = []
        watch_rows: list[dict] = []
        new_fact_rows: list[dict] = []

        for spec in sources.active_sources(context.layers):
            outcome, items, rows = run_source(
                client, spec, context, known_orgs, entity_index, territories, reference, ai_state,
                sector_stats, new_fact_rows,
            )
            report.outcomes.append(outcome)
            collected.extend(items)
            watch_rows.extend(rows)
            print(
                f"  {outcome.source_id:28} {outcome.status:8} "
                f"{outcome.coverage:3}%  items={outcome.items_collected:4} "
                f"calls={outcome.calls:4}  {outcome.reason_code}"
            )
            print(
                "    perf "
                f"collect={outcome.collect_duration_seconds:.1f}s "
                f"process={outcome.processing_duration_seconds:.1f}s "
                f"registry={outcome.org_registry_duration_seconds:.1f}s/{outcome.org_registry_calls} "
                f"official={outcome.org_official_site_duration_seconds:.1f}s/{outcome.org_official_site_calls} "
                f"q-llm={outcome.qualification_llm_duration_seconds:.1f}s/{outcome.qualification_llm_calls} "
                f"sf-llm={outcome.source_facts_llm_duration_seconds:.1f}s/{outcome.source_facts_llm_calls} "
                f"other={outcome.other_processing_duration_seconds:.1f}s"
            )

        replacement_source_ids = {
            spec.source_id for spec in sources.active_sources(context.layers)
            if spec.params.get("replace_snapshot")
        }
        merge_base = [item for item in existing_items if item.Source_ID not in replacement_source_ids]
        merged, _ = merge_items(merge_base, collected)
        new_count = sum(item.Item_ID not in existing_item_ids for item in collected)
        for outcome in report.outcomes:
            outcome.new_items = sum(
                item.Source_ID == outcome.source_id and item.Item_ID not in existing_item_ids
                for item in collected
            )
        report.items = merged
        report.new_items = new_count

        existing_facts = [] if context.mode == MODE_CREATE else store.load_source_facts()
        facts_base = [row for row in existing_facts if row.get("Source_ID") not in replacement_source_ids]
        report.source_facts = source_facts.merge_source_facts(facts_base, new_fact_rows)
        report.requests = run_budget.requests_made
        report.ai_usage = ai.finish_run(ai_state, context.run_id, context.as_of, context.mode, sector_stats)

    qualified = qualify(report.items)
    report.items = qualified.items
    report.incidents = qualified.incidents
    report.qualification_provenance = qualified.provenance
    report.incident_id_registry = qualified.incident_id_registry
    report.new_incidents = len([i for i in report.incidents if i.Incident_ID not in previous_ids])
    report.items_hash = qualified.items_hash
    report.incidents_hash = qualified.incidents_hash
    report.overall = status.OK if offline else (
        status.OK if report.outcomes and not any(
            outcome_blocks_snapshot(outcome, sources.by_id(outcome.source_id))
            for outcome in report.outcomes
        ) else status.BROKEN
    )
    selected_source_ids = {spec.source_id for spec in sources.active_sources(context.layers)}
    report.problems = pre_export_checks(report.items, report.incidents, report.outcomes, selected_source_ids)
    report.problems.extend(incident_identity.validate_registry(
        report.incident_id_registry, report.items, report.incidents
    ))
    if offline:
        report.problems = [p for p in report.problems if "RUN_SOURCES" not in p]
    if report.problems:
        report.overall = status.BROKEN
    report.duration = round(time.monotonic() - started, 1)

    if persist:
        _persist(
            report,
            watch_rows if not offline else [],
            persist_snapshot=offline or (report.overall == status.OK and not report.problems),
        )
    return report


def _persist(
    report: RunReport,
    watch_rows: list[dict],
    *,
    persist_snapshot: bool,
) -> None:
    context = report.context

    store.save_sources(sources.to_rows())

    if report.outcomes:
        store.append_run_sources([
            {
                "Run_ID": context.run_id,
                "As_Of": context.as_of,
                "Source_ID": o.source_id,
                "Layer": o.layer,
                "Status": o.status,
                "Coverage": o.coverage,
                "Reason_Code": o.reason_code,
                "Reason": o.reason,
                "Calls": o.calls,
                "Units_Done": o.units_done,
                "Units_Expected": o.units_expected,
                "Items_seen": o.items_seen,
                "Items_in_window": o.items_in_window,
                "Items_collected": o.items_collected,
                "New_items": o.new_items,
                "Latest_item_date": o.latest_item_date,
                "Latest_Item_Org": o.latest_item_org,
                "Access_Method": o.access_method,
                "Duration_s": o.duration_seconds,
                "Comment": o.comment,
                "History_Status": o.history_status,
                "Oldest_Available_Date": o.oldest_available_date,
                "Collect_Duration_s": o.collect_duration_seconds,
                "Processing_Duration_s": o.processing_duration_seconds,
                "Org_Registry_Duration_s": o.org_registry_duration_seconds,
                "Org_Registry_Calls": o.org_registry_calls,
                "Org_Official_Site_Duration_s": o.org_official_site_duration_seconds,
                "Org_Official_Site_Calls": o.org_official_site_calls,
                "Qualification_LLM_Duration_s": o.qualification_llm_duration_seconds,
                "Qualification_LLM_Calls": o.qualification_llm_calls,
                "Qualification_LLM_Cost_USD": o.qualification_llm_cost_usd,
                "SourceFacts_LLM_Duration_s": o.source_facts_llm_duration_seconds,
                "SourceFacts_LLM_Calls": o.source_facts_llm_calls,
                "SourceFacts_LLM_Cost_USD": o.source_facts_llm_cost_usd,
                "Other_Processing_Duration_s": o.other_processing_duration_seconds,
            }
            for o in report.outcomes
        ])

        if persist_snapshot:
            store.save_entity_watch(
                build_entity_watch(watch_rows, report.incidents, context.as_of, store.load_entity_watch())
            )

    if not report.outcomes:
        if persist_snapshot:
            store.save_items(report.items)
            store.save_incidents(report.incidents)
            store.save_incident_id_registry(report.incident_id_registry)
            save_snapshot_provenance(
                store.load_items(), store.load_incidents(), operation="REPLAY",
                run_id=context.run_id, mode=context.mode, as_of=context.as_of,
                target_start=context.target_start, target_end=context.target_end,
            )
        return

    counts = status.status_counts(report.outcomes)
    store.append_run_log({
        "Run_ID": context.run_id,
        "As_Of": context.as_of,
        "Mode": context.mode,
        "Method_ID": context.method_id,
        "Target_Start": context.target_start,
        "Target_End": context.target_end,
        "Layers": ",".join(context.layers),
        "Items_Count": len(report.items),
        "Incidents_Count": len(report.incidents),
        "New_Items": report.new_items,
        "New_Incidents": report.new_incidents,
        "Source_Status": "OK" if report.overall == "OK" else status.FAIL,
        "Items_seen": sum(o.items_seen for o in report.outcomes),
        "Items_in_window": sum(o.items_in_window for o in report.outcomes),
        "Sources_OK": counts.get(status.OK, 0),
        "Sources_PARTIAL": counts.get(status.PARTIAL, 0),
        "Sources_FAIL": counts.get(status.FAIL, 0),
        "Sources_SKIPPED": counts.get(status.SKIPPED, 0),
        "Items_Hash": report.items_hash,
        "Incidents_Hash": report.incidents_hash,
        "Overall_Status": report.overall,
        "Duration_s": report.duration,
        "Requests": report.requests,
        "Notes": " ; ".join(report.problems),
    })
    if report.ai_usage:
        store.append_ai_usage(report.ai_usage)
    if persist_snapshot:
        store.save_items(report.items)
        store.save_incidents(report.incidents)
        store.save_incident_id_registry(report.incident_id_registry)
        store.save_source_facts(report.source_facts)
        store.save_qualification_provenance(report.qualification_provenance)
        save_snapshot_provenance(
            store.load_items(), store.load_incidents(), operation=context.mode,
            run_id=context.run_id, mode=context.mode, as_of=context.as_of,
            target_start=context.target_start, target_end=context.target_end,
        )
