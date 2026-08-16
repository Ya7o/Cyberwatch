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

from . import ai, config, enrichment, identity, source_facts, sources, status, store, watchlists
from .qualification import qualify
from .collectors import get_collector
from .collectors.cyberattaque_org import (
    is_negated_incident,
    is_obvious_multi,
    organisation_from_cyberattaque_entry,
)
from .collectors.base import RawEntry, SourceSpec, Window
from .dedup import build_incidents, merge_items
from .http import Budget, HttpClient
from .model import Incident, Item
from .normalize import (
    classify_location,
    searchable,
    classify_sector,
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
    """Répare les IDs et élimine seulement les doublons de clé exacte.

    Cette migration locale ne rapproche jamais deux organisations différentes.
    Pour une clé naturelle dupliquée, elle conserve la ligne la plus renseignée
    puis applique un ordre canonique pour briser les égalités.
    """
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
    """Paramètres figés au début du run (§6)."""

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
    """Fige les paramètres du run.

    `CREATE` sans période démarre au 1er janvier de l'année de `AS_OF` (§6).
    `MAJ` rejoue volontairement les 21 derniers jours depuis le dernier run ou,
    à défaut, depuis la provenance du snapshot. Ce chevauchement permet de
    récupérer ajouts tardifs et corrections.
    """
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
    """Date du dernier run enregistré, ou `None` si la base est neuve."""
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
    """Ancre une MAJ sur la provenance si le journal de run est absent."""
    value = store.load_snapshot().get("As_Of", "")
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value).date()
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Normalisation d'une entrée brute en item
# --------------------------------------------------------------------------


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
    """Convertit une entrée brute en item normalisé, ou `None` si hors périmètre.

    Un contenu sans aucun marqueur cyber n'entre pas dans la base, même
    lorsqu'il provient d'une rubrique cyber : c'est le garde-fou qui empêche la
    rubrique « Numérique » d'un média local de tout déverser dans `ITEMS`.
    """
    territories = territories or {}

    if not entry.published:
        return None

    text = f"{entry.title} {entry.summary}"
    if spec.params.get("include_content"):
        text = f"{text} {entry.content}"

    # Le garde-fou de vocabulaire protège des rubriques généralistes, où tout
    # n'est pas cyber. Il ne s'applique pas aux sources dont le périmètre entier
    # l'est déjà — liste de fuites, de victimes de rançongiciel, ou catégorie
    # « attaque » d'un site spécialisé : leur périmètre fait foi, et l'exiger en
    # plus écarterait des titres pourtant sans ambiguïté (« les données de 1 000
    # employés diffusées publiquement »).
    scope_is_cyber = spec.default_threat or spec.params.get("scope_is_cyber")
    if not scope_is_cyber and not looks_cyber(text):
        return None

    # Organisation : fournie par la source, sinon lue dans le titre, sinon
    # reconnue parmi les entités surveillées. Jamais devinée.
    if spec.source_id == "CYBERATTAQUE_ORG":
        if is_negated_incident(entry.title, entry.summary, entry.content):
            return None
        if is_obvious_multi(entry.title, entry.summary, entry.content):
            return None
        organisation = clean_organisation(entry.organisation) or organisation_from_cyberattaque_entry(entry, known_orgs)
    else:
        organisation = clean_organisation(entry.organisation) or organisation_from_title(
            entry.title
        )

    # Certaines sources publient l'organisation comme titre de l'entrée : les
    # chronologies de fuites et les listes de victimes nomment chaque entrée
    # d'après l'organisation touchée (§13.1, §13.2). La règle est déclarée par
    # la source, elle n'est pas déduite de la forme du titre.
    if not organisation and spec.params.get("title_is_organisation"):
        organisation = organisation_from_entry_title(entry.title)

    # Cyberattaque.org a son propre contrat conservateur : DIRECT ou resolver
    # temporel unique, sinon NO_VICTIM. Le fallback générique chercherait une
    # simple mention d'entité et contournerait ces garde-fous.
    if not organisation and spec.source_id != "CYBERATTAQUE_ORG":
        organisation = find_known_entity(text, known_orgs)


    # Les sources qui exigent une victime ne matérialisent que les entrées
    # dont la victime est déterminée sans heuristique variable.
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

    # Le secteur est celui de la victime (§9). Le nom de l'organisation est donc
    # examiné avant le corps de l'article : celui-ci décrit l'incident, pas le
    # métier de la victime, et un simple mot y suffirait à la reclasser à tort.
    # Lorsque la source nomme ses entrées d'après l'organisation, le corps n'est
    # qu'une description de la fuite : on ne s'y rabat pas du tout.
    # Les champs structurés de la source passent toujours en premier. Le
    # référentiel dédié vient ensuite ; les règles et défauts existants ne sont
    # consultés qu'en dernier recours.
    sector = classify_sector(given=entry.sector)
    location = classify_location(given=entry.location)

    # Pipeline Secteur (§12 METHODOLOGY.md) : chaque étape déterministe qui
    # résout Sector depuis Inconnu s'instrumente ici, avant tout appel IA.
    if sector_stats is not None and sector != config.SECTOR_UNKNOWN:
        sector_stats["resolved_native"] = sector_stats.get("resolved_native", 0) + 1
    sector_was_unknown = sector == config.SECTOR_UNKNOWN
    if sector_stats is not None and sector_was_unknown:
        sector_stats["initial_unknown"] = sector_stats.get("initial_unknown", 0) + 1

    sector, location = enrichment.enrich_unknowns(organisation, sector, location, reference or {})

    if sector_stats is not None and sector_was_unknown and sector != config.SECTOR_UNKNOWN:
        sector_stats["resolved_reference"] = sector_stats.get("resolved_reference", 0) + 1

    # Le fallback déterministe ne scanne plus jamais l'article complet
    # (§12 METHODOLOGY.md) : un mot isolé du récit d'incident ("à ce stade",
    # "site web piraté"...) ne doit jamais valoir preuve d'activité. Seule une
    # formulation métier étroitement extraite (`extract_activity_description`)
    # accompagne l'organisation. VEILLE_LLM garde son comportement historique
    # (source déjà structurée, cf. §13) : `entry.sector` la résout presque
    # toujours en amont, ce chemin n'est qu'un filet de sécurité inchangé.
    if spec.source_id == "VEILLE_LLM":
        sector_texts = (organisation, text)
    else:
        activity_description = extract_activity_description(text)
        sector_texts = (organisation, activity_description) if activity_description else (organisation,)
    if sector == config.SECTOR_UNKNOWN:
        sector = classify_sector(*sector_texts, given=sector_hint)
        if sector_stats is not None and sector != config.SECTOR_UNKNOWN:
            sector_stats["resolved_deterministic"] = sector_stats.get("resolved_deterministic", 0) + 1
    if location == config.LOC_INCONNU:
        location = classify_location(
            text, organisation,
            entity=territories.get(searchable(organisation), ""),
            default=spec.location_rule,
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


# --------------------------------------------------------------------------
# Exécution d'une source
# --------------------------------------------------------------------------


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
    """Exécute une source et rend son compte rendu, ses items et sa veille."""
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

    try:
        result = collector.collect(client, spec, context.window)
    except Exception as exc:  # aucune source ne doit interrompre le run
        outcome.status = status.FAIL
        outcome.coverage = 0
        outcome.reason_code = status.REASON_PARSE_ERROR
        outcome.comment = f"{type(exc).__name__}: {exc}"[:300]
        outcome.duration_seconds = round(time.monotonic() - started, 1)
        return outcome, [], []

    items: list[Item] = []
    requires_victim = bool(spec.params.get("require_victim"))
    articles_cyber = 0
    articles_rejected_no_victim = 0
    cyberattaque_rejected_negated = 0
    cyberattaque_rejected_multi = 0
    cyberattaque_rejected_no_victim = 0
    for entry in result.entries:
        if requires_victim and looks_cyber(
            entry.title, entry.summary, entry.content
        ):
            articles_cyber += 1
        if spec.source_id == "CYBERATTAQUE_ORG" and is_negated_incident(
            entry.title, entry.summary, entry.content
        ):
            cyberattaque_rejected_negated += 1
            continue
        if spec.source_id == "CYBERATTAQUE_ORG" and is_obvious_multi(
            entry.title, entry.summary, entry.content
        ):
            cyberattaque_rejected_multi += 1
            continue
        item = entry_to_item(
            entry, spec, context.as_of, known_orgs, entity_index, territories, reference,
            sector_stats,
        )
        if item is not None:
            items.append(item)
            if ai_state is not None:
                ai.qualify_item(item, entry, spec, ai_state)
            if fact_rows is not None:
                fact = source_facts.extract_source_fact(item, entry, spec)
                if fact is not None:
                    fact_rows.append(fact)
        elif requires_victim:
            articles_rejected_no_victim += 1
        elif spec.source_id == "CYBERATTAQUE_ORG":
            cyberattaque_rejected_no_victim += 1

    source_status, coverage = result.resolve()
    outcome.status = source_status
    outcome.coverage = coverage
    outcome.reason_code = result.reason_code
    outcome.units_done = result.units_done
    outcome.units_expected = result.units_expected
    outcome.calls = result.calls
    outcome.items_seen = result.items_seen if result.items_seen is not None else len(result.entries)
    outcome.items_in_window = (
        result.items_in_window
        if result.items_in_window is not None
        else len(result.entries)
    )
    outcome.items_collected = len(items)
    outcome.access_method = result.access_method
    outcome.comment = result.comment
    if spec.params.get("local_media_metrics"):
        extra = (
            f"articles_cyber={articles_cyber}; "
            f"victims_identified={len(items)}; "
            f"items_created={len(items)}; "
            f"articles_rejected_no_victim={articles_rejected_no_victim}"
        )
        outcome.comment = f"{outcome.comment}; {extra}" if outcome.comment else extra
    if spec.source_id == "CYBERATTAQUE_ORG":
        extra = (
            f"victims_identified={len(items)}; "
            f"articles_rejected_no_victim={cyberattaque_rejected_no_victim}; "
            f"articles_rejected_negated={cyberattaque_rejected_negated}; "
            f"articles_rejected_multi={cyberattaque_rejected_multi}"
        )
        outcome.comment = f"{outcome.comment}; {extra}" if outcome.comment else extra
    outcome.duration_seconds = round(time.monotonic() - started, 1)
    # Tri par (date, Item_ID) : déterministe même en cas d'égalité de date,
    # généralisé à toutes les sources (auparavant réservé à BonjourLaFuite,
    # qui le déduisait d'un texte libre dans `Comment`).
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


# --------------------------------------------------------------------------
# État de veille par entité
# --------------------------------------------------------------------------


def build_entity_watch(
    watch_rows: list[dict],
    incidents: list[Incident],
    as_of: str,
    previous: list[dict],
) -> list[dict]:
    """Construit `ENTITY_WATCH` : une ligne par entité sous surveillance.

    Les entités non interrogées lors de ce run conservent leur état précédent,
    de sorte que le tableau du dashboard reste complet et montre explicitement
    la date de dernière interrogation de chacune.
    """
    from .normalize import searchable

    previous_by_entity = {row.get("Entity", ""): row for row in previous}
    queried = {row["entity"]: row for row in watch_rows}

    # Dernier incident connu par organisation normalisée.
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

        rows.append(
            {
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
            }
        )

    return sorted(rows, key=lambda row: (row["Territory"], row["Type"], row["Entity"]))


# --------------------------------------------------------------------------
# Contrôles avant export (§29)
# --------------------------------------------------------------------------


def pre_export_checks(
    items: list[Item],
    incidents: list[Incident],
    outcomes: list[status.SourceOutcome],
    expected_source_ids: set[str] | None = None,
) -> list[str]:
    """Contrôles du §29. Renvoie la liste des anomalies détectées."""
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

    duplicate_keys = {
        key: entries for key, entries in natural_keys.items()
        if len(entries) > 1
    }
    for key, entries in duplicate_keys.items():
        problems.append(
            "Clé naturelle dupliquée : " + " | ".join(key)
            + f" ({len(entries)} items)"
        )

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
        if (
            (organisation_key(incident.Organisation), incident.Date) in duplicated_org_dates
            and incident.Items_Count > 1
        ):
            # Le contrôle de clé naturelle ci-dessus est la preuve primaire ;
            # cet avertissement rend visible l'impact potentiel dans INCIDENTS.
            problems.append(f"Incident potentiellement gonflé : {incident.Incident_ID}")
            break

    seen_sources = {o.source_id for o in outcomes}
    expected_source_ids = expected_source_ids or {
        spec.source_id for spec in sources.ALL_SOURCES if spec.active
    }
    for spec in sources.ALL_SOURCES:
        if spec.source_id in expected_source_ids and spec.source_id not in seen_sources:
            problems.append(f"Source active sans ligne RUN_SOURCES : {spec.source_id}")

    for outcome in outcomes:
        if outcome.status == status.OK and outcome.coverage < 100:
            problems.append(
                f"Statut OK sans couverture complète : {outcome.source_id}"
            )

    return problems


# --------------------------------------------------------------------------
# Run complet
# --------------------------------------------------------------------------


@dataclass
class RunReport:
    """Résultat d'un run, destiné à l'affichage et aux journaux."""

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
    #: Faits source (§13 METHODOLOGY.md) : jamais peuplé pour REPLAY
    #: (branche `offline`), jamais inclus dans un hash canonique.
    source_facts: list[dict] = field(default_factory=list)


def outcome_blocks_snapshot(outcome: status.SourceOutcome, spec: SourceSpec) -> bool:
    """Indique si le contrat de source interdit la publication du snapshot.

    Le contrat par défaut reste historique et strict : seul ``OK`` permet de
    publier. Une source explicitement déclarée ``live_watch`` peut rester
    ``PARTIAL`` lorsque son RSS permet la veille courante sans fournir
    l'historique complet. Son état reste visible dans RUN_SOURCES et le
    dashboard ; il n'est jamais transformé en ``OK``.
    """
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
    """Exécute un run complet et écrit la base.

    `offline=True` correspond au mode `REPLAY` (§26) : aucun accès Web, on
    reconstruit `INCIDENTS` à partir du snapshot `ITEMS` existant.
    """
    started = time.monotonic()
    report = RunReport(context=context)

    previous_incidents = store.load_incidents()
    previous_ids = {i.Incident_ID for i in previous_incidents}

    # `CREATE` construit la base **depuis zéro** (§24) : le snapshot `ITEMS`
    # précédent n'est pas repris. C'est ce qui permet de repartir proprement
    # après une évolution des règles de normalisation, laquelle change les
    # `Item_ID` et laisserait sinon cohabiter chaque item avec sa version
    # périmée. `MAJ` conserve au contraire le stock et n'y ajoute que le
    # nouveau (§25).
    snapshot_items = store.load_items()
    existing_items = [] if context.mode == MODE_CREATE else snapshot_items
    existing_item_ids = {item.Item_ID for item in existing_items}

    if offline:
        report.items = existing_items
    else:
        run_budget = Budget(
            config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN, "run"
        )
        client = HttpClient(run_budget=run_budget)
        known_orgs = watchlists.known_organisations()
        entity_index = watchlists.entity_index()
        territories = watchlists.entity_territories()
        reference = enrichment.load_reference()
        # CREATE ne peut jamais consulter des ITEMS éventuellement présents sur
        # disque : son résultat doit être identique sur base vide ou non.

        # Filet de rattrapage LLM (§ qualification IA) : uniquement pour une
        # collecte réelle, jamais pour REPLAY (branche `offline`, jamais
        # atteinte ici) ni pour diagnose/probe (qui appellent `run_source`
        # sans `ai_state`, resté à `None` par défaut).
        ai_state = ai.start_run()
        sector_stats = {"initial_unknown": 0, "resolved_reference": 0, "resolved_deterministic": 0}

        collected: list[Item] = []
        watch_rows: list[dict] = []
        new_fact_rows: list[dict] = []

        # Exécuter uniquement les sources actives des couches demandées.
        for spec in sources.active_sources(context.layers):
            outcome, items, rows = run_source(
                client, spec, context, known_orgs, entity_index, territories, reference, ai_state,
                sector_stats, new_fact_rows,
            )
            report.outcomes.append(outcome)
            collected.extend(items)
            watch_rows.extend(rows)
            # Écriture immédiate du compte rendu, comme l'exige le §24.7.
            print(
                f"  {outcome.source_id:28} {outcome.status:8} "
                f"{outcome.coverage:3}%  items={outcome.items_collected:4} "
                f"calls={outcome.calls:4}  {outcome.reason_code}"
            )

        replacement_source_ids = {
            spec.source_id for spec in sources.active_sources(context.layers)
            if spec.params.get("replace_snapshot")
        }
        merge_base = [
            item for item in existing_items
            if item.Source_ID not in replacement_source_ids
        ]
        merged, _ = merge_items(merge_base, collected)
        new_count = sum(item.Item_ID not in existing_item_ids for item in collected)
        for outcome in report.outcomes:
            outcome.new_items = sum(
                item.Source_ID == outcome.source_id and item.Item_ID not in existing_item_ids
                for item in collected
            )
        report.items = merged
        report.new_items = new_count

        # Même filtre replace_snapshot que pour les items ci-dessus (VEILLE_LLM) :
        # CREATE repart de zéro (§13 METHODOLOGY.md), MAJ conserve les facts
        # historiques et remplace uniquement par Item_ID recollecté.
        existing_facts = [] if context.mode == MODE_CREATE else store.load_source_facts()
        facts_base = [
            row for row in existing_facts
            if row.get("Source_ID") not in replacement_source_ids
        ]
        report.source_facts = source_facts.merge_source_facts(facts_base, new_fact_rows)
        report.requests = run_budget.requests_made
        report.ai_usage = ai.finish_run(
            ai_state, context.run_id, context.as_of, context.mode, sector_stats
        )

    # All producing paths converge here: no workflow may add a business
    # transformation after this point.
    qualified = qualify(report.items)
    report.items = qualified.items
    report.incidents = qualified.incidents
    report.new_incidents = len(
        [i for i in report.incidents if i.Incident_ID not in previous_ids]
    )
    report.items_hash = qualified.items_hash
    report.incidents_hash = qualified.incidents_hash
    # Le contrat historique est strict. Une veille RSS explicitement déclarée
    # ``live_watch`` peut en revanche être PARTIAL sans empêcher le snapshot :
    # le dashboard l'expose alors comme couverture incomplète.
    report.overall = status.OK if offline else (
        status.OK if report.outcomes and not any(
            outcome_blocks_snapshot(outcome, sources.by_id(outcome.source_id))
            for outcome in report.outcomes
        ) else status.BROKEN
    )
    selected_source_ids = {
        spec.source_id for spec in sources.active_sources(context.layers)
    }
    report.problems = pre_export_checks(
        report.items, report.incidents, report.outcomes, selected_source_ids
    )
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
    """Écrit la base, les journaux et l'état de veille."""
    context = report.context

    store.save_sources(sources.to_rows())

    if report.outcomes:
        store.append_run_sources(
            [
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
                }
                for o in report.outcomes
            ]
        )

        if persist_snapshot:
            store.save_entity_watch(
                build_entity_watch(
                    watch_rows,
                    report.incidents,
                    context.as_of,
                    store.load_entity_watch(),
                )
            )

    # REPLAY est une transformation locale : il ne constitue pas une collecte
    # et ne doit donc pas remplacer l'état OK/FAIL de la dernière collecte.
    if not report.outcomes:
        if persist_snapshot:
            store.save_items(report.items)
            store.save_incidents(report.incidents)
            save_snapshot_provenance(
                store.load_items(), store.load_incidents(), operation="REPLAY",
                run_id=context.run_id, mode=context.mode, as_of=context.as_of,
                target_start=context.target_start, target_end=context.target_end,
            )
        return

    counts = status.status_counts(report.outcomes)
    store.append_run_log(
        {
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
        }
    )
    if report.ai_usage:
        store.append_ai_usage(report.ai_usage)
    if persist_snapshot:
        store.save_items(report.items)
        store.save_incidents(report.incidents)
        # Jeu auxiliaire (§13 METHODOLOGY.md) : jamais écrit par REPLAY (branche
        # `not report.outcomes` ci-dessus), jamais inclus dans un hash canonique.
        store.save_source_facts(report.source_facts)
        save_snapshot_provenance(
            store.load_items(), store.load_incidents(), operation=context.mode,
            run_id=context.run_id, mode=context.mode, as_of=context.as_of,
            target_start=context.target_start, target_end=context.target_end,
        )
