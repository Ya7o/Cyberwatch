"""Runner : normalisation des entrées, veille par entité, contrôles du §29."""

import datetime as dt

import pytest

from cyberwatch import config, status, watchlists
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.dedup import build_incidents
from cyberwatch.runner import (
    MODE_CREATE,
    build_entity_watch,
    entry_to_item,
    make_run_context,
    pre_export_checks,
)

SPEC = SourceSpec(
    source_id="ZINFOS974_CYBER",
    layer=config.LAYER_LOCAL_MEDIA,
    zone=config.LOC_REUNION,
    location_rule=config.LOC_REUNION,
)
AS_OF = "2026-08-12T00:00:00+04:00"


class TestEntryToItem:
    def test_entree_cyber_devient_item(self):
        entry = RawEntry(
            title="Mairie de Saint-Leu : fuite de données",
            url="https://media.re/a",
            published="2026-03-05",
        )
        item = entry_to_item(entry, SPEC, AS_OF, {}, {})

        assert item is not None
        assert item.Organisation_Raw == "Mairie de Saint-Leu"
        assert item.Organisation_Key == "mairie de saint leu"
        assert item.Threat == config.THREAT_LEAK
        assert item.Sector == config.SECTOR_ADMIN
        assert item.Location == config.LOC_REUNION
        assert item.Item_ID.startswith("ITM-")

    def test_entree_non_cyber_ecartee(self):
        """Une rubrique « Numérique » ne doit pas tout déverser dans ITEMS."""
        entry = RawEntry(
            title="Inauguration de la médiathèque",
            url="https://media.re/b",
            published="2026-03-05",
        )
        assert entry_to_item(entry, SPEC, AS_OF, {}, {}) is None

    def test_source_a_menace_declaree_ne_refiltre_pas(self):
        """Une liste de fuites ne publie que des fuites : son périmètre fait foi.

        Sans cette règle, une entrée réduite au nom de l'organisation touchée
        serait écartée faute de vocabulaire cyber, produisant un faux zéro sur
        une source pourtant intégralement parcourue.
        """
        leak_spec = SourceSpec(
            source_id="BONJOURLAFUITE",
            layer=config.LAYER_CORE,
            zone=config.LOC_FRANCE,
            default_threat=config.THREAT_LEAK,
            location_rule=config.LOC_FRANCE,
        )
        entry = RawEntry(
            title="Société Générale",
            url="https://bonjourlafuite.eu.org/a",
            published="2026-03-05",
        )
        item = entry_to_item(entry, leak_spec, AS_OF, {}, {})

        assert item is not None
        assert item.Threat == config.THREAT_LEAK
        assert item.Organisation_Raw == "Société Générale"

    def test_entree_sans_date_ecartee(self):
        entry = RawEntry(title="Cyberattaque", url="https://media.re/c", published="")
        assert entry_to_item(entry, SPEC, AS_OF, {}, {}) is None

    def test_organisation_reconnue_parmi_les_entites(self):
        known = watchlists.known_organisations()
        entry = RawEntry(
            title="Le CHU de La Réunion touché par un ransomware",
            url="https://media.re/d",
            published="2026-03-05",
        )
        item = entry_to_item(entry, SPEC, AS_OF, known, {})
        assert item.Organisation_Raw == "CHU de La Réunion"
        assert item.Threat == config.THREAT_RANSOMWARE

    def test_organisation_absente_reste_vide(self):
        """Aucune organisation devinée : mieux vaut vide que faux."""
        entry = RawEntry(
            title="Une cyberattaque frappe la région",
            url="https://media.re/e",
            published="2026-03-05",
        )
        item = entry_to_item(entry, SPEC, AS_OF, {}, {})
        assert item.Organisation_Key == ""

    def test_item_sans_organisation_ne_cree_pas_d_incident(self):
        entry = RawEntry(
            title="Une cyberattaque frappe la région",
            url="https://media.re/f",
            published="2026-03-05",
        )
        item = entry_to_item(entry, SPEC, AS_OF, {}, {})
        assert build_incidents([item]) == []

    def test_secteur_de_la_watchlist_utilise(self):
        index = watchlists.entity_index()
        entry = RawEntry(
            title="Intrusion signalée",
            url="https://media.re/g",
            published="2026-03-05",
            entity="Air Austral",
            organisation="Air Austral",
        )
        item = entry_to_item(entry, SPEC, AS_OF, {}, index)
        assert item.Sector == config.SECTOR_TRANSPORT


class TestRunContext:
    def test_create_demarre_au_premier_janvier(self):
        context = make_run_context(MODE_CREATE, as_of="2026-08-12T10:00:00+04:00")
        assert context.target_start == "2026-01-01"
        assert context.target_end == "2026-08-12"
        assert context.mode == MODE_CREATE

    def test_debut_explicite_respecte(self):
        context = make_run_context(
            MODE_CREATE, as_of="2026-08-12T10:00:00+04:00", target_start="2025-06-01"
        )
        assert context.target_start == "2025-06-01"

    def test_couches_par_defaut(self):
        context = make_run_context(MODE_CREATE, as_of="2026-08-12T10:00:00+04:00")
        assert config.LAYER_CORE in context.layers


class TestEntityWatch:
    def test_ligne_par_entite_surveillee(self):
        rows = build_entity_watch([], [], AS_OF, [])
        assert len(rows) == len(watchlists.ALL_ENTITIES)
        assert {row["Territory"] for row in rows} >= {
            config.LOC_REUNION,
            config.LOC_MAYOTTE,
        }

    def test_entite_interrogee_marquee(self):
        watch_rows = [
            {"entity": "CHU de La Réunion", "status": status.OK, "items_found": 2,
             "queries_expected": 2, "queries_done": 2}
        ]
        rows = build_entity_watch(watch_rows, [], AS_OF, [])
        chu = next(r for r in rows if r["Entity"] == "CHU de La Réunion")
        assert chu["Last_Queried"] == AS_OF
        assert chu["Query_Status"] == status.OK
        assert chu["Items_Found"] == 2

    def test_entite_non_interrogee_conserve_son_etat(self):
        """Le tableau reste complet : on voit depuis quand une entité dort."""
        previous = [
            {"Entity": "Air Austral", "Last_Queried": "2026-01-01T00:00:00+04:00",
             "Query_Status": status.OK, "Items_Found": "3"}
        ]
        rows = build_entity_watch([], [], AS_OF, previous)
        air = next(r for r in rows if r["Entity"] == "Air Austral")
        assert air["Last_Queried"] == "2026-01-01T00:00:00+04:00"

    def test_dernier_incident_rattache(self, make_item):
        incidents = build_incidents(
            [make_item(org="CHU de La Réunion", published="2026-05-01")]
        )
        rows = build_entity_watch([], incidents, AS_OF, [])
        chu = next(r for r in rows if r["Entity"] == "CHU de La Réunion")
        assert chu["Last_Incident_Date"] == "2026-05-01"
        assert chu["Last_Incident_ID"].startswith("INC-")


class TestPreExportChecks:
    def test_base_saine(self, make_item):
        items = [make_item()]
        incidents = build_incidents(items)
        outcomes = [
            status.SourceOutcome(spec.source_id, spec.layer, status.OK, 100)
            for spec in __import__(
                "cyberwatch.sources", fromlist=["ALL_SOURCES"]
            ).ALL_SOURCES
        ]
        assert pre_export_checks(items, incidents, outcomes) == []

    def test_item_id_duplique_detecte(self, make_item):
        item = make_item()
        problems = pre_export_checks([item, item], [], [])
        assert any("Item_ID dupliqué" in p for p in problems)

    def test_source_active_sans_ligne_detectee(self, make_item):
        problems = pre_export_checks([make_item()], [], [])
        assert any("sans ligne RUN_SOURCES" in p for p in problems)

    def test_ok_sans_couverture_complete_detecte(self):
        outcomes = [
            status.SourceOutcome("FRENCHBREACHES", config.LAYER_CORE, status.OK, 80)
        ]
        problems = pre_export_checks([], [], outcomes)
        assert any("OK sans couverture complète" in p for p in problems)
