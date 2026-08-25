"""Runner : normalisation des entrées, veille par entité, contrôles du §29."""

import datetime as dt

import pytest

from cyberwatch import config, identity, runner, status, watchlists
from cyberwatch.collectors.base import CollectResult, RawEntry, SourceSpec, Window
from cyberwatch.dedup import build_incidents
from cyberwatch.runner import (
    MODE_CREATE,
    RunContext,
    build_entity_watch,
    entry_to_item,
    make_run_context,
    pre_export_checks,
    repair_item_integrity,
    run_source,
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
        # `entry_to_item` conserve désormais le défaut source pour l'étape
        # suivante du pipeline afin que l'enrichissement entreprise reste prioritaire.
        assert item.Location == config.LOC_INCONNU
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
            params={"title_is_organisation": True},
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

    def test_titre_organisation_declare_par_la_source_seulement(self):
        """Sans la règle déclarée, aucun titre n'est promu en organisation."""
        leak_spec = SourceSpec(
            source_id="FRENCHBREACHES",
            layer=config.LAYER_CORE,
            zone=config.LOC_FRANCE,
            default_threat=config.THREAT_LEAK,
        )
        entry = RawEntry(
            title="Une fuite de données touche plusieurs acteurs du secteur",
            url="https://frenchbreaches.com/a",
            published="2026-03-05",
        )
        item = entry_to_item(entry, leak_spec, AS_OF, {}, {})

        assert item is not None
        assert item.Organisation_Key == ""  # aucune organisation inventée

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


class TestHistoryStatus:
    """§stabilisation pré-release — axe orthogonal à Status/Coverage."""

    WINDOW = Window("2026-01-01", "2026-08-12")

    def test_borne_reellement_atteinte_donne_complete(self):
        result = CollectResult(reached_boundary=True, oldest_available_date="2025-12-01")
        history_status, oldest = runner._resolve_history_status(result, status.OK, self.WINDOW)
        assert history_status == status.HISTORY_COMPLETE
        assert oldest == "2025-12-01"

    def test_ok_malgre_profondeur_plus_courte_donne_truncated(self):
        """Cas FrenchBreaches : `feed_has_no_pagination` fait accepter la
        borne (Status=OK) alors que le flux ne remonte pas jusqu'au début de
        la fenêtre demandée — History_Status le documente sans reconsidérer
        Status/Coverage."""
        result = CollectResult(reached_boundary=True, oldest_available_date="2026-07-21")
        history_status, oldest = runner._resolve_history_status(result, status.OK, self.WINDOW)
        assert history_status == status.HISTORY_TRUNCATED
        assert oldest == "2026-07-21"

    def test_sans_date_connue_donne_unknown(self):
        result = CollectResult(reached_boundary=True)
        history_status, oldest = runner._resolve_history_status(result, status.OK, self.WINDOW)
        assert history_status == status.HISTORY_UNKNOWN
        assert oldest == ""

    def test_statut_non_ok_donne_unknown_meme_avec_une_date(self):
        """Une source PARTIAL/FAIL ne revendique aucune complétude
        historique, même si une date la plus ancienne a pu être calculée."""
        result = CollectResult(reached_boundary=False, oldest_available_date="2026-07-21")
        history_status, oldest = runner._resolve_history_status(result, status.PARTIAL, self.WINDOW)
        assert history_status == status.HISTORY_UNKNOWN
        assert oldest == "2026-07-21"

    def test_generique_sans_condition_sur_source_id(self):
        """Aucune règle spécifique à FRENCHBREACHES : seule la présence
        d'`oldest_available_date` déclenche le calcul."""
        result = CollectResult(reached_boundary=True, oldest_available_date="2026-07-21")
        history_status, _ = runner._resolve_history_status(result, status.OK, self.WINDOW)
        assert history_status == status.HISTORY_TRUNCATED


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
        items = [make_item(source="BONJOURLAFUITE")]
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

    def test_item_id_recalcule_et_cle_naturelle_detectes(self, make_item):
        left = make_item(url="https://example.test/a")
        right = make_item(url="https://example.test/a")
        right.Item_ID = "ITM-invalide"
        problems = pre_export_checks([left, right], build_incidents([left, right]), [])
        assert any("Item_ID invalide" in p for p in problems)
        assert any("Clé naturelle dupliquée" in p for p in problems)

    def test_source_active_sans_ligne_detectee(self, make_item):
        problems = pre_export_checks([make_item()], [], [])
        assert any("sans ligne RUN_SOURCES" in p for p in problems)

    def test_ok_sans_couverture_complete_detecte(self):
        outcomes = [
            status.SourceOutcome("FRENCHBREACHES", config.LAYER_CORE, status.OK, 80)
        ]
        problems = pre_export_checks([], [], outcomes)
        assert any("OK sans couverture complète" in p for p in problems)


class TestRepairItemIntegrity:
    def test_recalcul_et_dedoublonnage_exact(self, make_item):
        first = make_item(url="https://example.test/a")
        duplicate = make_item(url="https://example.test/a")
        duplicate.Item_ID = "ITM-obsolete"
        repaired, report = repair_item_integrity([first, duplicate])
        assert len(repaired) == 1
        assert report["duplicates_removed"] == 1
        assert repaired[0].Item_ID != "ITM-obsolete"


class TestCreateRepartDeZero:
    """§24 — `CREATE` construit la base depuis zéro, `MAJ` cumule (§25)."""

    def test_create_ignore_le_snapshot_precedent(self, tmp_path, monkeypatch, make_item):
        """Une évolution des règles change les Item_ID : sans repartir de zéro,
        chaque item cohabiterait avec sa version périmée."""
        from cyberwatch import runner, store

        for name in ("ITEMS_CSV", "INCIDENTS_CSV", "SOURCES_CSV",
                     "RUN_SOURCES_CSV", "RUN_LOG_CSV", "ENTITY_WATCH_CSV", "SNAPSHOT_JSON",
                     "SOURCE_FACTS_CSV", "QUALIFICATION_PROVENANCE_CSV"):
            monkeypatch.setattr(store, name, tmp_path / f"{name.lower()}.csv")

        store.save_items([make_item(url="https://ancien/1")])
        store.save_snapshot({"As_Of": "2026-08-10T10:00:00+04:00"})
        context = runner.make_run_context(
            runner.MODE_CREATE, as_of="2026-08-12T10:00:00+04:00"
        )
        report = runner.execute(context, offline=True)
        assert report.items == []
        assert report.overall == status.OK

    def test_maj_conserve_le_stock(self, tmp_path, monkeypatch, make_item):
        from cyberwatch import runner, store

        for name in ("ITEMS_CSV", "INCIDENTS_CSV", "SOURCES_CSV",
                     "RUN_SOURCES_CSV", "RUN_LOG_CSV", "ENTITY_WATCH_CSV", "SNAPSHOT_JSON",
                     "SOURCE_FACTS_CSV", "QUALIFICATION_PROVENANCE_CSV"):
            monkeypatch.setattr(store, name, tmp_path / f"{name.lower()}.csv")

        store.save_items([make_item(url="https://ancien/1")])
        store.save_snapshot({"As_Of": "2026-08-10T10:00:00+04:00"})
        context = runner.make_run_context(
            runner.MODE_MAJ, as_of="2026-08-12T10:00:00+04:00"
        )
        report = runner.execute(context, offline=True)
        assert len(report.items) == 1
        assert report.overall == status.OK


class TestSourceFactsPersistence:
    """§13 METHODOLOGY.md : CREATE peuple `source_facts.csv`, MAJ fusionne
    par `Item_ID` sans doublon, REPLAY ne le touche jamais.

    VEILLE_LLM est la seule source active de `LAYER_REGIONAL_WATCH` et son
    collecteur lit un snapshot JSON local (aucun accès réseau) : ces tests
    exercent `runner.execute()` en mode non `offline` sans mock HTTP.
    """

    def _isolate(self, tmp_path, monkeypatch):
        from cyberwatch import store

        # Le mode non `offline` traverse aussi `ai.py`/`org_enrichment.py`
        # (même sans clé API : Status=DISABLED est tout de même journalisé) et,
        # en MAJ, `runner.run_daily_dedup_net` (§Lot 2/9 : même sans candidat
        # ni clé API, la télémétrie NO_CANDIDATES/LLM_DISABLED est journalisée
        # dans DEDUP_AI_DAILY_USAGE_CSV) : isoler ces CSV est requis pour ne
        # jamais écrire dans data/ réel.
        for name in ("ITEMS_CSV", "INCIDENTS_CSV", "SOURCES_CSV",
                     "RUN_SOURCES_CSV", "RUN_LOG_CSV", "ENTITY_WATCH_CSV", "SNAPSHOT_JSON",
                     "SOURCE_FACTS_CSV", "QUALIFICATION_PROVENANCE_CSV", "AI_QUALIFICATIONS_CSV", "AI_USAGE_CSV",
                     "ORG_ENRICHMENT_CACHE_CSV", "DEDUP_AI_DAILY_USAGE_CSV"):
            monkeypatch.setattr(store, name, tmp_path / f"{name.lower()}.csv")
        monkeypatch.setattr(store, "DATA_DIR", tmp_path)

    def test_create_peuple_source_facts(self, tmp_path, monkeypatch):
        from cyberwatch import runner, store

        self._isolate(tmp_path, monkeypatch)
        context = runner.make_run_context(
            runner.MODE_CREATE, as_of="2026-08-15T10:00:00+04:00",
            target_start="2000-01-01", layers=[config.LAYER_REGIONAL_WATCH],
        )
        report = runner.execute(context, offline=False)

        assert report.overall == status.OK
        facts = store.load_source_facts()
        assert facts
        assert all(row["Source_ID"] == "VEILLE_LLM" for row in facts)
        veille_item_ids = {i.Item_ID for i in report.items if i.Source_ID == "VEILLE_LLM"}
        assert {row["Item_ID"] for row in facts} <= veille_item_ids
        assert all(row["Fine_Location"] or row["Threat_Actor"] for row in facts)

    def test_maj_fusionne_sans_doublon(self, tmp_path, monkeypatch):
        from cyberwatch import runner, store

        self._isolate(tmp_path, monkeypatch)
        first_context = runner.make_run_context(
            runner.MODE_CREATE, as_of="2026-08-15T10:00:00+04:00",
            target_start="2000-01-01", layers=[config.LAYER_REGIONAL_WATCH],
        )
        runner.execute(first_context, offline=False)
        first_facts = store.load_source_facts()

        second_context = runner.make_run_context(
            runner.MODE_MAJ, as_of="2026-08-16T10:00:00+04:00",
            target_start="2000-01-01", layers=[config.LAYER_REGIONAL_WATCH],
        )
        runner.execute(second_context, offline=False)
        second_facts = store.load_source_facts()

        item_ids = [row["Item_ID"] for row in second_facts]
        assert len(item_ids) == len(set(item_ids))
        assert len(second_facts) == len(first_facts)

    def test_replay_n_ecrit_jamais_source_facts(self, tmp_path, monkeypatch, make_item):
        from cyberwatch import runner, store

        self._isolate(tmp_path, monkeypatch)
        store.save_items([make_item()])
        store.save_snapshot({"As_Of": "2026-08-10T10:00:00+04:00"})
        store.save_source_facts([{"Item_ID": "sentinel", "Source_ID": "X"}])

        def _boom(*_args, **_kwargs):
            raise AssertionError("REPLAY ne doit jamais écrire source_facts.csv")

        monkeypatch.setattr(store, "save_source_facts", _boom)
        context = runner.make_run_context(
            runner.MODE_REPLAY, as_of="2026-08-12T10:00:00+04:00"
        )
        report = runner.execute(context, offline=True)

        assert report.overall == status.OK
        # Le fichier isolé n'a pas été rouvert : la sentinelle reste telle quelle.
        facts = store.load_source_facts()
        assert len(facts) == 1
        assert facts[0]["Item_ID"] == "sentinel"
        assert facts[0]["Source_ID"] == "X"


def test_runner_passes_one_semantic_snapshot_to_source_facts(monkeypatch, make_item):
    """Un cache complet ne peut plus masquer une extraction sémantique fraîche."""
    from cyberwatch import runner, source_facts_ai
    from cyberwatch.collectors.base import RawEntry, SourceSpec

    item = make_item()
    item.Source_ID = "CYBERATTAQUE_ORG"
    entry = RawEntry(title="Exemple", content="Un incident est confirmé.")
    snapshot = source_facts_ai.SemanticExtraction(
        item_id=item.Item_ID,
        content_hash=source_facts_ai.content_hash(entry),
        fields={"summary": "Exemple SA a confirmé un incident affectant ses services."},
        statuses={"summary": "accepted"},
    )
    captured = {}
    monkeypatch.setattr(runner.source_facts_ai, "extract_semantic", lambda *_: snapshot)

    def _extract(*_args, **kwargs):
        captured["semantic"] = kwargs.get("semantic")
        return {"Item_ID": item.Item_ID}

    monkeypatch.setattr(
        runner.source_facts,
        "extract_source_fact",
        _extract,
    )

    result = runner._extract_source_fact_for_entry(
        item, entry, SourceSpec(source_id="CYBERATTAQUE_ORG", layer="core", zone="France")
    )

    assert result == {"Item_ID": item.Item_ID}
    assert captured["semantic"] is snapshot


class TestFauxPositifFourriere:
    """Régression sur le cas réel qui a pollué la base.

    « Six interpellations après une intrusion dans une fourrière à Saint-Denis »
    était devenu un incident cyber de la Mairie de Saint-Denis — et c'était le
    seul incident réunionnais de la base.
    """

    TITRE = "Six interpellations après une intrusion dans une fourrière à Saint-Denis"

    def test_le_nom_nu_de_commune_n_identifie_plus_la_mairie(self):
        from cyberwatch import watchlists
        from cyberwatch.collectors.mediawatch import mentions
        from cyberwatch.normalize import searchable

        mairie = next(
            e for e in watchlists.REUNION_ENTITIES if e.name == "Mairie de Saint-Denis"
        )
        labels = watchlists.identifying_labels(mairie)
        assert "Saint-Denis" not in labels
        assert mentions(searchable(self.TITRE), labels) == ""

    def test_le_fait_divers_n_est_pas_cyber(self):
        from cyberwatch.normalize import looks_cyber

        assert not looks_cyber(self.TITRE)

    def test_la_mairie_reste_reconnue_quand_elle_est_nommee(self):
        from cyberwatch import watchlists
        from cyberwatch.collectors.mediawatch import mentions
        from cyberwatch.normalize import searchable

        mairie = next(
            e for e in watchlists.REUNION_ENTITIES if e.name == "Mairie de Saint-Denis"
        )
        labels = watchlists.identifying_labels(mairie)
        for titre in (
            "La Mairie de Saint-Denis victime d'une cyberattaque",
            "La commune de Saint-Denis touchée par un ransomware",
        ):
            assert mentions(searchable(titre), labels) != ""


class TestTerritoireDeLEntite:
    """§10 rang 2 — une entité surveillée impose son territoire."""

    def test_entite_ultramarine_dans_une_source_nationale(self):
        """Air Austral restait « France métropolitaine » via un agrégateur national."""
        from cyberwatch import sources, watchlists

        spec = sources.by_id("CYBERATTAQUE_ORG")
        entry = RawEntry(
            title="Air Austral : les données de 1 000 employés diffusées publiquement",
            url="https://www.cyberattaque.org/a",
            published="2026-05-31",
        )
        item = entry_to_item(
            entry, spec, AS_OF,
            watchlists.known_organisations(),
            watchlists.entity_index(),
            watchlists.entity_territories(),
        )
        assert item.Organisation_Raw == "Air Austral"
        assert item.Location == config.LOC_REUNION
        assert item.Sector == config.SECTOR_TRANSPORT

    def test_organisation_inconnue_ne_recoit_pas_un_defaut_france(self):
        from cyberwatch import sources, watchlists

        spec = sources.by_id("CYBERATTAQUE_ORG")
        entry = RawEntry(
            title="Société Dupont : fuite de données",
            url="https://www.cyberattaque.org/b",
            published="2026-05-31",
        )
        item = entry_to_item(
            entry, spec, AS_OF, {}, {}, watchlists.entity_territories()
        )
        assert item.Location == config.LOC_INCONNU

    def test_localisation_de_la_source_prime_sur_l_entite(self):
        """Une localisation explicitement fournie reste au rang 1."""
        from cyberwatch import watchlists

        spec = SourceSpec("X", config.LAYER_CORE, "Multi", location_rule="")
        entry = RawEntry(
            title="Air Austral piratée", url="https://x/c", published="2026-05-31",
            location=config.LOC_MAURICE,
        )
        item = entry_to_item(
            entry, spec, AS_OF, watchlists.known_organisations(), {},
            watchlists.entity_territories(),
        )
        assert item.Location == config.LOC_MAURICE


class _FakeCollector:
    """Renvoie des entrées fixes, indépendamment de la source déclarée.

    Permet de tester `run_source` sans réseau : le contrat testé est le calcul
    de `latest_item_date`/`latest_item_org`, généralisé à toute source (plus
    de traitement spécial BonjourLaFuite).
    """

    def __init__(self, entries):
        self._entries = entries

    def collect(self, client, spec, window):
        return CollectResult(
            entries=self._entries, reached_boundary=True,
            units_done=1, units_expected=1,
        )


class TestLatestItemGeneralized:
    """`latest_item_date`/`latest_item_org` : mêmes champs pour toute source,
    calculés depuis les items réellement matérialisés, tri déterministe."""

    SPEC = SourceSpec(
        source_id="GENERIC_SOURCE", layer=config.LAYER_CORE, zone=config.LOC_FRANCE,
        default_threat=config.THREAT_UNKNOWN,
    )
    CONTEXT = RunContext(
        run_id="RUN-TEST", as_of=AS_OF, target_start="2026-01-01",
        target_end="2026-08-15", mode=MODE_CREATE, layers=[config.LAYER_CORE],
    )

    def _run(self, entries, spec=None, monkeypatch=None):
        assert monkeypatch is not None
        monkeypatch.setattr(runner, "get_collector", lambda name: _FakeCollector(entries))
        outcome, items, _ = run_source(
            None, spec or self.SPEC, self.CONTEXT, {}, {},
        )
        return outcome, items

    def test_latest_item_date_et_org_correspondent_au_dernier_item(self, monkeypatch):
        entries = [
            RawEntry(title="A", organisation="Org A", published="2026-06-01", url="https://x/a"),
            RawEntry(title="B", organisation="Org B", published="2026-06-03", url="https://x/b"),
        ]
        outcome, items = self._run(entries, monkeypatch=monkeypatch)

        assert len(items) == 2
        assert outcome.latest_item_date == "2026-06-03"
        assert outcome.latest_item_org == "Org B"

    def test_determinisme_en_cas_degalite_de_date(self, monkeypatch):
        """Deux items publiés le même jour : le départage par Item_ID est
        stable d'un run à l'autre, jamais un artefact d'ordre d'itération."""
        entries = [
            RawEntry(title="C", organisation="Org C", published="2026-06-03", url="https://x/c"),
            RawEntry(title="D", organisation="Org D", published="2026-06-03", url="https://x/d"),
        ]
        outcome1, items1 = self._run(entries, monkeypatch=monkeypatch)
        outcome2, items2 = self._run(list(reversed(entries)), monkeypatch=monkeypatch)

        winner = max(items1, key=lambda i: (i.Published_Date, i.Item_ID))
        assert outcome1.latest_item_date == winner.Published_Date
        assert outcome1.latest_item_org == winner.Organisation_Raw
        # Même résultat quel que soit l'ordre d'entrée des entrées sources.
        assert outcome1.latest_item_date == outcome2.latest_item_date
        assert outcome1.latest_item_org == outcome2.latest_item_org

    def test_aucun_item_laisse_les_champs_vides(self, monkeypatch):
        outcome, items = self._run([], monkeypatch=monkeypatch)
        assert items == []
        assert outcome.latest_item_date == ""
        assert outcome.latest_item_org == ""

    def test_bonjourlafuite_nest_plus_un_cas_special(self, monkeypatch):
        """Même mécanique générique pour BonjourLaFuite : plus de dépendance
        au texte libre du commentaire du collecteur."""
        spec = SourceSpec(
            source_id="BONJOURLAFUITE", layer=config.LAYER_CORE, zone=config.LOC_FRANCE,
            default_threat=config.THREAT_LEAK,
            params={"title_is_organisation": True},
        )
        entries = [
            RawEntry(title="France VAE", organisation="France VAE", published="2026-08-13", url="https://x/e"),
        ]
        outcome, items = self._run(entries, spec=spec, monkeypatch=monkeypatch)

        assert outcome.latest_item_date == "2026-08-13"
        assert outcome.latest_item_org == "France VAE"


class TestDailyDedupNet:
    """Filet LLM post-déterministe quotidien (§Lot 2/9/10/15/17).

    `run_daily_dedup_net` est testée directement (sans traverser tout
    `execute`) pour les cas unitaires ; `test_replay_never_calls_llm` exerce
    `execute(offline=True)` en entier pour garantir l'invariant absolu de
    REPLAY même avec le filet activé et une clé API présente.
    """

    def _isolate(self, tmp_path, monkeypatch):
        from cyberwatch import store

        for name in ("ITEMS_CSV", "INCIDENTS_CSV", "SOURCES_CSV",
                     "RUN_SOURCES_CSV", "RUN_LOG_CSV", "ENTITY_WATCH_CSV", "SNAPSHOT_JSON",
                     "SOURCE_FACTS_CSV", "QUALIFICATION_PROVENANCE_CSV", "AI_QUALIFICATIONS_CSV",
                     "AI_USAGE_CSV", "ORG_ENRICHMENT_CACHE_CSV", "DEDUP_AI_DAILY_USAGE_CSV"):
            monkeypatch.setattr(store, name, tmp_path / f"{name.lower()}.csv")
        monkeypatch.setattr(store, "DATA_DIR", tmp_path)

    def test_no_new_items_is_zero_call(self, tmp_path, monkeypatch, make_item):
        self._isolate(tmp_path, monkeypatch)
        state, problems = runner.run_daily_dedup_net(
            [make_item()], [], [],
            run_id="RUN-1", as_of="2026-08-20T00:00:00+04:00", mode="MAJ", persist=False,
        )
        assert problems == []
        assert state.batch_calls_attempted == 0

    def test_daily_run_llm_failure_falls_back_deterministic(self, tmp_path, monkeypatch, make_item):
        """Une panne du filet (ici simulée par une exception dans le
        challenger batch) ne doit jamais se propager : le run continue avec
        le pipeline déterministe, la panne est journalisée explicitement."""
        from cyberwatch import dedup_ai

        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("DEDUP_AI_DAILY_ENABLED", "1")

        new_item = make_item(source="A", org="Zorglub Consulting", published="2026-08-20", url="https://a")
        historical = make_item(source="B", org="ZorglubConsulting", published="2026-01-01", url="https://b")

        def _boom(*args, **kwargs):
            raise RuntimeError("panne réseau simulée")

        monkeypatch.setattr(dedup_ai, "challenge_candidates_batch", _boom)

        state, problems = runner.run_daily_dedup_net(
            [new_item, historical], [new_item], [],
            run_id="RUN-2", as_of="2026-08-20T00:00:00+04:00", mode="MAJ", persist=False,
        )
        assert problems
        assert "panne réseau simulée" in problems[0]

    def test_registry_write_gated_by_persist(self, tmp_path, monkeypatch, make_item):
        """`--transient` (`persist=False`) ne doit jamais réécrire le registre
        d'identité, au même titre qu'ITEMS/INCIDENTS."""
        from cyberwatch import dedup_ai, org_identity, store

        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("DEDUP_AI_DAILY_ENABLED", "1")

        new_item = make_item(source="A", org="Zorglub Consulting", published="2026-08-20", url="https://a")
        historical = make_item(source="B", org="ZorglubConsulting", published="2026-01-01", url="https://b")

        def fake_batch(candidates, facts_by_item, state, company_ids):
            return {
                dedup_ai.candidate_id(c): dedup_ai.DedupAiDecision(
                    status=dedup_ai.STATUS_OK, same_organisation=dedup_ai.SAME,
                    same_incident=dedup_ai.DIFFERENT, confidence=0.99, evidence="e",
                )
                for c in candidates
            }

        monkeypatch.setattr(dedup_ai, "challenge_candidates_batch", fake_batch)

        runner.run_daily_dedup_net(
            [new_item, historical], [new_item], [],
            run_id="RUN-3", as_of="2026-08-20T00:00:00+04:00", mode="MAJ", persist=False,
        )
        assert store.load_organisation_identity_registry_rows() == []
        assert store.load_dedup_ai_daily_usage() == []

    def test_replay_uses_registry_without_llm(self, tmp_path, monkeypatch, make_item):
        """Invariant absolu (§Lot 10) : REPLAY ne doit jamais appeler le LLM,
        même avec `OPENAI_API_KEY` et `DEDUP_AI_DAILY_ENABLED=1` — mais doit
        tout de même reproduire le regroupement issu d'une décision LLM déjà
        validée et persistée dans une MAJ antérieure, en lisant uniquement le
        registre déjà sur disque (§Lot 6/9/10)."""
        from cyberwatch import dedup_ai, llm_runtime, org_identity, store

        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("DEDUP_AI_DAILY_ENABLED", "1")

        def _forbidden(*args, **kwargs):
            raise AssertionError("REPLAY ne doit jamais appeler le LLM")

        monkeypatch.setattr(llm_runtime.LlmRuntime, "call_json", _forbidden)
        monkeypatch.setattr(dedup_ai.ai, "_post_openai", _forbidden)

        left = make_item(source="A", org="Zorglub Consulting", published="2026-08-01", url="https://a")
        right = make_item(source="B", org="ZorglubConsulting", published="2026-08-02", url="https://b")
        store.save_items([left, right])
        store.save_snapshot({"As_Of": "2026-08-10T10:00:00+04:00"})

        # Simule une décision LLM validée et persistée par une MAJ antérieure.
        registry_path = tmp_path / "organisation_identity_registry.csv"
        store.write_csv(
            registry_path,
            org_identity.ORGANISATION_IDENTITY_REGISTRY_COLUMNS,
            [{
                "Alias_Key": "zorglubconsulting", "Canonical_Key": "zorglub consulting",
                "Alias_Raw": "ZorglubConsulting", "Canonical_Raw": "Zorglub Consulting",
                "Decision": "SAME", "Origin": "LLM_CONFIRMED", "Confidence": "0.97",
                "Evidence": "e", "First_Seen": "2026-08-09T00:00:00+00:00",
                "Last_Validated": "2026-08-09T00:00:00+00:00", "Model": "gpt-4o-mini",
                "Prompt_Version": "v1", "Input_Hash": "h",
            }],
        )
        org_identity.reload_organisation_identity_registry(registry_path)
        try:
            context = runner.make_run_context(runner.MODE_REPLAY, as_of="2026-08-12T10:00:00+04:00")
            report = runner.execute(context, offline=True)

            assert report.overall == status.OK
            assert report.dedup_ai_summary == {}
            # Le registre déjà persisté suffit à reproduire le regroupement,
            # sans le moindre appel LLM : les deux items forment un seul incident.
            matching = [i for i in report.incidents if i.Items_Count == 2]
            assert len(matching) == 1
        finally:
            org_identity.reload_organisation_identity_registry()

    def test_create_declenche_aussi_le_filet(self, tmp_path, monkeypatch):
        """Cas réel constaté (audit post-reset 2026-08-25) : un reset total
        (CREATE) publiait "Banque Alimentaire de la Croix-Rouge à
        Strasbourg" et "Banque Alimentaire de Strasbourg" comme deux
        incidents distincts sans jamais soumettre la paire au filet LLM,
        celui-ci étant gelé sur MODE_MAJ. `execute()` doit désormais
        invoquer `run_daily_dedup_net` pour CREATE aussi bien que pour MAJ.
        VEILLE_LLM (seule source de LAYER_REGIONAL_WATCH) lit un snapshot
        JSON local : ce test exerce `execute(offline=False)` sans la moindre
        collecte réseau, comme `TestSourceFactsPersistence`."""
        self._isolate(tmp_path, monkeypatch)
        context = runner.make_run_context(
            runner.MODE_CREATE, as_of="2026-08-25T10:00:00+04:00",
            layers=[config.LAYER_REGIONAL_WATCH],
        )
        report = runner.execute(context, offline=False)

        assert report.overall == status.OK
        assert report.dedup_ai_summary != {}
        assert report.dedup_ai_summary["dedup_candidates_generated"] > 0
        assert report.dedup_ai_problems == []


class TestOrganisationIdentityRegistryDoesNotAffectItemId:
    """§Lot 8 : le registre n'agit que sur `effective_organisation_key`, la
    déduplication — jamais sur `Item_ID`, dont la stabilité historique doit
    être préservée."""

    def test_item_id_unaffected_by_registry(self, monkeypatch):
        from cyberwatch import identity, org_identity
        from cyberwatch.normalize import organisation_key

        key = organisation_key("ZorglubConsulting")
        before = identity.item_id("A", "2026-08-01", key, "https://a")
        monkeypatch.setattr(
            org_identity, "ORGANISATION_IDENTITY_REGISTRY",
            {"zorglubconsulting": "zorglub consulting"},
        )
        after = identity.item_id("A", "2026-08-01", key, "https://a")
        assert before == after

    def test_incident_id_stability_through_registry_regroup(self, make_item, monkeypatch):
        """§Lot 8/9 : quand le registre unifie deux items jusque-là séparés,
        l'incident résultant conserve l'identité de son ancre historique la
        plus ancienne (`incident_identity.assign_incident_ids`) — jamais un
        Incident_ID fraîchement inventé — et les `Item_ID` ne bougent jamais."""
        from cyberwatch import org_identity
        from cyberwatch.dedup import build_incidents_with_registry

        left = make_item(source="A", org="Zorglub Consulting", published="2026-08-01", url="https://a")
        right = make_item(source="B", org="ZorglubConsulting", published="2026-08-02", url="https://b")
        left_id_before, right_id_before = left.Item_ID, right.Item_ID

        before, registry = build_incidents_with_registry([left, right], [])
        assert len(before) == 2
        pre_existing_incident_ids = {incident.Incident_ID for incident in before}

        monkeypatch.setattr(
            org_identity, "ORGANISATION_IDENTITY_REGISTRY",
            {"zorglubconsulting": "zorglub consulting"},
        )
        after, _ = build_incidents_with_registry([left, right], registry)
        assert len(after) == 1
        # L'Incident_ID survivant est l'un des deux déjà connus (celui dont
        # l'ancre a été collectée en premier), jamais un troisième ID inédit.
        assert after[0].Incident_ID in pre_existing_incident_ids
        # Les Item_ID ne changent jamais, seul le regroupement en incidents change.
        assert left.Item_ID == left_id_before
        assert right.Item_ID == right_id_before
