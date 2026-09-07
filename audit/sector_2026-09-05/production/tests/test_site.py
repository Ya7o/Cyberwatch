"""Dashboard : détail des sources homogène, `latest_item_org` généralisé."""

from __future__ import annotations

import re

import pytest

from cyberwatch import site, store


def _isolate_store(tmp_path, monkeypatch):
    mapping = {
        "RUN_LOG_CSV": tmp_path / "run_log.csv",
        "RUN_SOURCES_CSV": tmp_path / "run_sources.csv",
        "ENTITY_WATCH_CSV": tmp_path / "entity_watch.csv",
        "SOURCES_CSV": tmp_path / "sources.csv",
        "SOURCE_FACTS_CSV": tmp_path / "source_facts.csv",
    }
    for name, path in mapping.items():
        monkeypatch.setattr(store, name, path)
    monkeypatch.setattr(store, "snapshot_state", lambda: (store.BASE_VALID, []))


def _seed_run(monkeypatch, tmp_path, sources_rows):
    _isolate_store(tmp_path, monkeypatch)
    store.append_run_log({
        "Run_ID": "RUN-TEST", "As_Of": "2026-08-15T00:00:00+04:00", "Mode": "MAJ",
        "Overall_Status": "OK", "Sources_OK": len(sources_rows), "Sources_PARTIAL": 0,
        "Sources_FAIL": 0, "Sources_SKIPPED": 0,
    })
    for row in sources_rows:
        base = {
            "Run_ID": "RUN-TEST", "As_Of": "2026-08-15T00:00:00+04:00",
            "Status": "OK", "Coverage": 100, "Reason_Code": "OK", "Reason": "OK",
            "Calls": 1, "Units_Done": 1, "Units_Expected": 1,
            "Items_seen": 0, "Items_in_window": 0, "Items_collected": 0, "New_items": 0,
            "Latest_item_date": "", "Latest_Item_Org": "", "Access_Method": "", "Duration_s": 1.0,
            "Comment": "",
        }
        base.update(row)
        store.append_run_sources([base])


class TestLatestItemOrgGeneralized:
    def test_toutes_les_sources_exposent_latest_item_org_de_facon_uniforme(self, tmp_path, monkeypatch):
        """Aucun traitement spécial par source_id : le champ vient directement
        de la colonne générique `Latest_Item_Org` pour toute source."""
        _seed_run(monkeypatch, tmp_path, [
            {
                "Source_ID": "BONJOURLAFUITE", "Layer": "CORE_DIRECT",
                "Items_seen": 9, "Items_in_window": 3,
                "Latest_item_date": "2026-08-13", "Latest_Item_Org": "France VAE",
            },
            {
                "Source_ID": "FRENCHBREACHES", "Layer": "CORE_DIRECT",
                "Items_seen": 77, "Items_in_window": 12,
                "Latest_item_date": "2026-08-14", "Latest_Item_Org": "Société Dupont",
            },
        ])

        payload = site.status_payload()
        by_id = {row["id"]: row for row in payload["sources"]}

        assert by_id["BONJOURLAFUITE"]["latest_item_org"] == "France VAE"
        assert by_id["BONJOURLAFUITE"]["latest_item"] == "2026-08-13"
        assert by_id["FRENCHBREACHES"]["latest_item_org"] == "Société Dupont"
        assert by_id["FRENCHBREACHES"]["latest_item"] == "2026-08-14"

    def test_items_seen_et_items_in_window_passent_tels_quels(self, tmp_path, monkeypatch):
        _seed_run(monkeypatch, tmp_path, [
            {
                "Source_ID": "CYBERATTAQUE_ORG", "Layer": "CORE_DIRECT",
                "Items_seen": 64, "Items_in_window": 21,
            },
        ])

        payload = site.status_payload()
        row = next(r for r in payload["sources"] if r["id"] == "CYBERATTAQUE_ORG")
        assert row["items_seen"] == 64
        assert row["items_in_window"] == 21

    def test_plus_de_bloc_bonjourlafuite_special_dans_le_payload(self, tmp_path, monkeypatch):
        """`_local_analysis_by_incident`/`status_payload` ne portent plus de
        clé dédiée : le détail générique par source suffit."""
        _seed_run(monkeypatch, tmp_path, [
            {"Source_ID": "BONJOURLAFUITE", "Layer": "CORE_DIRECT"},
        ])

        payload = site.status_payload()
        assert "bonjourlafuite" not in payload

    def test_source_sans_item_a_des_champs_vides(self, tmp_path, monkeypatch):
        _seed_run(monkeypatch, tmp_path, [
            {"Source_ID": "RANSOMWARE_LIVE", "Layer": "CORE_DIRECT"},
        ])

        payload = site.status_payload()
        row = next(r for r in payload["sources"] if r["id"] == "RANSOMWARE_LIVE")
        assert row["latest_item"] == ""
        assert row["latest_item_org"] == ""


class TestHistoryStatusPayload:
    """§stabilisation pré-release — propagation vers `assets/data/status.json`."""

    def test_history_status_et_oldest_available_date_propages(self, tmp_path, monkeypatch):
        _seed_run(monkeypatch, tmp_path, [
            {
                "Source_ID": "FRENCHBREACHES", "Layer": "CORE_DIRECT",
                "History_Status": "TRUNCATED", "Oldest_Available_Date": "2026-07-21",
            },
        ])

        payload = site.status_payload()
        row = next(r for r in payload["sources"] if r["id"] == "FRENCHBREACHES")

        assert row["history_status"] == "TRUNCATED"
        assert row["oldest_available_date"] == "2026-07-21"

    def test_absence_de_colonne_historique_reste_unknown(self, tmp_path, monkeypatch):
        """Compatibilité ascendante : une ligne `run_sources.csv` antérieure
        à ce chantier n'a pas ces colonnes — jamais une erreur, `UNKNOWN`."""
        _seed_run(monkeypatch, tmp_path, [
            {"Source_ID": "BONJOURLAFUITE", "Layer": "CORE_DIRECT"},
        ])

        payload = site.status_payload()
        row = next(r for r in payload["sources"] if r["id"] == "BONJOURLAFUITE")

        assert row["history_status"] == "UNKNOWN"
        assert row["oldest_available_date"] == ""


class TestDashboardSourcesSection:
    """Vue globale compacte (nom + couleur seulement) et détail homogène
    (mêmes six champs pour toute source) accessible sous la vue globale.

    Cible `assets/dashboard-v2.js` (`renderSources()`), le runtime actif —
    `dashboard.js` (v1) qu'il a remplacé a été retiré."""

    def _read(self, path):
        return open(path, encoding="utf-8").read()

    def test_vue_globale_reste_compacte_sans_metriques(self):
        js = self._read("assets/dashboard-v2.js")
        match = re.search(r'"#sources-leds"\)\.innerHTML = .*?;', js)
        assert match, "rendu de #sources-leds introuvable"
        compact_part = match.group(0)
        for forbidden in ("items_seen", "items_in_window", "latest_item"):
            assert forbidden not in compact_part

    def test_detail_accessible_sous_la_vue_globale_avec_les_six_champs(self):
        html = self._read("index.html")
        assert '<div id="sources-leds"' in html
        list_pos = html.index('id="sources-leds"')
        detail_pos = html.index('class="sources-detail"')
        assert detail_pos > list_pos, "le détail doit suivre la vue globale"
        assert "<summary>" in html

        js = self._read("assets/dashboard-v2.js")
        match = re.search(r'"#sources-detail-body"\)\.innerHTML = .*?;', js)
        assert match, "rendu de #sources-detail-body introuvable"
        body = match.group(0)
        for expected in (
            "sourceLabel(source.id)", "source.status", "formatDateTime(source.last_run)",
            "source.duration", "source.items_collected", "source.reason",
        ):
            assert expected in body

    def test_veille_llm_utilise_le_libelle_partage_dans_le_dashboard(self):
        """`VEILLE_LLM` s'affichait « veillellmReYt » dans app.js et « Veille IA »
        dans p2.js : deux noms pour la même source. Le libellé vient désormais
        d'une table unique (`config.SOURCE_LABELS`), publiée dans status.json et
        lue par le dashboard via `sourceLabel()` — jamais codée en dur ici."""
        js = self._read("assets/dashboard-v2.js")
        assert 'veillellmReYt' not in js
        assert '"VEILLE_LLM":' not in js
        from cyberwatch import config
        assert config.source_label("VEILLE_LLM") == config.SOURCE_LABELS["VEILLE_LLM"]
        assert config.source_label("VEILLE_LLM") != "VEILLE_LLM"
