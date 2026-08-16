"""Faits source (§13 METHODOLOGY.md) : extraction déterministe, offline,
jamais canonique. Un fait décrit ce qu'une source publie, jamais une
connaissance supposée sur l'organisation."""

from __future__ import annotations

import json

from cyberwatch import source_facts as sf
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.collectors.bonjourlafuite import parse_timeline
from cyberwatch.collectors.ransomware_live import _entry_from_record
from cyberwatch.collectors.veillellm import VeilleLlmCollector
from cyberwatch.collectors.base import Window
from cyberwatch.model import Item, SOURCE_FACT_COLUMNS


def make_item(source_id="FRENCHBREACHES", item_id="ITM-test"):
    return Item(Item_ID=item_id, Source_ID=source_id)


# --------------------------------------------------------------------------
# JSON déterministe
# --------------------------------------------------------------------------


class TestJson:
    def test_dumps_vide_donne_chaine_vide(self):
        assert sf._dumps_json([]) == ""
        assert sf._dumps_json({}) == ""
        assert sf._dumps_json(None) == ""

    def test_dumps_deterministe_cles_triees(self):
        first = sf._dumps_json({"b": 1, "a": 2})
        second = sf._dumps_json({"a": 2, "b": 1})
        assert first == second == '{"a":2,"b":1}'

    def test_dumps_sans_espace(self):
        assert sf._dumps_json(["x", "y"]) == '["x","y"]'

    def test_round_trip(self):
        payload = {"a": [1, 2, 3], "b": "texte"}
        assert sf._loads_json(sf._dumps_json(payload)) == payload

    def test_loads_chaine_vide_ou_invalide(self):
        assert sf._loads_json("") is None
        assert sf._loads_json("{invalide") is None


# --------------------------------------------------------------------------
# merge_source_facts
# --------------------------------------------------------------------------


class TestMergeSourceFacts:
    def test_unicite_item_id(self):
        existing = [{"Item_ID": "A", "Source_ID": "X"}]
        incoming = [{"Item_ID": "A", "Source_ID": "X", "Threat_Actor": "Y"}]
        merged = sf.merge_source_facts(existing, incoming)
        assert len(merged) == 1
        assert merged[0]["Threat_Actor"] == "Y"

    def test_incoming_ecrase_existing_sur_collision(self):
        existing = [{"Item_ID": "A", "Threat_Actor": "ancien"}]
        incoming = [{"Item_ID": "A", "Threat_Actor": "nouveau"}]
        merged = sf.merge_source_facts(existing, incoming)
        assert merged[0]["Threat_Actor"] == "nouveau"

    def test_ajoute_les_nouveaux_conserve_les_autres(self):
        existing = [{"Item_ID": "A"}, {"Item_ID": "B"}]
        incoming = [{"Item_ID": "C"}]
        merged = sf.merge_source_facts(existing, incoming)
        assert {row["Item_ID"] for row in merged} == {"A", "B", "C"}

    def test_idempotent(self):
        existing = [{"Item_ID": "A", "Threat_Actor": "X"}]
        incoming = [{"Item_ID": "B", "Threat_Actor": "Y"}]
        once = sf.merge_source_facts(existing, incoming)
        twice = sf.merge_source_facts(once, incoming)
        assert once == twice

    def test_ligne_sans_item_id_ignoree(self):
        merged = sf.merge_source_facts([], [{"Source_ID": "X"}])
        assert merged == []

    def test_tri_deterministe(self):
        merged = sf.merge_source_facts([], [{"Item_ID": "B"}, {"Item_ID": "A"}])
        assert [row["Item_ID"] for row in merged] == ["A", "B"]


# --------------------------------------------------------------------------
# Rétrocompatibilité RawEntry
# --------------------------------------------------------------------------


class TestRawEntryBackwardCompat:
    def test_source_metadata_par_defaut_vide(self):
        entry = RawEntry(title="X", url="https://example.test")
        assert entry.source_metadata == {}

    def test_construction_avec_metadata(self):
        entry = RawEntry(title="X", source_metadata={"k": "v"})
        assert entry.source_metadata == {"k": "v"}


# --------------------------------------------------------------------------
# extract_source_fact : source inconnue / item sans rien à extraire
# --------------------------------------------------------------------------


class TestDispatch:
    def test_source_non_reconnue_renvoie_none(self):
        item = make_item(source_id="AUTRE_SOURCE")
        entry = RawEntry(title="X", summary="rien à voir")
        spec = SourceSpec(source_id="AUTRE_SOURCE", layer="core", zone="France")
        assert sf.extract_source_fact(item, entry, spec) is None

    def test_entree_sans_rien_a_extraire_renvoie_none(self):
        item = make_item(source_id="FRENCHBREACHES")
        entry = RawEntry(title="Fuite chez Exemple", summary="")
        spec = SourceSpec(source_id="FRENCHBREACHES", layer="core", zone="France")
        assert sf.extract_source_fact(item, entry, spec) is None

    def test_toutes_les_colonnes_du_schema_presentes(self):
        item = make_item(source_id="FRENCHBREACHES")
        entry = RawEntry(
            title="Fuite chez Exemple",
            summary="Revendiquée par le groupe X, CVE-2026-11111 exploitée.",
        )
        spec = SourceSpec(source_id="FRENCHBREACHES", layer="core", zone="France")
        fact = sf.extract_source_fact(item, entry, spec)
        assert set(fact.keys()) == set(SOURCE_FACT_COLUMNS)


# --------------------------------------------------------------------------
# BONJOURLAFUITE
# --------------------------------------------------------------------------

BONJOUR_HTML = """
<html><body>
  <section>
    <p>10 août 2026</p>
    <h2>🟢 Intermarché</h2>
    <p>Via Twitter</p>
    <p>Données concernées : noms, emails, mots de passe hashés</p>
    <a href="https://example.test/intermarche">Source</a>
    <a href="https://example.test/intermarche-2">Source</a>
  </section>
</body></html>
"""


class TestBonjourLaFuite:
    SPEC = SourceSpec(
        source_id="BONJOURLAFUITE", layer="core", zone="France",
        start_url="https://bonjourlafuite.eu.org/", collector="bonjourlafuite",
        params={"title_is_organisation": True},
    )

    def _entry(self, html=BONJOUR_HTML):
        entries = parse_timeline(html, self.SPEC.start_url)
        return entries[0]

    def test_via_alimente_third_party(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        assert fact["Third_Party"] == "Twitter"

    def test_donnees_concernees_alimente_data_types(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        assert json.loads(fact["Data_Types_JSON"]) == [
            "noms", "emails", "mots de passe hashés",
        ]

    def test_toutes_les_urls_source_conservees(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        urls = json.loads(fact["Evidence_URLs_JSON"])
        assert urls == [
            "https://example.test/intermarche",
            "https://example.test/intermarche-2",
        ]

    def test_entry_url_reste_le_premier_lien(self):
        entry = self._entry()
        assert entry.url == "https://example.test/intermarche"

    def test_claim_status_raw_capture_sans_claim_status_canonique(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        assert fact["Claim_Status_Raw"] == "🟢"
        assert fact["Claim_Status"] == ""

    def test_bloc_sans_via_ni_donnees_concernees(self):
        html = """
        <p>9 août 2026</p><h2>Société Exemple</h2>
        <a href="/source-exemple">Source</a>
        """
        entries = parse_timeline(html, self.SPEC.start_url)
        entry = entries[0]
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        assert fact["Third_Party"] == ""
        assert fact["Data_Types_JSON"] == ""
        assert json.loads(fact["Evidence_URLs_JSON"]) == [
            "https://bonjourlafuite.eu.org/source-exemple"
        ]

    def test_aucune_requete_http_supplementaire(self):
        # Le parseur ne fait qu'analyser le HTML déjà téléchargé (source_facts
        # ne prend jamais `client`/`spec.start_url` en entrée réseau).
        entry = self._entry()
        assert sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC) is not None


# --------------------------------------------------------------------------
# FRENCHBREACHES
# --------------------------------------------------------------------------


class TestFrenchBreaches:
    SPEC = SourceSpec(source_id="FRENCHBREACHES", layer="core", zone="France")

    def test_quantite_avec_unite_reconnue(self):
        entry = RawEntry(
            title="Fuite chez Exemple SA",
            summary="La fuite expose 2,8 millions d'enregistrements clients.",
        )
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert fact["Affected_Count"] == "2800000"
        assert fact["Affected_Unit"] == "records"
        assert fact["Affected_Count_Raw"] == "2,8 millions d'enregistrements"

    def test_quantite_ambigue_laisse_champs_vides_sauf_raw(self):
        entry = RawEntry(
            title="Fuite chez Exemple SA",
            summary="Le préjudice est estimé à 2,8 millions d'euros.",
        )
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert fact["Affected_Count"] == ""
        assert fact["Affected_Unit"] == ""
        assert fact["Affected_Count_Raw"] == "2,8 millions d'euros"

    def test_cve_explicite(self):
        entry = RawEntry(
            title="Fuite chez Exemple SA",
            summary="La vulnérabilité CVE-2026-72898 a été exploitée.",
        )
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert json.loads(fact["Vulnerabilities_JSON"]) == ["CVE-2026-72898"]

    def test_acteur_et_tiers_explicites(self):
        entry = RawEntry(
            title="Fuite chez Exemple SA",
            summary=(
                "La fuite, revendiquée par le groupe ShinyHunters, "
                "provient via la plateforme BlgCloud."
            ),
        )
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert fact["Threat_Actor"] == "ShinyHunters"
        assert fact["Third_Party"] == "BlgCloud"

    def test_statut_non_confirme_distingue_de_confirme(self):
        entry = RawEntry(title="Fuite chez Exemple SA", summary="Non confirmée par la société.")
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert fact["Claim_Status"] == "unconfirmed"

    def test_pas_de_page_detail_chargee(self):
        # `entry.content` reste vide pour FrenchBreaches (feed.py ne le peuple
        # jamais) : l'extraction ne doit se fonder que sur summary/title.
        entry = RawEntry(title="Fuite chez Exemple", summary="2,8 millions d'enregistrements", content="")
        assert entry.content == ""
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert fact["Affected_Count"] == "2800000"


# --------------------------------------------------------------------------
# CYBERATTAQUE_ORG
# --------------------------------------------------------------------------


class TestCyberattaqueOrg:
    SPEC = SourceSpec(
        source_id="CYBERATTAQUE_ORG", layer="core", zone="France",
        params={"include_content": True},
    )

    def test_relation_explicite_prestataire_compromis(self):
        entry = RawEntry(
            title="Société Exemple victime d'une cyberattaque",
            summary="Le prestataire BlgCloud a été compromis, exposant les données.",
            content="Le groupe LockBit a revendiqué l'attaque.",
        )
        fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, self.SPEC)
        assert fact["Third_Party"] == "BlgCloud"
        assert fact["Threat_Actor"] == "LockBit"

    def test_simple_co_mention_ne_suffit_pas(self):
        entry = RawEntry(
            title="Société Exemple victime d'une cyberattaque",
            summary="La société travaille habituellement avec le prestataire BlgCloud.",
            content="",
        )
        fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, self.SPEC)
        assert fact is None or fact["Third_Party"] == ""

    def test_cve_et_cvss(self):
        entry = RawEntry(
            title="Société Exemple victime d'une cyberattaque",
            summary="",
            content="CVE-2026-72898 exploitée, score CVSS 9.8.",
        )
        fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, self.SPEC)
        assert json.loads(fact["Vulnerabilities_JSON"]) == ["CVE-2026-72898"]
        assert "9.8" in fact["CVSS_Raw"]

    def test_activity_description_peuplee(self):
        entry = RawEntry(
            title="Société Exemple victime d'une cyberattaque",
            summary="",
            content="Société Exemple est une entreprise spécialisée dans la vente de matériel médical.",
        )
        fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, self.SPEC)
        assert "vente de matériel médical" in fact["Activity_Description"]


# --------------------------------------------------------------------------
# RANSOMWARE_LIVE
# --------------------------------------------------------------------------


class TestRansomwareLive:
    SPEC = SourceSpec(
        source_id="RANSOMWARE_LIVE", layer="core", zone="Multi",
        location_rule="France métropolitaine",
    )

    def _entry(self, **overrides):
        record = {
            "victim": "Exemple SA",
            "discovered": "2026-08-10",
            "attackdate": "2026-08-01",
            "group": "LockBit",
            "country": "FR",
            "sector": "Santé",
            "website": "exemple.fr",
            "post_url": "https://leaksite.example/exemple-sa",
        }
        record.update(overrides)
        return _entry_from_record(record, self.SPEC, "FR")

    def test_groupe_devient_threat_actor(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), entry, self.SPEC)
        assert fact["Threat_Actor"] == "LockBit"

    def test_dates_distinctes_preservees(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), entry, self.SPEC)
        assert fact["Discovered_Date"] == "2026-08-10"
        assert fact["Attack_Date"] == "2026-08-01"

    def test_website_et_claim_url_distincts(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), entry, self.SPEC)
        assert fact["Victim_Website"] == "https://exemple.fr"
        urls = json.loads(fact["Evidence_URLs_JSON"])
        assert "https://exemple.fr" in urls
        assert "https://leaksite.example/exemple-sa" in urls

    def test_secteur_brut_preserve(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), entry, self.SPEC)
        assert fact["Source_Sector_Raw"] == "Santé"

    def test_published_url_sector_location_inchanges(self):
        # La sémantique historique de `RawEntry` (Item_ID en dépend) ne change
        # pas : seule `source_metadata` gagne les variantes perdues.
        entry = self._entry()
        assert entry.published == "2026-08-10"
        assert entry.url == "https://leaksite.example/exemple-sa"
        assert entry.sector == "Santé"


# --------------------------------------------------------------------------
# VEILLE_LLM
# --------------------------------------------------------------------------


class TestVeilleLlm:
    SPEC = SourceSpec(
        source_id="VEILLE_LLM", layer="regional_watch", zone="La Réunion / Mayotte",
        start_url="https://example.test/snapshot.json", collector="veillellm",
        location_rule="Inconnu",
        params={"path": "sources/veillellm/cyberattaques_reunion_mayotte_2026.json"},
    )

    def _entries(self):
        result = VeilleLlmCollector().collect(None, self.SPEC, Window("2000-01-01", "2030-01-01"))
        return result.entries

    def test_acteur_localisation_fine_score_impact_sources_evolution(self):
        entries = self._entries()
        assert entries
        found = False
        for entry in entries:
            fact = sf.extract_source_fact(make_item("VEILLE_LLM"), entry, self.SPEC)
            if fact is None:
                continue
            if fact["Fine_Location"] and fact["Evolution"]:
                found = True
                assert fact["Fine_Location"] != entry.location  # fine != territoire
                assert fact["Threat_Actor"]
                assert fact["Cyberattack_Score"]
                assert fact["Impact"]
                assert fact["Evidence_URLs_JSON"]
                break
        assert found, "aucun record du snapshot réel n'a produit de fait complet"

    def test_fine_location_distincte_de_location_historique(self):
        entries = self._entries()
        entry = next(e for e in entries if e.source_metadata.get("localisation"))
        fact = sf.extract_source_fact(make_item("VEILLE_LLM"), entry, self.SPEC)
        # Comportement historique inchangé : `entry.location` reste le
        # territoire, jamais écrasé par la localisation précise.
        assert entry.location != fact["Fine_Location"] or entry.location == ""

    def test_aucun_second_appel_llm(self):
        # `source_facts.py` n'importe jamais `ai.py`.
        import cyberwatch.source_facts as module
        assert "ai" not in module.__dict__ or module.__dict__["ai"] is None
