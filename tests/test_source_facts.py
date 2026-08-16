"""Faits source (§13) : extraction déterministe, offline et non canonique."""
from __future__ import annotations

import json

from cyberwatch import source_facts as sf
from cyberwatch.collectors.base import RawEntry, SourceSpec, Window
from cyberwatch.collectors.bonjourlafuite import parse_timeline
from cyberwatch.collectors.ransomware_live import _entry_from_record
from cyberwatch.collectors.veillellm import VeilleLlmCollector
from cyberwatch.model import Item, SOURCE_FACT_COLUMNS


def make_item(source_id="FRENCHBREACHES", item_id="ITM-test"):
    return Item(Item_ID=item_id, Source_ID=source_id)


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
        assert sf.merge_source_facts([], [{"Source_ID": "X"}]) == []

    def test_tri_deterministe(self):
        merged = sf.merge_source_facts([], [{"Item_ID": "B"}, {"Item_ID": "A"}])
        assert [row["Item_ID"] for row in merged] == ["A", "B"]


class TestRawEntryBackwardCompat:
    def test_source_metadata_par_defaut_vide(self):
        assert RawEntry(title="X", url="https://example.test").source_metadata == {}

    def test_construction_avec_metadata(self):
        entry = RawEntry(title="X", source_metadata={"k": "v"})
        assert entry.source_metadata == {"k": "v"}


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

    def test_erreur_extracteur_est_non_bloquante(self):
        original = sf._EXTRACTORS["FRENCHBREACHES"]
        sf._EXTRACTORS["FRENCHBREACHES"] = lambda *_args: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            fact = sf.extract_source_fact(
                make_item(), RawEntry(title="X"),
                SourceSpec(source_id="FRENCHBREACHES", layer="core", zone="France"),
            )
            assert fact is None
        finally:
            sf._EXTRACTORS["FRENCHBREACHES"] = original

    def test_version_extracteur_v2(self):
        assert sf.SOURCE_FACTS_VERSION == "2"


BONJOUR_HTML = """
<html><body><section>
  <p>10 août 2026</p>
  <h2>🟢 Intermarché</h2>
  <p>Via Twitter</p>
  <p>Données concernées : noms, emails, mots de passe hashés</p>
  <a href="https://example.test/intermarche">Source</a>
  <a href="https://example.test/intermarche-2">Source</a>
</section></body></html>
"""


class TestBonjourLaFuite:
    SPEC = SourceSpec(
        source_id="BONJOURLAFUITE", layer="core", zone="France",
        start_url="https://bonjourlafuite.eu.org/", collector="bonjourlafuite",
        params={"title_is_organisation": True},
    )

    def _entry(self, html=BONJOUR_HTML):
        return parse_timeline(html, self.SPEC.start_url)[0]

    def test_via_reste_provenance_brute(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        assert entry.source_metadata["via_raw"] == "Twitter"
        assert fact["Third_Party"] == ""

    def test_donnees_concernees_alimente_data_types(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        assert json.loads(fact["Data_Types_JSON"]) == ["noms", "emails", "mots de passe hashés"]

    def test_donnees_concernees_fragmentee(self):
        html = """
        <p>10 août 2026</p><h2>🟢 Exemple</h2>
        <p><strong>Données concernées :</strong></p>
        <p>Noms, emails, téléphones</p>
        <a href="/preuve">Source</a>
        """
        entry = self._entry(html)
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        assert entry.source_metadata["data_types_raw"] == "Noms, emails, téléphones"
        assert json.loads(fact["Data_Types_JSON"]) == ["Noms", "emails", "téléphones"]

    def test_via_fragmente(self):
        html = """
        <p>10 août 2026</p><h2>Exemple</h2>
        <p><strong>Via :</strong></p><p>Telegram</p>
        <a href="/preuve">Source</a>
        """
        entry = self._entry(html)
        assert entry.source_metadata["via_raw"] == "Telegram"

    def test_toutes_les_urls_source_conservees(self):
        entry = self._entry()
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        assert json.loads(fact["Evidence_URLs_JSON"]) == [
            "https://example.test/intermarche", "https://example.test/intermarche-2"
        ]

    def test_entry_url_reste_le_premier_lien(self):
        assert self._entry().url == "https://example.test/intermarche"

    def test_claim_status_raw_capture_sans_claim_status_canonique(self):
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), self._entry(), self.SPEC)
        assert fact["Claim_Status_Raw"] == "🟢"
        assert fact["Claim_Status"] == ""

    def test_bloc_sans_via_ni_donnees_concernees(self):
        html = '<p>9 août 2026</p><h2>Société Exemple</h2><a href="/source-exemple">Source</a>'
        entry = self._entry(html)
        fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, self.SPEC)
        assert fact["Third_Party"] == ""
        assert fact["Data_Types_JSON"] == ""
        assert json.loads(fact["Evidence_URLs_JSON"]) == ["https://bonjourlafuite.eu.org/source-exemple"]


class TestFrenchBreaches:
    SPEC = SourceSpec(source_id="FRENCHBREACHES", layer="core", zone="France")

    def test_quantite_avec_unite_reconnue(self):
        entry = RawEntry(title="Fuite chez Exemple SA", summary="La fuite expose 2,8 millions d'enregistrements clients.")
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert fact["Affected_Count"] == "2800000"
        assert fact["Affected_Unit"] == "records"
        assert fact["Affected_Count_Raw"] == "2,8 millions d'enregistrements"

    def test_quantite_ambigue_est_totalement_ignoree(self):
        entry = RawEntry(title="Fuite", summary="Le préjudice est estimé à 2,8 millions d'euros.")
        assert sf.extract_source_fact(make_item(), entry, self.SPEC) is None

    def test_faux_comptages_reels_sont_ignores(self):
        for text in ("1er", "27 juillet", "25 ans", "40 devient", "5doigts", "8h", "00h", "2019 diffusée"):
            assert sf._parse_count_phrase(text) == ("", "", "")

    def test_volume_ne_devient_pas_affected_count(self):
        for text in ("13,8 Go", "3,4 Go", "261,4 Mo"):
            assert sf._parse_count_phrase(text) == ("", "", "")
            assert sf._extract_volume(text) == text

    def test_cve_explicite(self):
        fact = sf.extract_source_fact(make_item(), RawEntry(title="Fuite", summary="CVE-2026-72898 exploitée."), self.SPEC)
        assert json.loads(fact["Vulnerabilities_JSON"]) == ["CVE-2026-72898"]

    def test_acteur_et_tiers_explicites(self):
        entry = RawEntry(
            title="Fuite chez Exemple SA", organisation="Exemple SA",
            summary="La fuite, revendiquée par le groupe ShinyHunters, provient via la plateforme BlgCloud.",
        )
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert fact["Threat_Actor"] == "ShinyHunters"
        assert fact["Third_Party"] == "BlgCloud"

    def test_faux_acteurs_reels_sont_rejetes(self):
        cases = (
            ("ENGIE", "Le groupe ENGIE publie un communiqué sur la fuite."),
            ("Cloué", "Groupe Cloué est cité dans l'article."),
            ("Exemple", "Fuite revendiquée par un."),
            ("Exemple", "Incident revendiqué par le hacker."),
            # §stabilisation pré-release : reproduction exacte du cas signalé
            # — un mot générique de menace n'est jamais un nom d'acteur.
            ("Exemple", "La fuite a été revendiquée par le groupe Ransomware."),
            ("Exemple", "L'attaque a été revendiquée par le groupe Rançongiciel."),
        )
        for organisation, summary in cases:
            entry = RawEntry(title=organisation, organisation=organisation, summary=summary)
            fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
            assert fact is None or fact["Threat_Actor"] == ""

    def test_activity_doit_nommer_la_victime(self):
        entry = RawEntry(
            title="Fédération X", organisation="Fédération X",
            summary="Un forum spécialisé dans les fuites de données revendique Fédération X.",
        )
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert fact is None or fact["Activity_Description"] == ""

    def test_activity_victime_explicitement_ancree(self):
        entry = RawEntry(
            title="Scalingo", organisation="Scalingo",
            summary="Scalingo est une entreprise spécialisée dans l'hébergement cloud.",
        )
        fact = sf.extract_source_fact(make_item(), entry, self.SPEC)
        assert "hébergement cloud" in fact["Activity_Description"]

    def test_statut_non_confirme_distingue_de_confirme(self):
        fact = sf.extract_source_fact(make_item(), RawEntry(title="Fuite", summary="Non confirmée par la société."), self.SPEC)
        assert fact["Claim_Status"] == "unconfirmed"


class TestCyberattaqueOrg:
    SPEC = SourceSpec(source_id="CYBERATTAQUE_ORG", layer="core", zone="France", params={"include_content": True})

    def test_relation_explicite_prestataire_compromis(self):
        entry = RawEntry(
            title="Société Exemple victime d'une cyberattaque", organisation="Société Exemple",
            summary="Le prestataire BlgCloud a été compromis, exposant les données.",
            content="Le groupe LockBit a revendiqué l'attaque.",
        )
        fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, self.SPEC)
        assert fact["Third_Party"] == "BlgCloud"
        assert fact["Threat_Actor"] == "LockBit"

    def test_acteur_generique_rancongiciel_nest_jamais_un_acteur(self):
        entry = RawEntry(
            title="Société Exemple", organisation="Société Exemple",
            content="Le groupe Rançongiciel a revendiqué l'attaque.",
        )
        fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, self.SPEC)
        assert fact is None or fact["Threat_Actor"] == ""

    def test_simple_co_mention_ne_suffit_pas(self):
        entry = RawEntry(title="Société Exemple", organisation="Société Exemple", summary="La société travaille avec le prestataire BlgCloud.")
        fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, self.SPEC)
        assert fact is None or fact["Third_Party"] == ""

    def test_cve_et_cvss(self):
        entry = RawEntry(title="Société Exemple", content="CVE-2026-72898 exploitée, score CVSS 9.8.")
        fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, self.SPEC)
        assert json.loads(fact["Vulnerabilities_JSON"]) == ["CVE-2026-72898"]
        assert "9.8" in fact["CVSS_Raw"]

    def test_activity_description_peuplee_si_victime_nommee(self):
        entry = RawEntry(
            title="Société Exemple", organisation="Société Exemple",
            content="Société Exemple est une entreprise spécialisée dans la vente de matériel médical.",
        )
        fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, self.SPEC)
        assert "vente de matériel médical" in fact["Activity_Description"]


class TestRansomwareLive:
    SPEC = SourceSpec(source_id="RANSOMWARE_LIVE", layer="core", zone="Multi", location_rule="France métropolitaine")

    def _entry(self, **overrides):
        record = {
            "victim": "Exemple SA", "discovered": "2026-08-10", "attackdate": "2026-08-01",
            "group": "LockBit", "country": "FR", "sector": "Santé", "website": "exemple.fr",
            "post_url": "https://leaksite.example/exemple-sa",
        }
        record.update(overrides)
        return _entry_from_record(record, self.SPEC, "FR")

    def test_groupe_devient_threat_actor(self):
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), self._entry(), self.SPEC)
        assert fact["Threat_Actor"] == "LockBit"

    def test_groupe_generique_ransomware_nest_jamais_un_acteur(self):
        entry = self._entry(group="Ransomware")
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), entry, self.SPEC)
        assert fact is None or fact["Threat_Actor"] == ""

    def test_dates_distinctes_preservees(self):
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), self._entry(), self.SPEC)
        assert fact["Discovered_Date"] == "2026-08-10"
        assert fact["Attack_Date"] == "2026-08-01"

    def test_published_date_ne_devient_pas_attack_date(self):
        entry = self._entry(attackdate="", publishedDate="2026-08-02")
        assert entry.source_metadata["attackdate"] == ""
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), entry, self.SPEC)
        assert fact["Attack_Date"] == ""

    def test_website_et_preuve_sont_separes(self):
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), self._entry(), self.SPEC)
        assert fact["Victim_Website"] == "https://exemple.fr"
        assert json.loads(fact["Evidence_URLs_JSON"]) == ["https://leaksite.example/exemple-sa"]

    def test_secteur_brut_preserve(self):
        fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), self._entry(), self.SPEC)
        assert fact["Source_Sector_Raw"] == "Santé"

    def test_published_url_sector_location_inchanges(self):
        entry = self._entry()
        assert entry.published == "2026-08-10"
        assert entry.url == "https://leaksite.example/exemple-sa"
        assert entry.sector == "Santé"


class TestVeilleLlm:
    SPEC = SourceSpec(
        source_id="VEILLE_LLM", layer="regional_watch", zone="La Réunion / Mayotte",
        start_url="https://example.test/snapshot.json", collector="veillellm", location_rule="Inconnu",
        params={"path": "sources/veillellm/cyberattaques_reunion_mayotte_2026.json"},
    )

    def _entries(self):
        result = VeilleLlmCollector().collect(None, self.SPEC, Window("2000-01-01", "2030-01-01"))
        return result.entries

    def test_acteur_localisation_fine_score_impact_sources_evolution(self):
        for entry in self._entries():
            fact = sf.extract_source_fact(make_item("VEILLE_LLM"), entry, self.SPEC)
            if fact and fact["Fine_Location"] and fact["Evolution"] and fact["Threat_Actor"]:
                assert fact["Cyberattack_Score"]
                assert fact["Impact"]
                assert fact["Evidence_URLs_JSON"]
                return
        raise AssertionError("aucun record structuré avec acteur identifié n'a produit de fait complet")

    def test_sentinetelles_acteur_non_identifiees_sont_vides(self):
        for actor in ("Inconnu", "Non identifié", "Non identifié publiquement", "Ransomware", "Rançongiciel"):
            entry = RawEntry(
                title="X", organisation="X",
                source_metadata={"acteur": actor, "statut": "signalé"},
            )
            fact = sf.extract_source_fact(make_item("VEILLE_LLM"), entry, self.SPEC)
            assert fact["Threat_Actor"] == ""
            assert actor in fact["Source_Metadata_JSON"]

    def test_fine_location_distincte_de_location_historique(self):
        entry = next(e for e in self._entries() if e.source_metadata.get("localisation"))
        fact = sf.extract_source_fact(make_item("VEILLE_LLM"), entry, self.SPEC)
        assert entry.location != fact["Fine_Location"] or entry.location == ""

    def test_aucun_second_appel_llm(self):
        import cyberwatch.source_facts as module
        assert "ai" not in module.__dict__ or module.__dict__["ai"] is None
