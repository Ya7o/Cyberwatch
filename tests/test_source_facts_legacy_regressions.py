"""Régressions historiques conservées lors du passage source_facts V2 -> V3."""
from __future__ import annotations

import json

from cyberwatch import source_facts as sf
from cyberwatch.collectors.base import RawEntry, SourceSpec, Window
from cyberwatch.collectors.bonjourlafuite import parse_timeline
from cyberwatch.collectors.ransomware_live import _entry_from_record
from cyberwatch.collectors.veillellm import VeilleLlmCollector
from cyberwatch.model import Item


def item(source="FRENCHBREACHES", org="Exemple"):
    return Item(Item_ID="ITM-legacy", Source_ID=source, Organisation_Raw=org)


def source(source_id, **params):
    return SourceSpec(source_id=source_id, layer="core", zone="France", params=params)


def test_json_vide_et_invalide():
    assert sf._dumps_json({}) == ""
    assert sf._dumps_json(None) == ""
    assert sf._loads_json("") is None
    assert sf._loads_json("{bad") is None


def test_json_liste_sans_espaces():
    assert sf._dumps_json(["x", "y"]) == '["x","y"]'


def test_merge_ignore_ligne_sans_item_id():
    assert sf.merge_source_facts([], [{"Source_ID": "X"}]) == []


def test_merge_conserve_autres_items():
    rows = sf.merge_source_facts([{"Item_ID": "A"}, {"Item_ID": "B"}], [{"Item_ID": "C"}])
    assert {row["Item_ID"] for row in rows} == {"A", "B", "C"}


def test_raw_entry_metadata_par_defaut_et_explicit():
    assert RawEntry(title="X").source_metadata == {}
    assert RawEntry(title="X", source_metadata={"k": "v"}).source_metadata == {"k": "v"}


def test_french_entree_sans_fait_renvoie_none():
    assert sf.extract_source_fact(item(), RawEntry(title="Exemple"), source("FRENCHBREACHES")) is None


def _blf(html: str):
    spec = SourceSpec(
        source_id="BONJOURLAFUITE", layer="core", zone="France",
        start_url="https://bonjourlafuite.eu.org/", params={"title_is_organisation": True},
    )
    return spec, parse_timeline(html, spec.start_url)[0]


def test_blf_format_une_ligne_decoupe_types():
    spec, entry = _blf('''<p>10 août 2026</p><h2>🟢 Exemple</h2>
    <p>Données concernées : noms, emails, mots de passe hashés</p><a href="/p">Source</a>''')
    fact = sf.extract_source_fact(item("BONJOURLAFUITE"), entry, spec)
    assert json.loads(fact["Data_Types_JSON"]) == ["noms", "emails", "mots de passe hashés"]


def test_blf_donnees_fragmentees_ancien_format():
    spec, entry = _blf('''<p>10 août 2026</p><h2>🟢 Exemple</h2>
    <p><strong>Données concernées :</strong></p><p>Noms, emails, téléphones</p><a href="/p">Source</a>''')
    fact = sf.extract_source_fact(item("BONJOURLAFUITE"), entry, spec)
    assert entry.source_metadata["data_types_raw"] == "Noms, emails, téléphones"
    assert json.loads(fact["Data_Types_JSON"]) == ["Noms", "emails", "téléphones"]


def test_blf_via_fragmente_reste_metadata():
    spec, entry = _blf('''<p>10 août 2026</p><h2>Exemple</h2>
    <p><strong>Via :</strong></p><p>Telegram</p><a href="/p">Source</a>''')
    assert entry.source_metadata["via_raw"] == "Telegram"
    fact = sf.extract_source_fact(item("BONJOURLAFUITE"), entry, spec)
    assert fact["Third_Party"] == ""


def test_blf_toutes_urls_et_premiere_url_item():
    spec, entry = _blf('''<p>10 août 2026</p><h2>🟢 Exemple</h2>
    <a href="https://example.test/a">Source</a><a href="https://example.test/b">Source</a>''')
    fact = sf.extract_source_fact(item("BONJOURLAFUITE"), entry, spec)
    assert entry.url == "https://example.test/a"
    assert json.loads(fact["Evidence_URLs_JSON"]) == ["https://example.test/a", "https://example.test/b"]


def test_blf_sans_donnees_conserve_preuve():
    spec, entry = _blf('<p>9 août 2026</p><h2>Exemple</h2><a href="/preuve">Source</a>')
    fact = sf.extract_source_fact(item("BONJOURLAFUITE"), entry, spec)
    assert fact["Data_Types_JSON"] == ""
    assert json.loads(fact["Evidence_URLs_JSON"]) == ["https://bonjourlafuite.eu.org/preuve"]


def test_french_quantite_enregistrements_exacte():
    fact = sf.extract_source_fact(
        item(), RawEntry(title="Exemple", summary="La fuite expose 2,8 millions d'enregistrements clients."),
        source("FRENCHBREACHES"),
    )
    assert (fact["Affected_Count"], fact["Affected_Unit"]) == ("2800000", "records")
    assert fact["Affected_Count_Raw"] == "2,8 millions d'enregistrements"


def test_french_euros_ne_deviennent_pas_compteur():
    entry = RawEntry(title="Exemple", summary="Le préjudice est estimé à 2,8 millions d'euros.")
    assert sf.extract_source_fact(item(), entry, source("FRENCHBREACHES")) is None


def test_french_cve_explicite():
    fact = sf.extract_source_fact(item(), RawEntry(title="X", summary="CVE-2026-72898 exploitée."), source("FRENCHBREACHES"))
    assert json.loads(fact["Vulnerabilities_JSON"]) == ["CVE-2026-72898"]


def test_french_non_confirmee_prioritaire_sur_confirmee():
    fact = sf.extract_source_fact(item(), RawEntry(title="X", summary="Non confirmée par la société."), source("FRENCHBREACHES"))
    assert fact["Claim_Status"] == "unconfirmed"


def test_cyber_acteur_generique_rejete():
    entry = RawEntry(title="Exemple", organisation="Exemple", content="Le groupe Rançongiciel a revendiqué l'attaque.")
    fact = sf.extract_source_fact(item("CYBERATTAQUE_ORG"), entry, source("CYBERATTAQUE_ORG", include_content=True))
    assert fact is None or fact["Threat_Actor"] == ""


def test_cyber_simple_mention_prestataire_ne_suffit_pas():
    entry = RawEntry(title="Exemple", organisation="Exemple", summary="La société travaille avec le prestataire BlgCloud.")
    fact = sf.extract_source_fact(item("CYBERATTAQUE_ORG"), entry, source("CYBERATTAQUE_ORG", include_content=True))
    assert fact is None or fact["Third_Party"] == ""


def test_cyber_cve_et_cvss():
    entry = RawEntry(title="Exemple", content="CVE-2026-72898 exploitée, score CVSS 9.8.")
    fact = sf.extract_source_fact(item("CYBERATTAQUE_ORG"), entry, source("CYBERATTAQUE_ORG", include_content=True))
    assert json.loads(fact["Vulnerabilities_JSON"]) == ["CVE-2026-72898"]
    assert "9.8" in fact["CVSS_Raw"]


def test_cyber_activity_victime_ancree():
    entry = RawEntry(
        title="Exemple", organisation="Exemple",
        content="Exemple est une entreprise spécialisée dans la vente de matériel médical.",
    )
    fact = sf.extract_source_fact(item("CYBERATTAQUE_ORG", "Exemple"), entry, source("CYBERATTAQUE_ORG", include_content=True))
    assert "vente de matériel médical" in fact["Activity_Description"]


def _ransom(**overrides):
    spec = SourceSpec(source_id="RANSOMWARE_LIVE", layer="core", zone="Multi")
    record = {
        "victim": "Exemple SA", "discovered": "2026-08-10", "attackdate": "2026-08-01",
        "group": "LockBit", "country": "FR", "sector": "Santé", "website": "exemple.fr",
        "post_url": "https://leaksite.example/exemple",
    }
    record.update(overrides)
    return spec, _entry_from_record(record, spec, "FR")


def test_ransom_published_date_ne_devient_pas_attack_date():
    spec, entry = _ransom(attackdate="", publishedDate="2026-08-02")
    assert entry.source_metadata["attackdate"] == ""
    fact = sf.extract_source_fact(item("RANSOMWARE_LIVE"), entry, spec)
    assert fact["Attack_Date"] == ""


def test_ransom_site_victime_et_preuve_separes():
    spec, entry = _ransom()
    fact = sf.extract_source_fact(item("RANSOMWARE_LIVE"), entry, spec)
    assert fact["Victim_Website"] == "https://exemple.fr"
    assert json.loads(fact["Evidence_URLs_JSON"]) == ["https://leaksite.example/exemple"]


def test_ransom_entry_preserve_url_secteur_date():
    spec, entry = _ransom()
    assert entry.published == "2026-08-10"
    assert entry.url == "https://leaksite.example/exemple"
    assert entry.sector == "Santé"
    fact = sf.extract_source_fact(item("RANSOMWARE_LIVE"), entry, spec)
    assert fact["Source_Sector_Raw"] == "Santé"


def _veille():
    spec = SourceSpec(
        source_id="VEILLE_LLM", layer="regional_watch", zone="La Réunion / Mayotte",
        start_url="https://example.test/snapshot.json", collector="veillellm", location_rule="Inconnu",
        params={"path": "sources/veillellm/cyberattaques_reunion_mayotte_2026.json"},
    )
    return spec, VeilleLlmCollector().collect(None, spec, Window("2000-01-01", "2030-01-01")).entries


def test_veille_sentinetelles_acteur_vides():
    spec, _ = _veille()
    for actor in ("Inconnu", "Non identifié", "Non identifié publiquement", "Ransomware", "Rançongiciel"):
        entry = RawEntry(title="X", organisation="X", source_metadata={"acteur": actor, "statut": "signalé"})
        fact = sf.extract_source_fact(item("VEILLE_LLM", "X"), entry, spec)
        assert fact["Threat_Actor"] == ""
        assert actor in fact["Source_Metadata_JSON"]


def test_veille_fine_location_et_donnees_analytiques():
    spec, entries = _veille()
    found = False
    for entry in entries:
        fact = sf.extract_source_fact(item("VEILLE_LLM"), entry, spec)
        if fact and fact["Fine_Location"] and fact["Impact"]:
            assert fact["Cyberattack_Score"]
            assert fact["Summary"]
            assert fact["Evidence_URLs_JSON"]
            found = True
            break
    assert found
