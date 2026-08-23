"""Faits source : extracteurs V4, validation et non-régression."""
from __future__ import annotations

import json

from cyberwatch import source_facts as sf
from cyberwatch.collectors.base import RawEntry, SourceSpec, Window
from cyberwatch.collectors.bonjourlafuite import parse_timeline
from cyberwatch.collectors.ransomware_live import _entry_from_record
from cyberwatch.collectors.veillellm import VeilleLlmCollector
from cyberwatch.model import Item, SOURCE_FACT_COLUMNS


def make_item(source_id="FRENCHBREACHES", item_id="ITM-test", organisation="Exemple SA"):
    return Item(Item_ID=item_id, Source_ID=source_id, Organisation_Raw=organisation)


def spec(source_id: str, **params):
    return SourceSpec(source_id=source_id, layer="core", zone="France", params=params)


def test_json_canonique_et_round_trip():
    assert sf._dumps_json([]) == ""
    assert sf._dumps_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    payload = {"a": [1, 2], "b": "texte"}
    assert sf._loads_json(sf._dumps_json(payload)) == payload
    assert sf._loads_json("{invalide") is None


def test_merge_source_facts_idempotent_et_trie():
    existing = [{"Item_ID": "B", "Threat_Actor": "ancien"}, {"Item_ID": "A"}]
    incoming = [{"Item_ID": "B", "Threat_Actor": "nouveau"}, {"Item_ID": "C"}]
    once = sf.merge_source_facts(existing, incoming)
    twice = sf.merge_source_facts(once, incoming)
    assert once == twice
    assert [row["Item_ID"] for row in once] == ["A", "B", "C"]
    assert once[1]["Threat_Actor"] == "nouveau"


def test_merge_source_facts_conserve_les_metadonnees_riches_absentes_du_refresh():
    existing = [{
        "Item_ID": "ITM-a",
        "Source_Metadata_JSON": sf._dumps_json({
            "_source_facts_content_hash": "old",
            "rich_facts": {"claims": [{"value": "fait documenté"}]},
        }),
    }]
    incoming = [{
        "Item_ID": "ITM-a",
        "Source_Metadata_JSON": sf._dumps_json({"_source_facts_content_hash": "new"}),
    }]
    merged = sf.merge_source_facts(existing, incoming)[0]
    metadata = sf._loads_json(merged["Source_Metadata_JSON"])
    assert metadata["_source_facts_content_hash"] == "new"
    assert metadata["rich_facts"]["claims"][0]["value"] == "fait documenté"


def test_dispatch_et_schema_et_version_v4():
    unknown = spec("AUTRE_SOURCE")
    assert sf.extract_source_fact(make_item("AUTRE_SOURCE"), RawEntry(title="X"), unknown) is None
    entry = RawEntry(title="Exemple", summary="Revendiquée par le groupe X, CVE-2026-11111 exploitée.")
    fact = sf.extract_source_fact(make_item(), entry, spec("FRENCHBREACHES"))
    assert set(fact) == set(SOURCE_FACT_COLUMNS)
    assert fact["Extraction_Version"] == "4"
    assert sf.SOURCE_FACTS_VERSION == "4"
    assert "Initial_Access" in SOURCE_FACT_COLUMNS
    assert "Attack_Flow_JSON" in SOURCE_FACT_COLUMNS


def test_erreur_extracteur_ne_bloque_jamais():
    original = sf._EXTRACTORS["FRENCHBREACHES"]
    sf._EXTRACTORS["FRENCHBREACHES"] = lambda *_args: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        assert sf.extract_source_fact(make_item(), RawEntry(title="X"), spec("FRENCHBREACHES")) is None
    finally:
        sf._EXTRACTORS["FRENCHBREACHES"] = original


def test_count_ignore_les_faux_positifs_et_continue_apres_eux():
    for text in ("1er", "27 juillet", "25 ans", "40 devient", "5doigts", "8h", "00h", "2019 diffusée"):
        assert sf._parse_count_phrase(text) == ("", "", "")
    assert sf._parse_count_phrase("le 27 juillet, 3 millions de personnes sont concernées")[:2] == ("3000000", "people")
    assert sf._parse_count_phrase("1 023 victimes")[:2] == ("1023", "people")


def test_volume_ne_devient_jamais_compteur():
    for text in ("13,8 Go", "3,4 Go", "261,4 Mo"):
        assert sf._parse_count_phrase(text) == ("", "", "")
        assert sf._extract_volume(text) == text


BONJOUR_HTML = """
<p>10 août 2026</p>
<h2>🟢 Bloctel</h2>
<p>3 millions de personnes</p>
<p>Via Twitter</p>
<p><strong>Données concernées :</strong></p>
<p>Numéro de téléphone</p>
<a href="https://example.test/bloctel">Source</a>
"""


def test_bonjourlafuite_statut_donnees_volume_et_via():
    entry = parse_timeline(BONJOUR_HTML, "https://bonjourlafuite.eu.org/")[0]
    blf = SourceSpec(
        source_id="BONJOURLAFUITE", layer="core", zone="France",
        start_url="https://bonjourlafuite.eu.org/", collector="bonjourlafuite",
        params={"title_is_organisation": True},
    )
    fact = sf.extract_source_fact(make_item("BONJOURLAFUITE", organisation="Bloctel"), entry, blf)
    assert fact["Claim_Status_Raw"] == "🟢"
    assert fact["Claim_Status"] == "confirmed"
    assert fact["Affected_Count"] == "3000000"
    assert fact["Affected_Unit"] == "people"
    assert json.loads(fact["Data_Types_JSON"]) == ["Numéro de téléphone"]
    assert entry.source_metadata["via_raw"] == "Twitter"
    assert fact["Third_Party"] == ""


def test_bonjourlafuite_plusieurs_bulles_preservees():
    html = """
    <p>10 août 2026</p><h2>🟠 Exemple</h2>
    <p><strong>Données concernées :</strong></p>
    <span>Nom et prénom</span><span>Adresse e-mail</span><span>Mot de passe hashé</span>
    <a href="/preuve">Source</a>
    """
    entry = parse_timeline(html, "https://bonjourlafuite.eu.org/")[0]
    blf = SourceSpec(source_id="BONJOURLAFUITE", layer="core", zone="France", start_url="https://bonjourlafuite.eu.org/")
    fact = sf.extract_source_fact(make_item("BONJOURLAFUITE"), entry, blf)
    assert fact["Claim_Status"] == "claimed"
    assert json.loads(fact["Data_Types_JSON"]) == ["Nom et prénom", "Adresse e-mail", "Mot de passe hashé"]


FB = spec("FRENCHBREACHES")


def test_frenchbreaches_natif_structuré_gagne_sur_le_reste():
    entry = RawEntry(
        title="Air Austral", organisation="Air Austral",
        summary="Alerte de fuite.",
        content="02/06/2026 Revendiquée (crédible) 1 023 victimes Secteur Transport Fuite de données.",
    )
    fact = sf.extract_source_fact(make_item(organisation="Air Austral"), entry, FB)
    assert fact["Claim_Status"] == "claimed"
    assert fact["Affected_Count"] == "1023"
    assert fact["Affected_Unit"] == "people"
    assert fact["Source_Sector_Raw"] == "Transport"


def test_frenchbreaches_actor_tiers_cve_et_activity_fallback():
    entry = RawEntry(
        title="Scalingo", organisation="Scalingo",
        summary=("Scalingo est une entreprise spécialisée dans l'hébergement cloud. "
                 "La fuite est revendiquée par le groupe ShinyHunters via la plateforme BlgCloud. "
                 "CVE-2026-72898 exploitée, CVSS 10/10."),
    )
    fact = sf.extract_source_fact(make_item(organisation="Scalingo"), entry, FB)
    assert fact["Threat_Actor"] == "ShinyHunters"
    assert fact["Third_Party"] == "BlgCloud"
    assert json.loads(fact["Vulnerabilities_JSON"]) == ["CVE-2026-72898"]
    assert "10" in fact["CVSS_Raw"]
    assert "hébergement cloud" in fact["Activity_Description"]


def test_frenchbreaches_faux_acteurs_rejetes():
    cases = (
        ("ENGIE", "Le groupe ENGIE publie un communiqué."),
        ("Cloué", "Groupe Cloué est cité."),
        ("Exemple", "La fuite est revendiquée par un."),
        ("Exemple", "La fuite est revendiquée par le groupe Ransomware."),
    )
    for organisation, summary in cases:
        fact = sf.extract_source_fact(
            make_item(organisation=organisation),
            RawEntry(title=organisation, organisation=organisation, summary=summary),
            FB,
        )
        assert fact is None or fact["Threat_Actor"] == ""


def test_activity_non_victime_rejetee():
    entry = RawEntry(
        title="Fédération X", organisation="Fédération X",
        summary="Un forum spécialisé dans les fuites de données revendique Fédération X.",
    )
    fact = sf.extract_source_fact(make_item(organisation="Fédération X"), entry, FB)
    assert fact is None or fact["Activity_Description"] == ""


CO = spec("CYBERATTAQUE_ORG", include_content=True)


def test_cyberattaque_fallback_deterministe_reste_disponible_sans_llm():
    entry = RawEntry(
        title="Société Exemple victime d'une cyberattaque", organisation="Société Exemple",
        summary="Le prestataire BlgCloud a été compromis, exposant les données.",
        content="Le groupe LockBit a revendiqué l'attaque. 138 000 personnes sont concernées. CVE-2026-72898, CVSS 9.8.",
    )
    fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG", organisation="Société Exemple"), entry, CO)
    assert fact["Third_Party"] == "BlgCloud"
    assert fact["Threat_Actor"] == "LockBit"
    assert fact["Affected_Count"] == "138000"
    assert json.loads(fact["Vulnerabilities_JSON"]) == ["CVE-2026-72898"]


def test_cyberattaque_editorial_title_is_safe_summary_when_ai_abstains(monkeypatch):
    monkeypatch.setattr(sf.source_facts_ai, "enrich", lambda *_: {})
    entry = RawEntry(
        title="Société Exemple : 18 Go de données revendiqués après une attaque ransomware",
        organisation="Société Exemple",
        content="Le groupe Qilin revendique une attaque et 18 Go de données.",
    )
    fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG", organisation="Société Exemple"), entry, CO)
    assert fact["Summary"] == entry.title
    assert json.loads(fact["Evidence_JSON"])["Summary"] == entry.title


def test_enrichissement_semantique_est_materialise(monkeypatch):
    monkeypatch.setattr(sf.source_facts_ai, "enrich", lambda *_: {
        "summary": {
            "value": "Intrusion via une vulnérabilité, suivie d'une exfiltration.",
            "confidence": .95,
            "evidence": "L'attaquant a exploité la vulnérabilité puis exfiltré les données.",
        },
        "initial_access": {
            "value": "vulnerability_exploitation",
            "confidence": .99,
            "evidence": "L'attaquant a exploité la vulnérabilité pour entrer dans le SI.",
        },
        "attack_flow": [
            {
                "action": "Exploitation de la vulnérabilité",
                "confidence": .99,
                "evidence": "L'attaquant a exploité la vulnérabilité pour entrer dans le SI.",
            },
            {
                "action": "Exfiltration des données",
                "confidence": .95,
                "evidence": "L'attaquant a ensuite exfiltré les données clients.",
            },
        ],
        "impact": {
            "value": "Des données clients ont été exfiltrées.",
            "confidence": .95,
            "evidence": "L'attaquant a ensuite exfiltré les données clients.",
        },
    })
    entry = RawEntry(
        title="Société Exemple", organisation="Société Exemple",
        content=(
            "L'attaquant a exploité la vulnérabilité pour entrer dans le SI. "
            "L'attaquant a ensuite exfiltré les données clients."
        ),
    )
    fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG", organisation="Société Exemple"), entry, CO)
    assert fact["Initial_Access"] == "vulnerability_exploitation"
    assert json.loads(fact["Attack_Flow_JSON"]) == [
        {"action": "Exploitation de la vulnérabilité", "evidence": "L'attaquant a exploité la vulnérabilité pour entrer dans le SI."},
        {"action": "Exfiltration des données", "evidence": "L'attaquant a ensuite exfiltré les données clients."},
    ]
    assert fact["Summary"] == "Intrusion via une vulnérabilité, suivie d'une exfiltration."
    assert fact["Impact"] == "Des données clients ont été exfiltrées."
    evidence = json.loads(fact["Evidence_JSON"])
    assert evidence["Initial_Access"]
    assert len(evidence["Attack_Flow_JSON"]) == 2


def test_ai_count_est_valide_mecaniquement(monkeypatch):
    monkeypatch.setattr(sf.source_facts_ai, "enrich", lambda *_: {
        "affected_counts": [
            {"status": "claimed", "confidence": .99, "evidence": "1,08 million d'enregistrements revendiqués"},
            {"status": "confirmed", "confidence": .95, "evidence": "138 000 personnes confirmées"},
        ],
        "data_types": [{"value": "adresses e-mail", "confidence": .9, "evidence": "adresses e-mail exposées"}],
        "summary": {"value": "La société confirme une exposition de données.", "confidence": .9, "evidence": "confirme 138 000 personnes"},
    })
    entry = RawEntry(
        title="Société Exemple", organisation="Société Exemple",
        content="Le groupe revendique 1,08 million d'enregistrements revendiqués mais la société confirme 138 000 personnes confirmées ; adresses e-mail exposées.",
    )
    fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG", organisation="Société Exemple"), entry, CO)
    assert fact["Affected_Count"] == "138000"
    assert fact["Affected_Unit"] == "people"
    assert json.loads(fact["Data_Types_JSON"]) == ["adresses e-mail"]
    assert fact["Summary"]


def test_ai_mauvais_compteur_retombe_sur_deterministe(monkeypatch):
    monkeypatch.setattr(sf.source_facts_ai, "enrich", lambda *_: {
        "affected_counts": [{"status": "confirmed", "confidence": .99, "evidence": "depuis 25 ans"}],
    })
    entry = RawEntry(title="Société Exemple", organisation="Société Exemple", content="Entreprise créée depuis 25 ans.")
    fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG"), entry, CO)
    assert fact is None or fact["Affected_Count"] == ""


def test_ai_actor_victime_est_rejete(monkeypatch):
    monkeypatch.setattr(sf.source_facts_ai, "enrich", lambda *_: {
        "threat_actor": {"value": "Société Exemple", "confidence": .99, "evidence": "Société Exemple"},
    })
    entry = RawEntry(title="Société Exemple", organisation="Société Exemple", content="Société Exemple confirme l'incident.")
    fact = sf.extract_source_fact(make_item("CYBERATTAQUE_ORG", organisation="Société Exemple"), entry, CO)
    assert fact is None or fact["Threat_Actor"] == ""


RANSOM = SourceSpec(source_id="RANSOMWARE_LIVE", layer="core", zone="Multi")


def _ransom_entry(**overrides):
    record = {
        "victim": "Exemple SA", "discovered": "2026-08-10", "attackdate": "2026-08-01",
        "group": "LockBit", "country": "FR", "sector": "Santé", "website": "exemple.fr",
        "post_url": "https://leaksite.example/exemple-sa",
    }
    record.update(overrides)
    return _entry_from_record(record, RANSOM, "FR")


def test_ransomware_live_reste_structuré_sans_llm():
    fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), _ransom_entry(), RANSOM)
    assert fact["Threat_Actor"] == "LockBit"
    assert fact["Discovered_Date"] == "2026-08-10"
    assert fact["Attack_Date"] == "2026-08-01"
    assert fact["Victim_Website"] == "https://exemple.fr"
    assert fact["Source_Sector_Raw"] == "Santé"
    assert json.loads(fact["Evidence_URLs_JSON"]) == ["https://leaksite.example/exemple-sa"]


def test_ransomware_generique_rejete():
    fact = sf.extract_source_fact(make_item("RANSOMWARE_LIVE"), _ransom_entry(group="Ransomware"), RANSOM)
    assert fact is None or fact["Threat_Actor"] == ""


def test_veille_llm_reste_structuré_et_sans_second_llm():
    veille_spec = SourceSpec(
        source_id="VEILLE_LLM", layer="regional_watch", zone="La Réunion / Mayotte",
        start_url="https://example.test/snapshot.json", collector="veillellm", location_rule="Inconnu",
        params={"path": "sources/veillellm/cyberattaques_reunion_mayotte_2026.json"},
    )
    result = VeilleLlmCollector().collect(None, veille_spec, Window("2000-01-01", "2030-01-01"))
    assert result.entries
    entry = result.entries[0]
    fact = sf.extract_source_fact(make_item("VEILLE_LLM"), entry, veille_spec)
    assert fact is not None
    assert "source_facts_ai" in sf.__dict__
