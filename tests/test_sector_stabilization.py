"""Régressions de stabilisation de la qualification Sector.

Ces tests protègent les invariants de précision attendus avant le prochain
CREATE depuis une base vide. Ils ne constituent pas un benchmark.
"""

from __future__ import annotations

from cyberwatch import ai, config, dedup, org_enrichment, runner, sector
from cyberwatch.collectors.base import RawEntry, SourceSpec


CYBERATTAQUE = SourceSpec(
    source_id="CYBERATTAQUE_ORG",
    layer=config.LAYER_CORE,
    zone=config.LOC_FRANCE,
    params={"scope_is_cyber": True, "include_content": True},
)
FRENCHBREACHES = SourceSpec(
    source_id="FRENCHBREACHES",
    layer=config.LAYER_CORE,
    zone=config.LOC_FRANCE,
    default_threat=config.THREAT_LEAK,
    location_rule=config.LOC_FRANCE,
    params={"title_is_organisation": True},
)


def test_nom_de_marque_ne_vaut_pas_preuve_metier():
    for name in (
        "Agro Paris Tech",
        "Bureau Vallée",
        "Intermarché",
        "Son-Video.com",
        "Lebonmateriel.fr",
    ):
        assert sector.classify_sector_name(name) == config.SECTOR_UNKNOWN


def test_noms_auto_descriptifs_restent_deterministes():
    assert sector.classify_sector_name("Stade Français") == config.SECTOR_SPORT
    assert sector.classify_sector_name("Université de Toulouse") == config.SECTOR_EDUCATION
    assert sector.classify_sector_name("Clinique de l'Yvette") == config.SECTOR_HEALTH
    assert sector.classify_sector_name("Mairie de Drancy") == config.SECTOR_ADMIN


def test_description_metier_expresse_est_classable():
    assert sector.classify_sector_activity(
        "entreprise spécialisée dans le commerce et la distribution de fournitures"
    ) == config.SECTOR_RETAIL
    assert sector.classify_sector_activity(
        "éditeur de logiciels cloud pour entreprises"
    ) == config.SECTOR_TECH
    assert sector.classify_sector_activity(
        "club de football professionnel"
    ) == config.SECTOR_SPORT


def test_categories_source_ambiguës_restent_inconnues():
    for source_sector in ("agriculture", "consumer services", "non profit", "hospitality"):
        assert sector.classify_source_sector(source_sector) == config.SECTOR_UNKNOWN


def test_categories_source_claires_restent_mappees():
    assert sector.classify_source_sector("healthcare") == config.SECTOR_HEALTH
    assert sector.classify_source_sector("banking") == config.SECTOR_FINANCE
    assert sector.classify_source_sector("software") == config.SECTOR_TECH
    assert sector.classify_source_sector("transportation") == config.SECTOR_TRANSPORT


def test_cyberattaque_article_complet_ne_peut_plus_creer_sport():
    entry = RawEntry(
        title="Bureau Vallée : une cyberattaque expose des clients",
        summary="À ce stade, aucune revendication n'est confirmée.",
        content="Le site web a été isolé et les systèmes sont en cours d'analyse.",
        published="2026-08-09",
        organisation="Bureau Vallée",
    )
    item = runner.entry_to_item(entry, CYBERATTAQUE, "2026-08-16T00:00:00+04:00", {}, {})
    assert item is not None
    assert item.Sector == config.SECTOR_UNKNOWN


def test_cyberattaque_activite_explicite_peut_resoudre_le_secteur():
    entry = RawEntry(
        title="Exemple Distribution : cyberattaque",
        summary="Exemple Distribution est une entreprise spécialisée dans le commerce de fournitures de bureau.",
        content="À ce stade, l'incident est contenu.",
        published="2026-08-09",
        organisation="Exemple Distribution",
    )
    item = runner.entry_to_item(entry, CYBERATTAQUE, "2026-08-16T00:00:00+04:00", {}, {})
    assert item is not None
    assert item.Sector == config.SECTOR_RETAIL


def test_bonjourlafuite_nom_seul_ne_declenche_pas_llm_sector(make_item):
    item = make_item(
        source="BONJOURLAFUITE", org="Intermarché", sector=config.SECTOR_UNKNOWN,
        location=config.LOC_FRANCE,
    )
    entry = RawEntry(
        title="Intermarché",
        summary="Données concernées : noms, emails, adresses.",
        published="2026-08-10",
        organisation="Intermarché",
    )
    spec = SourceSpec(
        source_id="BONJOURLAFUITE", layer=config.LAYER_CORE, zone=config.LOC_FRANCE,
        default_threat=config.THREAT_LEAK, location_rule=config.LOC_FRANCE,
    )
    assert ai._sector_llm_worth_calling(entry, spec, item.Organisation_Key, 4000) is False


def test_llm_sector_exige_activite_explicite(make_item):
    item = make_item(org="Scalingo", sector=config.SECTOR_UNKNOWN)
    entry = RawEntry(
        title="Scalingo victime d'une fuite",
        summary="Scalingo est un fournisseur de services cloud pour le déploiement d'applications.",
        published="2026-08-13",
        organisation="Scalingo",
    )
    assert ai._sector_llm_worth_calling(entry, FRENCHBREACHES, item.Organisation_Key, 4000) is True


def test_evidence_sector_hors_activity_description_est_rejetee(make_item):
    item = make_item(org="Exemple", sector=config.SECTOR_UNKNOWN)
    raw = {
        "sector": {
            "value": config.SECTOR_TECH,
            "confidence": 0.9,
            "evidence": "plateforme informatique compromise",
        }
    }
    decision, rejected = ai._validate(
        raw,
        ["Sector"],
        "plateforme informatique compromise. Entreprise spécialisée dans le commerce de vêtements.",
        item.Organisation_Key,
        sector_context="entreprise spécialisée dans le commerce de vêtements",
    )
    assert "Sector" not in decision
    assert rejected["Sector"] == "not_grounded"


def test_matching_nom_commercial_exact_siren_unique():
    payload = {
        "results": [{
            "siren": "123456789",
            "nom_raison_sociale": "BV FRANCE",
            "nom_complet": "Bureau Vallée (BV FRANCE)",
        }]
    }
    status, candidate = org_enrichment._match("Bureau Vallée", payload)
    assert status == org_enrichment.MATCHED
    assert candidate["siren"] == "123456789"


def test_matching_nom_commercial_plusieurs_siren_reste_ambigu():
    payload = {
        "results": [
            {"siren": "111111111", "nom_complet": "Enseigne Test (A)"},
            {"siren": "222222222", "nom_complet": "Enseigne Test (B)"},
        ]
    }
    status, candidate = org_enrichment._match("Enseigne Test", payload)
    assert status == org_enrichment.AMBIGUOUS
    assert candidate == {}


def test_matching_sans_siren_reste_ambigu():
    payload = {"results": [{"siren": "", "nom_raison_sociale": "Exemple"}]}
    status, candidate = org_enrichment._match("Exemple", payload)
    assert status == org_enrichment.AMBIGUOUS
    assert candidate == {}


def test_sections_naf_ambigues_restent_inconnues():
    for letter in ("A", "B", "I", "R", "S", "T", "U"):
        label = org_enrichment.NAF_SECTION_LABELS[letter]
        assert org_enrichment.sector_for_activity_label(label) == config.SECTOR_UNKNOWN


def test_dedup_conflit_sector_un_contre_un_redevient_inconnu(make_item):
    items = [
        make_item(source="FRENCHBREACHES", org="Victime", sector=config.SECTOR_HEALTH, url="https://a.example"),
        make_item(source="CYBERATTAQUE_ORG", org="Victime", sector=config.SECTOR_ADMIN, url="https://b.example"),
    ]
    incidents = dedup.build_incidents(items)
    assert len(incidents) == 1
    assert incidents[0].Secteur == config.SECTOR_UNKNOWN


def test_dedup_majorite_sector_claire_est_conservee(make_item):
    items = [
        make_item(source="FRENCHBREACHES", org="Victime", sector=config.SECTOR_HEALTH, url="https://a.example"),
        make_item(source="CYBERATTAQUE_ORG", org="Victime", sector=config.SECTOR_HEALTH, url="https://b.example"),
        make_item(source="RANSOMWARE_LIVE", org="Victime", sector=config.SECTOR_ADMIN, url="https://c.example"),
    ]
    incidents = dedup.build_incidents(items)
    assert incidents[0].Secteur == config.SECTOR_HEALTH


def test_dedup_veille_llm_connue_reste_prioritaire(make_item):
    items = [
        make_item(source="CYBERATTAQUE_ORG", org="Victime", sector=config.SECTOR_ADMIN, url="https://a.example"),
        make_item(source="VEILLE_LLM", org="Victime", sector=config.SECTOR_HEALTH, url="https://b.example"),
    ]
    incidents = dedup.build_incidents(items)
    assert incidents[0].Secteur == config.SECTOR_HEALTH
