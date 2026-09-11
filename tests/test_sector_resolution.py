from types import SimpleNamespace

import pytest

from cyberwatch import config, sector_resolution, site
from cyberwatch.model import Item
import json


def _item(name: str = "Organisation opaque") -> Item:
    return Item(
        Item_ID="ITM-test",
        Source_ID="TEST",
        Organisation_Raw=name,
        Organisation_Key=name.casefold(),
        Sector=config.SECTOR_UNKNOWN,
        Title=f"Incident chez {name}",
    )


def test_reutilise_le_secteur_semantique_deja_extrait():
    decision = sector_resolution.resolve_item(
        _item(),
        {
            "Activity_Description": "La victime développe des applications métiers.",
            "Activity_Sector_Match": config.SECTOR_TECH,
            "Evidence_JSON": json.dumps({"Activity_Description": "Organisation opaque développe des applications métiers."}),
        },
        {},
    )
    assert decision.sector == config.SECTOR_TECH
    assert decision.reason == "SEMANTIC_ACTIVITY_MATCH"
    assert decision.status == "inferred"


def test_description_contradictoire_est_signalee():
    decision = sector_resolution.resolve_item(
        _item(),
        {
            "Activity_Description": "La société propose des téléconsultations médicales.",
            "Activity_Sector_Match": config.SECTOR_TECH,
            "Evidence_JSON": json.dumps({"Activity_Description": "Organisation opaque propose des téléconsultations médicales."}),
        },
        {},
    )
    assert decision.sector == config.SECTOR_UNKNOWN
    assert decision.reason == "ACTIVITY_SECTOR_CONFLICT"
    assert decision.status == "unknown"


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("Fédération nationale de tir sportif", config.SECTOR_SPORT),
        ("Plateforme de téléconsultation médicale", config.SECTOR_HEALTH),
        ("Gestion et diffusion de données foncières", config.SECTOR_CONSTRUCTION),
        ("Production agricole et horticulture", config.SECTOR_AGRICULTURE),
        ("Service cloud de stockage de fichiers", config.SECTOR_TECH),
        ("Vente en ligne de chaussures", config.SECTOR_RETAIL),
    ],
)
def test_regles_activite_couvrent_les_cas_metier_observes(description, expected):
    assert sector_resolution.sector_policy.classify_sector_activity(description) == expected


@pytest.mark.parametrize("name", ["Qare", "LiveTrail", "Geofoncier", "Herbiolys", "FFTir"])
def test_nom_de_marque_seul_reste_inconnu(name):
    assert sector_resolution.sector_policy.classify_sector_name(name) == config.SECTOR_UNKNOWN


def test_reference_exacte_precede_le_repli():
    reference = {
        "organisation opaque": SimpleNamespace(
            sector=config.SECTOR_FINANCE,
            reason="Activité validée",
            validation_url="https://example.test/preuve",
        )
    }
    decision = sector_resolution.resolve_item(_item(), {}, reference)
    assert decision.sector == config.SECTOR_FINANCE
    assert decision.status == "referenced"
    assert decision.evidence_url == "https://example.test/preuve"


def test_absence_de_preuve_ne_fabrique_pas_un_secteur():
    item = _item()
    rows = sector_resolution.resolve_items([item], [], {})
    assert item.Sector == config.SECTOR_UNKNOWN
    assert sector_resolution.unknown_rate([item]) == 100.0
    assert rows[0]["Status"] == "unknown"
    assert rows[0]["Reason"] == "NO_ACTIVITY_EVIDENCE"
    assert rows[0]["Confidence"] == "0.00"


def test_publication_expose_la_preuve_du_secteur_reference():
    row = {"org": "Organisation opaque", "sector": config.SECTOR_FINANCE}
    decisions = {"organisation opaque": [{
        "Resolved_Sector": config.SECTOR_FINANCE,
        "Status": "referenced",
        "Reason": "REFERENCE_EXACT",
        "Confidence": "0.90",
        "Evidence": "Activité validée",
        "Evidence_URL": "https://example.test/preuve",
    }]}
    assert site._sector_status(row, decisions) == {
        "status": "referenced",
        "reason": "REFERENCE_EXACT",
        "confidence": 0.9,
        "evidence": "Activité validée",
        "evidence_url": "https://example.test/preuve",
    }


def _wizishop() -> Item:
    return Item(
        Item_ID="ITM-2f18fd4763986071",
        Source_ID="FRENCHBREACHES",
        Organisation_Raw="WiziShop",
        Organisation_Key="wizishop",
        Sector=config.SECTOR_UNKNOWN,
        Title="Fuite de données chez WiziShop",
        URL="https://frenchbreaches.com/alertes/wizishop",
    )


def test_rubrique_de_source_qualifie_sans_activite_ni_llm():
    """RUN-20260911T171856 : « Technologie » était extrait mais illisible."""
    decision = sector_resolution.resolve_item(
        _wizishop(),
        {"Source_Sector_Raw": "Technologie", "Activity_Description": "",
         "Activity_Sector_Match": ""},
        {},
    )
    assert (decision.sector, decision.status, decision.reason) == (
        config.SECTOR_TECH, "reported", "SOURCE_SECTOR_RAW")
    assert decision.evidence == "Technologie"


def test_rubrique_non_reconnue_est_nommee_et_non_confondue_avec_une_absence():
    decision = sector_resolution.resolve_item(
        _item(), {"Source_Sector_Raw": "Cryogénie quantique"}, {})
    assert decision.sector == config.SECTOR_UNKNOWN
    assert decision.status == "unknown"
    assert decision.reason == "SOURCE_SECTOR_RAW_UNMAPPED"
    assert decision.evidence == "Cryogénie quantique"


def test_absence_de_rubrique_reste_une_absence_de_preuve():
    decision = sector_resolution.resolve_item(_item(), {"Source_Sector_Raw": ""}, {})
    assert decision.reason == "NO_ACTIVITY_EVIDENCE"


def test_une_rubrique_incomprise_ne_prime_sur_aucune_preuve_existante():
    """Le motif d'audit est un dernier ressort, jamais un court-circuit."""
    previous = [{"Item_ID": "ITM-test", "Resolved_Sector": config.SECTOR_HEALTH,
                 "Status": "referenced", "Reason": "REFERENCE_EXACT", "Confidence": "0.90"}]
    item = _item()
    item.Sector = config.SECTOR_HEALTH
    rows = sector_resolution.resolve_items(
        [item], [{"Item_ID": "ITM-test", "Source_Sector_Raw": "Cryogénie quantique"}], {},
        previous_rows=previous)
    assert rows[0]["Resolved_Sector"] == config.SECTOR_HEALTH
    assert rows[0]["Reason"] == "REFERENCE_EXACT"


def test_le_motif_d_audit_n_est_pas_une_preuve_recevable():
    assert "SOURCE_SECTOR_RAW_UNMAPPED" not in sector_resolution.SUPPORTED_REASONS
    rows = [{"Resolved_Sector": config.SECTOR_UNKNOWN, "Reason": "SOURCE_SECTOR_RAW_UNMAPPED"},
            {"Resolved_Sector": config.SECTOR_TECH, "Reason": "ACTIVITY_RULE"}]
    assert sector_resolution.component_sector_rows(rows) == config.SECTOR_TECH


def test_une_activite_explicite_prime_toujours_sur_la_rubrique_de_source():
    """Aqualter : « Industrie » désormais lisible ne doit pas battre l'activité."""
    proof = "Aqualter est une entreprise spécialisée dans la gestion de l'eau."
    decision = sector_resolution.resolve_item(
        _item("Aqualter"),
        {"Source_Sector_Raw": "Industrie", "Activity_Description": proof,
         "Evidence_JSON": json.dumps({"Activity_Description": proof})},
        {},
    )
    assert decision.sector == config.SECTOR_ENERGY
    assert decision.reason == "ACTIVITY_OVERRIDES_SOURCE_LABEL"
    assert "Industrie" in decision.evidence
