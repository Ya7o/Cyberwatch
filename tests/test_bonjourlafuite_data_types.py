"""Régressions ciblées : données multi-bulles BonjourLaFuite et rendu groupé."""
from __future__ import annotations

import json
from pathlib import Path

from cyberwatch import source_facts as sf
from cyberwatch.collectors.base import SourceSpec
from cyberwatch.collectors.bonjourlafuite import parse_timeline
from cyberwatch.model import Item
from cyberwatch.site import _source_fact_payload


SPEC = SourceSpec(
    source_id="BONJOURLAFUITE",
    layer="core",
    zone="France",
    start_url="https://bonjourlafuite.eu.org/",
    collector="bonjourlafuite",
    params={"title_is_organisation": True},
)

FRANCE_VAE_TYPES = [
    "Nom, prénoms",
    "Genre",
    "Adresse e-mail",
    "Adresse postale",
    "Département de résidence",
    "Numéro de téléphone",
    "Pays, ville et date de naissance",
    "Nationalité",
    "Certifications professionnelles",
    "Qualifications et expériences",
    "Résultats d’évaluation",
    "Financement du parcours de VAE",
]

FRANCE_VAE_HTML = """
<html><body>
  <p>13 août 2026</p>
  <h2>🟢 France VAE</h2>
  <div>
    <p><strong>Données concernées :</strong></p>
    <span>Nom, prénoms</span>
    <span>Genre</span>
    <span>Adresse e-mail</span>
    <span>Adresse postale</span>
    <span>Département de résidence</span>
    <span>Numéro de téléphone</span>
    <span>Pays, ville et date de naissance</span>
    <span>Nationalité</span>
    <span>Certifications professionnelles</span>
    <span>Qualifications et expériences</span>
    <span>Résultats d’évaluation</span>
    <span>Financement du parcours de VAE</span>
    <a href="/img/france-vae.png">Source</a>
  </div>
  <p>14 août 2026</p>
  <h2>🟢 Incident suivant</h2>
  <a href="/img/suivant.png">Source</a>
</body></html>
"""


def _item(item_id="ITM-france-vae"):
    return Item(Item_ID=item_id, Source_ID="BONJOURLAFUITE")


def test_bonjourlafuite_capture_toutes_les_bulles_sans_decouper_les_libelles():
    entries = parse_timeline(FRANCE_VAE_HTML, SPEC.start_url)
    assert len(entries) == 2
    assert entries[0].organisation == "France VAE"
    assert entries[0].source_metadata["data_types"] == FRANCE_VAE_TYPES
    assert entries[0].source_metadata["data_types_raw"] == " ; ".join(FRANCE_VAE_TYPES)


def test_bonjourlafuite_ne_contamine_pas_incident_suivant():
    entries = parse_timeline(FRANCE_VAE_HTML, SPEC.start_url)
    assert "data_types" not in entries[1].source_metadata
    assert "data_types_raw" not in entries[1].source_metadata


def test_source_fact_preserve_exactement_la_liste_structuree():
    entry = parse_timeline(FRANCE_VAE_HTML, SPEC.start_url)[0]
    fact = sf.extract_source_fact(_item(), entry, SPEC)
    assert fact is not None
    assert json.loads(fact["Data_Types_JSON"]) == FRANCE_VAE_TYPES
    assert json.loads(fact["Evidence_JSON"])["Data_Types_JSON"] == FRANCE_VAE_TYPES
    assert json.loads(fact["Source_Metadata_JSON"])["data_types"] == FRANCE_VAE_TYPES


def test_payload_dashboard_transmet_la_liste_sans_transformation():
    payload = _source_fact_payload({
        "Item_ID": "ITM-france-vae",
        "Source_ID": "BONJOURLAFUITE",
        "Data_Types_JSON": json.dumps(FRANCE_VAE_TYPES, ensure_ascii=False),
    })
    assert payload is not None
    assert payload["data_types"] == FRANCE_VAE_TYPES


def test_dashboard_regroupe_les_types_sans_fallback_autres():
    """Cible `dashboard-v2.js` (`dataTypeFamily()`/`DATA_TYPE_FAMILY_RULES`),
    le runtime actif — `dashboard.js` (v1) qu'il a remplacé a été retiré.

    Retour utilisateur réel (round 4) : le fourre-tout "Autres" affichait des
    valeurs de piètre qualité (phrases brutes non canonisées, parfois en
    anglais) sans rien apporter. Une valeur non reconnue par
    `DATA_TYPE_FAMILY_RULES` est désormais simplement absente de "Données
    exposées" plutôt que bucketée dans un panier générique."""
    dashboard = (Path(__file__).parents[1] / "assets" / "dashboard-v2.js").read_text(encoding="utf-8")
    for label in (
        "Santé",
        "Financières",
        "Authentification",
        "Administratives",
        "Professionnelles",
        "Identité",
        "Coordonnées",
    ):
        assert label in dashboard
    assert "function dataTypeFamily(value)" in dashboard
    assert "function dataTypesHtml(entries)" in dashboard
    assert "dataTypesHtml(detail.data_types || [])" in dashboard
    family_order_line = next(
        line for line in dashboard.splitlines() if "DATA_TYPE_FAMILY_ORDER = [" in line
    )
    assert "Autres" not in family_order_line
    assert "return null;" in dashboard
