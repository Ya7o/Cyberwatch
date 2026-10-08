"""Détail sensible sourcé, sans convertir un démenti en exposition."""
import json
from pathlib import Path

import pytest

from cyberwatch import data_sensitivity, dedup, site, site_sensitive_data, store


@pytest.mark.parametrize("label", ["pièces d'identité", "cartes d’identité", "IBAN", "données médicales"])
def test_sensitive_categories_include_identity_plural(label):
    assert data_sensitivity.classify({"data_types": [{"value": label, "status": "claimed"}]})[
        "high_sensitivity_data_exposed"
    ]


def test_publication_preserves_iban_precision_and_canonical_facts(tmp_path, monkeypatch, make_item):
    data_dir = store.DATA_DIR
    for name, value in vars(store).copy().items():
        if isinstance(value, Path) and value.parent == data_dir:
            monkeypatch.setattr(store, name, tmp_path / value.name)
    monkeypatch.setattr(store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(store, "SITE_DATA_DIR", tmp_path / "public")
    item = make_item(org="Exemple sensible", source="BONJOURLAFUITE", sector="Inconnu")
    store.save_items([item])
    store.save_incidents(dedup.build_incidents([item]))
    store.save_source_facts([{"Item_ID": item.Item_ID, "Source_ID": item.Source_ID,
                             "Summary": "Une fuite de données est signalée.",
                             "Data_Types_JSON": json.dumps(["IBAN", "Nom, prénom"])}])
    canonical = store.SOURCE_FACTS_CSV.read_bytes()
    site.build()
    row = json.loads((store.SITE_DATA_DIR / "incidents.json").read_text())[0]
    detail = json.loads((store.SITE_DATA_DIR / "facts.json").read_text())[row["id"]]
    assert row["high_sensitivity_data_exposed"] is True
    assert detail["sensitive_data"]["types"] == [{
        "value": "données bancaires", "status": "unknown",
        "sources": ["BONJOURLAFUITE"], "specifics": ["IBAN"],
    }]
    assert store.SOURCE_FACTS_CSV.read_bytes() == canonical
    assert "sensitive_data" not in row  # Le détail voyage uniquement dans facts.json.


def test_negative_list_and_prevention_do_not_become_exposed_categories():
    context = (
        "Selon l’entreprise, ne sont notamment pas concernés :\n"
        "- les IBAN ;\n- les mots de passe ;\n\n"
        "Documents mis en vente :\n- pièces d’identité.\n"
        "Paiements et mots de passe épargnés.\n"
        "WiziShop attire particulièrement l’attention sur les messages demandant "
        "de régler une facture sur de nouvelles coordonnées bancaires."
    )
    rich = {"data_types": [
        {"value": "données bancaires", "status": "confirmed", "evidence": "- les IBAN ;"},
        {"value": "mots de passe", "status": "unknown", "evidence": "- les mots de passe ;"},
        {"value": "pièces d'identité", "status": "claimed", "evidence": "- pièces d’identité."},
        {"value": "mots de passe", "status": "unknown", "evidence": "Paiements et mots de passe épargnés."},
        {"value": "données bancaires", "status": "unknown", "evidence": context.split("\n")[-1]},
    ]}
    fact = site._source_fact_payload({
        "Item_ID": "ITM-sensitive", "Source_ID": "FRENCHBREACHES",
        "Source_Metadata_JSON": json.dumps({"editorial_context": context, "rich_facts": rich}),
        "Data_Types_JSON": json.dumps(["IBAN", "mots de passe", "pièces d'identité"]),
    })
    details = site._resolved_details([{"id": "INC-sensitive", "org": "Exemple"}], {"INC-sensitive": [fact]})
    sensitive = site_sensitive_data.payload(details["INC-sensitive"], [fact])
    assert sensitive["types"] == [{"value": "pièces d'identité", "status": "claimed",
                                    "sources": ["FRENCHBREACHES"], "specifics": []}]
    # La revalidation de publication ne modifie pas la preuve canonique fournie.
    assert rich["data_types"][0]["status"] == "confirmed"


def test_unconfirmed_types_are_not_exposed_and_vulnerable_context_is_retained():
    sensitive = site_sensitive_data.payload({
        "data_types": [
            {"value": "IBAN", "status": "unconfirmed"},
            {"value": "mots de passe", "status": "denied"},
            {"value": "noms", "status": "reported", "sources": ["BONJOURLAFUITE"]},
        ],
        "display_summary": "Des données d’enfants ont été diffusées.",
    }, [])
    assert sensitive["vulnerable_people"] is True
    assert [entry["value"] for entry in sensitive["types"]] == ["noms"]
