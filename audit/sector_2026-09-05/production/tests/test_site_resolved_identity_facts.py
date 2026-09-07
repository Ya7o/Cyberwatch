"""Régression : les faits dashboard suivent l'Incident_ID réellement dédupliqué."""

from cyberwatch import identity, site
from cyberwatch.dedup import build_incidents
from cyberwatch.model import Item
from cyberwatch.normalize import organisation_key


def _item(item_id: str, source: str, organisation: str) -> Item:
    return Item(
        Item_ID=item_id,
        Source_ID=source,
        Published_Date="2026-04-12",
        Organisation_Raw=organisation,
        Organisation_Key=organisation_key(organisation),
        Threat="Fuite de données",
        Sector="Administration / Collectivité",
        Location="France métropolitaine",
        Title=f"Incident {organisation}",
        URL=f"https://example.test/{item_id}",
    )


def test_faits_suivent_identite_resolue_dune_fusion_multi_items():
    items = [
        _item("ITM-a", "FRENCHBREACHES", "Département de la Gironde"),
        _item("ITM-b", "CYBERATTAQUE_ORG", "CD33"),
    ]
    incident = build_incidents(items)[0]
    assert incident.Items_Count == 2

    facts = site._source_facts_by_incident(items, [
        {"Item_ID": "ITM-a", "Source_ID": "FRENCHBREACHES", "Summary": "Fait A"},
        {"Item_ID": "ITM-b", "Source_ID": "CYBERATTAQUE_ORG", "Summary": "Fait B"},
    ])

    assert list(facts) == [incident.Incident_ID]
    assert {fact["item_id"] for fact in facts[incident.Incident_ID]} == {"ITM-a", "ITM-b"}


def test_singleton_conserve_identifiant_historique():
    item = _item("ITM-a", "FRENCHBREACHES", "Département de la Gironde")
    expected = identity.incident_id(item.Organisation_Key, item.Item_ID)
    facts = site._source_facts_by_incident(
        [item],
        [{"Item_ID": item.Item_ID, "Source_ID": item.Source_ID, "Summary": "Fait"}],
    )
    assert list(facts) == [expected]
