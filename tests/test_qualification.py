from cyberwatch import config, identity
from cyberwatch.qualification import qualify


def test_qualification_is_idempotent_and_keeps_item_identity(make_item):
    item = make_item(threat=config.THREAT_UNKNOWN, title="Fuite de données confirmée")
    before = item.Item_ID
    first = qualify([item])
    second = qualify(first.items)
    assert first.items_hash == second.items_hash
    assert first.incidents_hash == second.incidents_hash
    assert first.items[0].Item_ID == before


def test_structured_values_are_not_overwritten_by_qualification(make_item):
    item = make_item(sector="Santé", location="France", threat="Ransomware")
    result = qualify([item])
    assert (result.items[0].Sector, result.items[0].Location, result.items[0].Threat) == ("Santé", "France", "Ransomware")
