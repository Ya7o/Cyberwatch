from cyberwatch import config, qualification
from cyberwatch.model import Item


def make_item(**overrides):
    values = dict(
        Item_ID="ITM-1", Source_ID="CYBERATTAQUE_ORG", Source_Item_ID="1",
        URL="https://example.test", Title="DINUM : 31 544 lignes liées au cloud de l’État en fuite",
        Published_Date="2026-08-22", Event_Date="", Organisation_Raw="DINUM",
        Organisation_Key="dinum", Sector=config.SECTOR_UNKNOWN, Location=config.LOC_INCONNU,
        Threat=config.THREAT_THIRD_PARTY, Threat_Raw="Incident tiers",
    )
    values.update(overrides)
    return Item(**values)


def test_fuite_explicite_ne_peut_etre_ecrasee_par_incident_tiers():
    item = make_item()
    qualification.stabilize_threats([item])
    assert item.Threat == config.THREAT_LEAK
