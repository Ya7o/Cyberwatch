from cyberwatch import incremental_runtime
from cyberwatch.model import Item


def _item(**changes):
    values = dict(
        Item_ID="ITM-1", Source_ID="SRC", Source_Item_ID="1",
        Published_Date="2026-08-20", Event_Date="2026-08-20",
        Organisation_Raw="Example SA", Organisation_Key="example-sa",
        Threat_Raw="Ransomware", Threat="Ransomware", Sector="Technologies",
        Location="France", Title="Incident Example SA",
        URL="https://example.test/1", Collected_As_Of="2026-08-20T08:00:00+04:00",
    )
    values.update(changes)
    return Item(**values)


def test_runtime_disabled_by_default(monkeypatch):
    monkeypatch.delenv("CYBERWATCH_INCREMENTAL_QUALIFICATION", raising=False)
    assert incremental_runtime.enabled() is False


def test_runtime_can_be_enabled(monkeypatch):
    monkeypatch.setenv("CYBERWATCH_INCREMENTAL_QUALIFICATION", "1")
    assert incremental_runtime.enabled() is True


def test_business_snapshot_ignores_collection_timestamp():
    assert incremental_runtime._same_business_snapshot(
        [_item(Collected_As_Of="2026-08-21T08:00:00+04:00")], [_item()]
    )


def test_business_snapshot_detects_real_change():
    assert not incremental_runtime._same_business_snapshot(
        [_item(Title="Titre modifié")], [_item()]
    )
