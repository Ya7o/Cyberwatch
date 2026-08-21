from scripts import bootstrap_sector_state
from cyberwatch import config
from cyberwatch.model import Item


def _item(item_id: str, source: str, key: str, sector: str) -> Item:
    return Item(
        Item_ID=item_id,
        Source_ID=source,
        Organisation_Raw=key.title(),
        Organisation_Key=key,
        Sector=sector,
    )


def test_target_keys_include_unknowns_and_ransomware_native(monkeypatch):
    rows = [
        _item("I1", "CYBERATTAQUE_ORG", "unknown-org", config.SECTOR_UNKNOWN),
        _item("I2", "RANSOMWARE_LIVE", "native-org", config.SECTOR_TRANSPORT),
        _item("I3", "CYBERATTAQUE_ORG", "already-proved", config.SECTOR_HEALTH),
    ]
    monkeypatch.setattr(bootstrap_sector_state.store, "load_items", lambda: rows)
    assert bootstrap_sector_state._target_keys() == {"unknown-org", "native-org"}


def test_bootstrap_empty_state_runs_create_then_full_enrichment(monkeypatch):
    rows = [_item("I1", "RANSOMWARE_LIVE", "example", config.SECTOR_TRANSPORT)]
    states = [[], rows, rows, rows, rows]

    def load_items():
        return states.pop(0) if states else rows

    commands = []

    def fake_run(command, *, env=None):
        commands.append((command, env or {}))

    monkeypatch.setattr(bootstrap_sector_state.store, "load_items", load_items)
    monkeypatch.setattr(bootstrap_sector_state, "_run", fake_run)
    monkeypatch.setattr(bootstrap_sector_state, "_write_registry_and_queue", lambda: ([], []))
    monkeypatch.setattr(bootstrap_sector_state, "_target_keys", lambda: {"example"})
    monkeypatch.setattr(bootstrap_sector_state, "_persist_final_qualification", lambda: (1, 1, 0))
    monkeypatch.setattr(bootstrap_sector_state.store, "load_org_enrichment_cache", lambda: [])

    assert bootstrap_sector_state.bootstrap(workers=4, max_orgs=0) == 0
    assert commands[0][0][-2:] == ["cyberwatch", "create"]
    enrich_command, env = commands[1]
    assert enrich_command[-1] == "scripts/enrich_sector_queue.py"
    assert env["SECTOR_ENRICHMENT_MODE"] == "full"
    assert env["SECTOR_ENRICHMENT_TARGET_KEYS"] == "example"
    assert env["SECTOR_ENRICHMENT_MAX_ORGS"] == "0"
    assert env["SECTOR_ENRICHMENT_WORKERS"] == "4"
    assert env["SECTOR_PURGE_GOLDEN_MISMATCHES"] == "0"


def test_bootstrap_can_refuse_network_create_on_empty_state(monkeypatch):
    monkeypatch.setattr(bootstrap_sector_state.store, "load_items", lambda: [])
    assert bootstrap_sector_state.bootstrap(skip_create=True) == 2
