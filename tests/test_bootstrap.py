"""Contrats de bootstrap : une MAJ ne peut jamais initialiser une base vide."""

from types import SimpleNamespace

from cyberwatch import cli, identity, site, status, store
from cyberwatch.dedup import build_incidents


def isolate_store(tmp_path, monkeypatch):
    """Redirige tous les artefacts générés vers un répertoire temporaire."""
    mapping = {
        "ITEMS_CSV": tmp_path / "items.csv",
        "INCIDENTS_CSV": tmp_path / "incidents.csv",
        "RUN_LOG_CSV": tmp_path / "run_log.csv",
        "RUN_SOURCES_CSV": tmp_path / "run_sources.csv",
        "SOURCES_CSV": tmp_path / "sources.csv",
        "ENTITY_WATCH_CSV": tmp_path / "entity_watch.csv",
        "SNAPSHOT_JSON": tmp_path / "snapshot.json",
        "BASELINE_JSON": tmp_path / "baseline.json",
        "SITE_DATA_DIR": tmp_path / "site-data",
    }
    for name, path in mapping.items():
        monkeypatch.setattr(store, name, path)


def valid_snapshot(make_item):
    items = [make_item()]
    incidents = build_incidents(items)
    store.save_items(items)
    store.save_incidents(incidents)
    store.save_snapshot({
        "Items_Count": len(items),
        "Incidents_Count": len(incidents),
        "Items_Hash": identity.items_hash(items),
        "Incidents_Hash": identity.incidents_hash(incidents),
    })


def test_maj_without_snapshot_is_refused(tmp_path, monkeypatch, capsys):
    isolate_store(tmp_path, monkeypatch)
    args = SimpleNamespace(as_of=None, start=None, layers="all")

    assert cli.cmd_maj(args) == 1
    assert "Aucun snapshot Cyberwatch valide" in capsys.readouterr().out


def test_maj_with_valid_snapshot_is_allowed(tmp_path, monkeypatch, make_item):
    isolate_store(tmp_path, monkeypatch)
    valid_snapshot(make_item)
    args = SimpleNamespace(as_of="2026-08-14T08:00:00+04:00", start=None, layers="all")
    called = []
    monkeypatch.setattr(cli, "execute", lambda context: called.append(context) or SimpleNamespace(overall=status.OK))
    monkeypatch.setattr(cli, "_print_summary", lambda report: None)
    monkeypatch.setattr(cli.site, "build", lambda: None)

    assert cli.cmd_maj(args) == 0
    assert called and called[0].mode == "MAJ"


def test_empty_base_is_uninitialized_and_ci_check_passes(tmp_path, monkeypatch, capsys):
    isolate_store(tmp_path, monkeypatch)

    assert store.snapshot_state()[0] == store.BASE_UNINITIALIZED
    assert cli.cmd_check(SimpleNamespace(allow_uninitialized=False)) == 1
    assert cli.cmd_check(SimpleNamespace(allow_uninitialized=True)) == 0
    assert "BASE NON INITIALISÉE" in capsys.readouterr().out


def test_partial_items_without_snapshot_is_incoherent(tmp_path, monkeypatch, make_item, capsys):
    isolate_store(tmp_path, monkeypatch)
    store.save_items([make_item()])

    assert store.snapshot_state()[0] == store.BASE_INCOHERENT
    assert cli.cmd_check(SimpleNamespace(allow_uninitialized=True)) == 1
    assert "BASE INCOHÉRENTE" in capsys.readouterr().out


def test_snapshot_without_items_is_incoherent(tmp_path, monkeypatch):
    isolate_store(tmp_path, monkeypatch)
    store.save_snapshot({"Items_Count": 0})

    assert store.snapshot_state()[0] == store.BASE_INCOHERENT


def test_site_build_on_uninitialized_base_is_explicit(tmp_path, monkeypatch):
    isolate_store(tmp_path, monkeypatch)

    assert site.build() == (0, 0)
    assert not store.SNAPSHOT_JSON.exists()
    import json
    status_payload = json.loads((store.SITE_DATA_DIR / "status.json").read_text(encoding="utf-8"))
    assert status_payload["initialized"] is False
    assert "health" not in status_payload["run"]


def test_report_uses_status_and_not_a_score(tmp_path, monkeypatch, capsys):
    isolate_store(tmp_path, monkeypatch)
    store.append_run_log({
        "Run_ID": "RUN-TEST",
        "Mode": "CREATE",
        "Overall_Status": "OK",
        "Sources_OK": 5,
        "Sources_FAIL": 0,
    })

    assert cli.cmd_report(SimpleNamespace()) == 0
    output = capsys.readouterr().out
    assert "Sources : **5 OK / 0 FAIL**" in output
    assert "Score de couverture" not in output


def test_collect_workflow_has_one_daily_cron():
    workflow = (store.ROOT / ".github" / "workflows" / "collect.yml").read_text(encoding="utf-8")
    assert 'cron: "0 4 * * *"' in workflow
    assert 'cron: "0 3 * * 1"' not in workflow
