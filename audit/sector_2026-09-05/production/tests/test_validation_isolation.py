"""Les validations transitoires ne publient aucun historique opérationnel."""

from types import SimpleNamespace

from cyberwatch import cli, status


def test_maj_transient_n_ecrit_ni_snapshot_ni_dashboard(monkeypatch):
    calls = []
    report = SimpleNamespace(overall=status.OK)
    monkeypatch.setattr(cli, "execute", lambda _context, *, persist: calls.append(persist) or report)
    monkeypatch.setattr(cli, "_print_summary", lambda _report: None)
    monkeypatch.setattr(cli.store, "snapshot_state", lambda: (cli.store.BASE_VALID, []))
    monkeypatch.setattr(cli.site, "build", lambda: (_ for _ in ()).throw(AssertionError("dashboard écrit")))

    args = SimpleNamespace(as_of="2026-08-14T17:00:00+04:00", layers="all", transient=True)
    assert cli.cmd_maj(args) == 0
    assert calls == [False]
