from __future__ import annotations

from cyberwatch import ai, org_enrichment, store
from scripts import benchmark_org_registry_depth as bench


class _Response:
    status_code = 200
    text = ""

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


def _state(**kwargs):
    values = dict(enabled=True, max_calls=20, official_site_max_calls=0)
    values.update(kwargs)
    return org_enrichment.OrgEnrichmentState(**values)


def test_negative_registry_result_is_reused_only_within_run(monkeypatch):
    calls = {"n": 0}

    def fake_get(*_args, **_kwargs):
        calls["n"] += 1
        return _Response({"results": []})

    monkeypatch.setattr(org_enrichment.requests, "get", fake_get)
    state = _state()

    first = org_enrichment.resolve("org x", "Org X", "2026-08-18", state)
    second = org_enrichment.resolve("org x", "Org X", "2026-08-18", state)

    # Contrat historique inchangé : sans fallback officiel, un négatif registre
    # reste None. Seule la répétition HTTP disparaît.
    assert first is None
    assert second is None
    assert calls["n"] == 1
    assert state.calls_attempted == 1
    assert state.run_cache_hits == 1
    assert "org x" in state.run_cache
    assert "org x" not in state.cache


def test_ambiguous_registry_result_is_reused_only_within_run(monkeypatch):
    payload = {
        "results": [
            {"nom_raison_sociale": "Org X", "siren": "111111111"},
            {"nom_raison_sociale": "Org X", "siren": "222222222"},
        ]
    }
    calls = {"n": 0}

    def fake_get(*_args, **_kwargs):
        calls["n"] += 1
        return _Response(payload)

    monkeypatch.setattr(org_enrichment.requests, "get", fake_get)
    state = _state()

    first = org_enrichment.resolve("org x", "Org X", "2026-08-18", state)
    second = org_enrichment.resolve("org x", "Org X", "2026-08-18", state)

    assert first is None
    assert second is None
    assert calls["n"] == 1
    assert state.run_cache_hits == 1
    assert "org x" in state.run_cache
    assert "org x" not in state.cache


def test_network_error_is_never_run_cached(monkeypatch):
    calls = {"n": 0}

    def timeout(*_args, **_kwargs):
        calls["n"] += 1
        raise org_enrichment.requests.Timeout("boom")

    monkeypatch.setattr(org_enrichment.requests, "get", timeout)
    monkeypatch.setattr(org_enrichment.time, "sleep", lambda *_args: None)
    state = _state()

    assert org_enrichment.resolve("org x", "Org X", "2026-08-18", state) is None
    assert org_enrichment.resolve("org x", "Org X", "2026-08-18", state) is None
    assert state.calls_attempted == 2
    assert state.run_cache == {}
    assert calls["n"] == (org_enrichment.ORG_ENRICHMENT_MAX_RETRIES + 1) * 2


def test_run_cache_is_not_persisted_by_finish_run(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    state = _state()
    state.run_cache["org x"] = {
        "Organisation_Key": "org x",
        "Query_Name": "Org X",
        "Match_Status": org_enrichment.NOT_FOUND,
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    }
    ai_state = ai.AiRunState(enabled=False, org_enrichment=state)

    ai.finish_run(ai_state, "RUN-X", "2026-08-18", "CREATE")

    assert store.load_org_enrichment_cache() == []


def test_positive_match_still_uses_persistent_cache(monkeypatch):
    calls = {"n": 0}
    payload = {
        "results": [{
            "nom_raison_sociale": "Scalingo",
            "siren": "111111111",
            "activite_principale": "63.11Z",
            "section_activite_principale": "J",
        }]
    }

    def fake_get(*_args, **_kwargs):
        calls["n"] += 1
        return _Response(payload)

    monkeypatch.setattr(org_enrichment.requests, "get", fake_get)
    state = _state()

    first = org_enrichment.resolve("scalingo", "Scalingo", "2026-08-18", state)
    second = org_enrichment.resolve("scalingo", "Scalingo", "2026-08-18", state)

    assert first is not None and first.Match_Status == org_enrichment.MATCHED
    assert second is not None and second.Match_Status == org_enrichment.MATCHED
    assert calls["n"] == 1
    assert state.cache_hits == 1
    assert "scalingo" in state.cache
    assert "scalingo" not in state.run_cache


def test_depth_benchmark_detects_late_match_then_ambiguity():
    def result(name, siren):
        return {"nom_raison_sociale": name, "siren": siren}

    payload = {
        "results": [
            *[result(f"Other {i}", str(i)) for i in range(6)],
            result("Target", "111111111"),
            *[result(f"Other B{i}", f"B{i}") for i in range(7)],
            result("Target", "222222222"),
        ]
    }

    evaluated = bench.evaluate_payload("Target", payload)

    assert evaluated[5]["status"] == org_enrichment.NOT_FOUND
    assert evaluated[10] == {
        "status": org_enrichment.MATCHED,
        "siren": "111111111",
    }
    assert evaluated[20]["status"] == org_enrichment.AMBIGUOUS
