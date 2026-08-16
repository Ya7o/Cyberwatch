"""Garde-fous du rebuild : budget HTTP et diagnostic des sources."""
from __future__ import annotations

from cyberwatch import http, sources, status
from cyberwatch.collectors.base import Window
from cyberwatch.collectors.ransomware_live import RansomwareLiveCollector


def test_budget_temps_http_ignore_le_temps_mural_hors_fetch(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(http.time, "monotonic", lambda: clock[0])
    budget = http.Budget(max_requests=10, max_seconds=5, label="run")

    # Simule 30 minutes passées dans un autre pipeline (ex. OpenAI) : le
    # budget HTTP ne doit pas bouger tant qu'aucun fetch ne l'a consommé.
    clock[0] += 30 * 60
    assert budget.elapsed == 0
    assert not budget.exhausted

    budget.consume_seconds(5.1)
    assert budget.exhausted


def test_budget_requetes_reste_independant_du_budget_temps():
    budget = http.Budget(max_requests=2, max_seconds=999, label="run")
    budget.consume()
    assert not budget.exhausted
    budget.consume()
    assert budget.exhausted


def test_ransomware_live_conserve_budget_run_comme_cause():
    spec = next(s for s in sources.CORE_SOURCES if s.source_id == "RANSOMWARE_LIVE")

    class FakeClient:
        def __init__(self):
            self.budget = http.Budget(max_requests=60, max_seconds=180, label="source")

        def source_budget(self):
            return self.budget

        def fetch(self, url, source_budget):
            del source_budget
            return http.FetchResult(False, url, reason_code=status.REASON_BUDGET_RUN)

    result = RansomwareLiveCollector().collect(
        FakeClient(), spec, Window("2026-01-01", "2026-08-16")
    )
    assert result.reason_code == status.REASON_BUDGET_RUN
    assert result.units_done == 0
    assert result.status_override == status.FAIL
