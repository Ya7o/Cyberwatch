from __future__ import annotations

import datetime as dt

from scripts import enrich_sector_queue as mod
from cyberwatch import org_enrichment


NOW = dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.timezone.utc)


def _row(key: str) -> dict[str, str]:
    return {"Organisation_Key": key, "Organisation": key.title()}


def _cache(status: str, fetched_at: str) -> dict[str, str]:
    return {"Match_Status": status, "Fetched_At": fetched_at}


def test_sector_only_skips_fresh_negative_cache(monkeypatch):
    monkeypatch.delenv("SECTOR_ENRICHMENT_TARGET_KEYS", raising=False)
    queue = [_row("alpha"), _row("beta")]
    cache = {
        "alpha": _cache(org_enrichment.NOT_FOUND, "2026-08-18T12:00:00+00:00"),
    }

    selected, stats = mod._select_queue_rows(queue, cache, "sector-only", NOW)

    assert [row["Organisation_Key"] for row in selected] == ["beta"]
    assert stats["skipped_fresh_cache"] == 1


def test_sector_only_retries_expired_error_cache(monkeypatch):
    monkeypatch.delenv("SECTOR_ENRICHMENT_TARGET_KEYS", raising=False)
    queue = [_row("alpha")]
    cache = {
        "alpha": _cache(org_enrichment.ERROR, "2026-08-19T04:00:00+00:00"),
    }

    selected, _stats = mod._select_queue_rows(queue, cache, "sector-only", NOW)

    assert [row["Organisation_Key"] for row in selected] == ["alpha"]


def test_explicit_targets_bound_golden_only_scope(monkeypatch):
    monkeypatch.setenv("SECTOR_ENRICHMENT_TARGET_KEYS", "beta,gamma")
    queue = [_row("alpha"), _row("beta"), _row("gamma")]

    selected, stats = mod._select_queue_rows(queue, {}, "golden-only", NOW)

    assert [row["Organisation_Key"] for row in selected] == ["beta", "gamma"]
    assert stats["skipped_scope"] == 1


def test_full_ignores_cache_freshness(monkeypatch):
    monkeypatch.delenv("SECTOR_ENRICHMENT_TARGET_KEYS", raising=False)
    queue = [_row("alpha")]
    cache = {
        "alpha": _cache(org_enrichment.MATCHED, "2026-08-19T11:59:00+00:00"),
    }

    selected, stats = mod._select_queue_rows(queue, cache, "full", NOW)

    assert [row["Organisation_Key"] for row in selected] == ["alpha"]
    assert stats["skipped_fresh_cache"] == 0


def test_matched_cache_has_long_retry_window(monkeypatch):
    monkeypatch.delenv("SECTOR_ENRICHMENT_TARGET_KEYS", raising=False)
    recent = _cache(org_enrichment.MATCHED, "2026-08-01T12:00:00+00:00")
    old = _cache(org_enrichment.MATCHED, "2026-07-01T12:00:00+00:00")

    assert mod._cache_fresh(recent, NOW) is True
    assert mod._cache_fresh(old, NOW) is False
