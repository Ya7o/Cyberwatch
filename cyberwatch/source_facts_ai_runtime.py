"""État, cache et télémétrie du runtime d'extraction sémantique."""

from __future__ import annotations

import atexit
import json
import math
import os
from collections import Counter
from pathlib import Path

from .source_facts_ai_contract import (
    CACHE_FORMAT,
    DEFAULT_MODEL,
    PROMPT_VERSION,
    SCHEMA_VERSION,
)

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _cache_path() -> Path:
    value = os.getenv("SOURCE_FACTS_AI_CACHE_PATH", "").strip()
    return Path(value) if value else Path(__file__).resolve().parents[1] / "data" / "source_facts_ai_cache.json"


def _stats_path() -> Path:
    value = os.getenv("SOURCE_FACTS_AI_STATS_PATH", "").strip()
    return Path(value) if value else Path(__file__).resolve().parents[1] / "data" / "source_facts_ai_usage.json"


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


class SourceFactsAiError(Exception):
    pass


class _Runtime:
    def __init__(self) -> None:
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
        flag = os.getenv("SOURCE_FACTS_AI_ENABLED", "1").strip().lower()
        self.enabled = bool(self.api_key) and flag not in {"0", "false", "no", "off"}
        self.disabled_reason = ("API_KEY_MISSING" if not self.api_key else
                                "FLAG_DISABLED" if not self.enabled else "")
        retry_legacy = os.getenv("SOURCE_FACTS_AI_RETRY_LEGACY_NULLS", "0").strip().lower()
        self.retry_legacy_nulls = retry_legacy not in {"0", "false", "no", "off"}
        self.model = os.getenv("SOURCE_FACTS_AI_MODEL", os.getenv("OPENAI_MODEL", DEFAULT_MODEL)).strip() or DEFAULT_MODEL
        self.max_calls = _env_int("SOURCE_FACTS_AI_MAX_CALLS_PER_RUN", 30)
        self.max_cost = _env_float("SOURCE_FACTS_AI_MAX_COST_USD_PER_RUN", 0.50)
        self.max_context_chars = _env_int("SOURCE_FACTS_AI_MAX_CONTEXT_CHARS", 10000)
        self.max_output_tokens = _env_int("SOURCE_FACTS_AI_MAX_OUTPUT_TOKENS", 1200)
        self.checkpoint_every = max(1, _env_int("SOURCE_FACTS_AI_CHECKPOINT_EVERY", 25))
        self.progress_every = max(1, _env_int("SOURCE_FACTS_AI_PROGRESS_EVERY", 25))
        self.calls = 0
        self.calls_succeeded = 0
        self.calls_failed = 0
        self.calls_budget_blocked = 0
        self.cache_hits = 0
        # field_cache_hits reste le compteur agrégé historique. Les compteurs
        # suivants distinguent désormais une valeur réellement réutilisée
        # d'une abstention mémorisée, afin de ne plus présenter les deux comme
        # un même "cache hit" dans les audits de rebuild.
        self.field_cache_hits = 0
        self.accepted_field_cache_hits = 0
        self.abstained_field_cache_hits = 0
        self.legacy_null_migrations = 0
        self.legacy_null_skips = 0
        self.semantic_first_misses = 0
        self.semantic_retries = 0
        self.semantic_recovered_on_retry = 0
        self.semantic_new_abstentions = 0
        self.legacy_field_cache_hits = 0
        self.fields_invalidated = 0
        self.items_fully_cached = 0
        self.items_partially_cached = 0
        self.items_eligible = 0
        self.items_would_call = 0
        self.skipped_no_missing_fields = 0
        self.retries = 0
        self.timeouts = 0
        self.http_429 = 0
        self.http_5xx = 0
        self.cost = 0.0
        self.input_tokens = 0
        self.output_tokens = 0
        self.durations: list[float] = []
        self.fields_requested: Counter[str] = Counter()
        self.fields_requested_new: Counter[str] = Counter()
        self.error_reasons: Counter[str] = Counter()
        self.trace_events: list[dict] = []
        self.effective_model = ""
        self.run_id = ""
        self.cache_path = _cache_path()
        self.stats_path = _stats_path()
        self.legacy_cache: dict[str, dict] = {}
        self.cache = self._load_cache()

    def _load_cache(self) -> dict[str, dict]:
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        if payload.get("_format") == CACHE_FORMAT:
            legacy = payload.get("legacy")
            self.legacy_cache = legacy if isinstance(legacy, dict) else {}
            entries = payload.get("entries")
            return entries if isinstance(entries, dict) else {}
        self.legacy_cache = payload
        return {}

    def save_cache(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
            payload = {"_format": CACHE_FORMAT, "entries": self.cache, "legacy": self.legacy_cache}
            tmp.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            tmp.replace(self.cache_path)
        except OSError:
            return

    def record_event(self, **event) -> None:
        """Journal borné au run courant, sans en-têtes HTTP ni clé API."""
        from datetime import datetime, timezone
        self.trace_events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "github_run_id": os.getenv("GITHUB_RUN_ID", ""),
            "run_id": self.run_id,
            "requested_model": self.model, "effective_model": self.effective_model,
            "prompt_version": PROMPT_VERSION, "schema_version": SCHEMA_VERSION,
            **event,
        })

    def save_trace(self) -> None:
        if not self.trace_events and not self.run_id:
            return
        path = self.cache_path.parent / "source_facts_ai_trace.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.trace_events, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def stats(self) -> dict:
        total = sum(self.durations)
        return {
            "run_id": self.run_id,
            "enabled": self.enabled,
            "disabled_reason": self.disabled_reason,
            "model": self.model,
            "requested_model": self.model,
            "effective_model": self.effective_model,
            "prompt_version": PROMPT_VERSION,
            "schema_version": SCHEMA_VERSION,
            "cache_format": CACHE_FORMAT,
            "items_eligible": self.items_eligible,
            "items_would_call": self.items_would_call,
            "items_skipped_no_missing_fields": self.skipped_no_missing_fields,
            "items_fully_cached": self.items_fully_cached,
            "items_partially_cached": self.items_partially_cached,
            "cache_hits": self.cache_hits,
            "field_cache_hits": self.field_cache_hits,
            "accepted_field_cache_hits": self.accepted_field_cache_hits,
            "abstained_field_cache_hits": self.abstained_field_cache_hits,
            "legacy_null_migrations": self.legacy_null_migrations,
            "legacy_null_skips": self.legacy_null_skips,
            "semantic_first_misses": self.semantic_first_misses,
            "semantic_retries": self.semantic_retries,
            "semantic_recovered_on_retry": self.semantic_recovered_on_retry,
            "semantic_new_abstentions": self.semantic_new_abstentions,
            "legacy_field_cache_hits": self.legacy_field_cache_hits,
            "fields_invalidated": self.fields_invalidated,
            "calls_attempted": self.calls,
            "calls_success": self.calls_succeeded,
            "calls_failed": self.calls_failed,
            "calls_budget_blocked": self.calls_budget_blocked,
            "retries": self.retries,
            "timeouts": self.timeouts,
            "http_429": self.http_429,
            "http_5xx": self.http_5xx,
            "total_duration_seconds": round(total, 3),
            "average_duration_seconds": round(total / self.calls, 3) if self.calls else 0.0,
            "p50_duration_seconds": round(_percentile(self.durations, 0.50), 3),
            "p95_duration_seconds": round(_percentile(self.durations, 0.95), 3),
            "max_duration_seconds": round(max(self.durations), 3) if self.durations else 0.0,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "estimated_cost_usd": round(self.cost, 6),
            "fields_requested": dict(sorted(self.fields_requested.items())),
            "fields_requested_new": dict(sorted(self.fields_requested_new.items())),
            "error_reasons": dict(sorted(self.error_reasons.items())),
        }

    def save_stats(self) -> None:
        if not self.run_id and not self.trace_events and self.calls == 0 and self.calls_budget_blocked == 0:
            return
        try:
            self.stats_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.stats_path.with_suffix(self.stats_path.suffix + ".tmp")
            tmp.write_text(json.dumps(self.stats(), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            tmp.replace(self.stats_path)
            if self.run_id:
                history = self.stats_path.parent / "llm_runs" / "".join(c for c in self.run_id if c.isalnum() or c in "-_")
                history.mkdir(parents=True, exist_ok=True)
                (history / self.stats_path.name).write_text(json.dumps(self.stats(), indent=2) + "\n", encoding="utf-8")
        except OSError:
            return

    def checkpoint(self, force: bool = False) -> None:
        if force or (self.calls and self.calls % self.checkpoint_every == 0):
            self.save_cache()
            self.save_stats()
            self.save_trace()

    def progress(self) -> None:
        if not self.calls or self.calls % self.progress_every:
            return
        stats = self.stats()
        print(
            "SourceFacts AI: "
            f"calls={self.calls} success={self.calls_succeeded} fail={self.calls_failed} "
            f"full_cache={self.items_fully_cached} partial_cache={self.items_partially_cached} "
            f"avg={stats['average_duration_seconds']:.2f}s p95={stats['p95_duration_seconds']:.2f}s "
            f"cost=${self.cost:.4f}",
            flush=True,
        )


_RUNTIME: _Runtime | None = None


def _runtime() -> _Runtime:
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = _Runtime()
    return _RUNTIME


def _flush_runtime() -> None:
    if _RUNTIME is not None:
        _RUNTIME.checkpoint(force=True)


atexit.register(_flush_runtime)


def reset_runtime_for_tests() -> None:
    global _RUNTIME
    _RUNTIME = None


def runtime_stats() -> dict:
    return _runtime().stats()
