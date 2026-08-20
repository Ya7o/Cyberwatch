"""Couche de clôture Performance : métriques préqual et verdict d'invariants."""
from __future__ import annotations

_INSTALLED = False


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    from . import incremental_performance as perf, incremental_runtime
    from .performance_gates import validate_performance_row

    original_save = perf._save_performance_row

    def save(row: dict) -> None:
        enriched = dict(row)
        enriched.update(incremental_runtime.last_stats())
        errors = validate_performance_row(enriched)
        enriched["performance_gate"] = "PASS" if not errors else "FAIL"
        enriched["performance_gate_errors"] = errors
        original_save(enriched)

    perf._save_performance_row = save
    _INSTALLED = True
