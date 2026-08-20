"""Incident-level consolidation of rich facts without destructive collapsing."""
from __future__ import annotations

from .rich_facts import divergence_groups, fact_history, merge_claims, primary_claim


def consolidate_sources(source_payloads: list[dict]) -> dict:
    """Combine rich facts from several sources while preserving every claim.

    `primary` is only a convenience projection for legacy UI. `claims`, `history`
    and `divergences` remain authoritative for provenance-aware rendering.
    """
    claims = merge_claims(*[
        payload.get("claims") or []
        for payload in source_payloads
        if isinstance(payload, dict)
    ])
    primary = {}
    for claim_type in sorted({str(c.get("type") or c.get("kind") or "statement") for c in claims}):
        value = primary_claim(claims, claim_type)
        if value:
            primary[claim_type] = value
    return {
        "claims": claims,
        "primary": primary,
        "history": fact_history(claims),
        "divergences": divergence_groups(claims),
    }
