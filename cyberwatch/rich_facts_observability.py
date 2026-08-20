"""Cross-source rich-facts observability helpers."""
from __future__ import annotations

from collections import Counter
import json


def summarize_source_fact_rows(rows: list[dict]) -> dict:
    by_source = Counter()
    rich_by_source = Counter()
    claims_by_source = Counter()
    statuses = Counter()
    llm = Counter()
    for row in rows:
        source = str(row.get("Source_ID") or "UNKNOWN")
        by_source[source] += 1
        try:
            metadata = json.loads(row.get("Source_Metadata_JSON") or "{}")
        except (TypeError, ValueError):
            metadata = {}
        rich = metadata.get("rich_facts") if isinstance(metadata, dict) else None
        if not isinstance(rich, dict):
            continue
        rich_by_source[source] += 1
        claims = rich.get("claims") or []
        claims_by_source[source] += len(claims)
        for claim in claims:
            if isinstance(claim, dict):
                statuses[str(claim.get("status") or "unknown")] += 1
        if rich.get("semantic_used"):
            llm["articles_llm"] += 1
        if rich.get("semantic_cache_hit"):
            llm["cache_hits"] += 1
        llm["claims_rejected"] += int(rich.get("semantic_rejected") or 0)
    return {
        "articles_by_source": dict(sorted(by_source.items())),
        "rich_articles_by_source": dict(sorted(rich_by_source.items())),
        "claims_by_source": dict(sorted(claims_by_source.items())),
        "claim_statuses": dict(sorted(statuses.items())),
        "semantic": dict(sorted(llm.items())),
    }
