#!/usr/bin/env python3
"""Audit reproductible de la couverture riche Cyberattaque.org déjà matérialisée."""
from __future__ import annotations

import json
from collections import Counter

from cyberwatch import store


def main() -> None:
    rows = [r for r in store.load_source_facts() if r.get("Source_ID") == "CYBERATTAQUE_ORG"]
    stats = Counter()
    statuses = Counter()
    types = Counter()
    total_claims = 0
    for row in rows:
        try:
            metadata = json.loads(row.get("Source_Metadata_JSON") or "{}")
        except (TypeError, ValueError):
            metadata = {}
        rich = metadata.get("rich_facts") if isinstance(metadata, dict) else None
        if not isinstance(rich, dict):
            stats["without_rich_facts"] += 1
            continue
        stats["with_rich_facts"] += 1
        for key in ("affected_counts", "data_volumes", "data_types", "affected_systems", "affected_datasets", "timeline", "relations", "vulnerabilities"):
            values = rich.get(key) or []
            if values:
                stats[f"articles_with_{key}"] += 1
        claims = rich.get("claims") or []
        total_claims += len(claims)
        if len(claims) > 1:
            stats["articles_multi_claims"] += 1
        if any(c.get("status") == "hypothesis" for c in claims if isinstance(c, dict)):
            stats["articles_with_hypotheses"] += 1
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            statuses[str(claim.get("status") or "unknown")] += 1
            types[str(claim.get("type") or claim.get("kind") or "statement")] += 1

    payload = {
        "source": "CYBERATTAQUE_ORG",
        "articles": len(rows),
        "total_claims": total_claims,
        "coverage": dict(sorted(stats.items())),
        "claim_statuses": dict(sorted(statuses.items())),
        "claim_types": dict(sorted(types.items())),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
