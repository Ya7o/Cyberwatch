"""Cross-source rich-facts observability helpers."""
from __future__ import annotations

from collections import Counter, defaultdict
import json


def summarize_source_fact_rows(rows: list[dict]) -> dict:
    by_source = Counter()
    rich_by_source = Counter()
    claims_by_source = Counter()
    zero_claims_by_source = Counter()
    semantic_candidates_by_source = Counter()
    semantic_used_by_source = Counter()
    cache_hits_by_source = Counter()
    rejected_by_source = Counter()
    evidence_missing_by_source = Counter()
    hypotheses_by_source = Counter()
    statuses = Counter()
    types = Counter()
    claim_counts: dict[str, list[int]] = defaultdict(list)

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
        claims = [claim for claim in (rich.get("claims") or []) if isinstance(claim, dict)]
        claims_by_source[source] += len(claims)
        claim_counts[source].append(len(claims))
        if not claims:
            zero_claims_by_source[source] += 1

        profile = rich.get("profile") if isinstance(rich.get("profile"), dict) else {}
        semantic = rich.get("semantic") if isinstance(rich.get("semantic"), dict) else {}
        candidate = bool(profile.get("semantic_candidate") or semantic.get("candidate"))
        if candidate:
            semantic_candidates_by_source[source] += 1
        if semantic.get("used"):
            semantic_used_by_source[source] += 1
        if semantic.get("cache_hit"):
            cache_hits_by_source[source] += 1
        rejected_by_source[source] += int(semantic.get("rejected") or 0)

        for claim in claims:
            status = str(claim.get("status") or "unknown")
            ctype = str(claim.get("type") or claim.get("kind") or "statement")
            statuses[status] += 1
            types[ctype] += 1
            if not str(claim.get("evidence") or "").strip():
                evidence_missing_by_source[source] += 1
            if status == "hypothesis":
                hypotheses_by_source[source] += 1

    source_quality = {}
    for source in sorted(by_source):
        total = by_source[source]
        rich = rich_by_source[source]
        counts = claim_counts.get(source) or []
        claims = claims_by_source[source]
        candidates = semantic_candidates_by_source[source]
        zero_claims = zero_claims_by_source[source]
        source_quality[source] = {
            "articles": total,
            "rich_articles": rich,
            "rich_coverage": round(rich / total, 4) if total else 0.0,
            "claims": claims,
            "avg_claims_per_rich_article": round(sum(counts) / len(counts), 3) if counts else 0.0,
            "zero_claim_articles": zero_claims,
            "zero_claim_ratio": round(zero_claims / rich, 4) if rich else 0.0,
            "semantic_candidates": candidates,
            "semantic_candidate_ratio": round(candidates / rich, 4) if rich else 0.0,
            "semantic_used": semantic_used_by_source[source],
            "semantic_cache_hits": cache_hits_by_source[source],
            "semantic_rejected": rejected_by_source[source],
            "claims_without_evidence": evidence_missing_by_source[source],
            "hypotheses": hypotheses_by_source[source],
        }

    return {
        "articles_by_source": dict(sorted(by_source.items())),
        "rich_articles_by_source": dict(sorted(rich_by_source.items())),
        "claims_by_source": dict(sorted(claims_by_source.items())),
        "claim_statuses": dict(sorted(statuses.items())),
        "claim_types": dict(sorted(types.items())),
        "source_quality": source_quality,
        "semantic": {
            "candidates_by_source": dict(sorted(semantic_candidates_by_source.items())),
            "used_by_source": dict(sorted(semantic_used_by_source.items())),
            "cache_hits_by_source": dict(sorted(cache_hits_by_source.items())),
            "rejected_by_source": dict(sorted(rejected_by_source.items())),
        },
    }
