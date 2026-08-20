"""Policy decisions for optional semantic rich-facts enrichment.

The policy is deliberately conservative. It recommends the LLM only when a source
contains a meaningful share of structurally rich/ambiguous articles for which the
deterministic pass still returns little or no factual structure.
"""
from __future__ import annotations


def semantic_decision(report: dict, source_id: str, *, min_articles: int = 8) -> dict:
    source = str(source_id or "").strip().upper()
    quality = (report.get("source_quality") or {}).get(source) or {}
    articles = int(quality.get("articles") or 0)
    rich_articles = int(quality.get("rich_articles") or 0)
    candidates = int(quality.get("semantic_candidates") or 0)
    zero_claims = int(quality.get("zero_claim_articles") or 0)
    avg_claims = float(quality.get("avg_claims_per_rich_article") or 0.0)
    missing_evidence = int(quality.get("claims_without_evidence") or 0)

    candidate_ratio = candidates / rich_articles if rich_articles else 0.0
    zero_ratio = zero_claims / rich_articles if rich_articles else 0.0
    enough_sample = articles >= min_articles

    # Semantic expansion is justified only when ambiguity/richness is common and
    # deterministic structure is measurably thin. Missing evidence is a blocker,
    # because semantic expansion must not hide an extraction-quality regression.
    use_llm = bool(
        enough_sample
        and missing_evidence == 0
        and candidate_ratio >= 0.20
        and (zero_ratio >= 0.15 or avg_claims < 1.50)
    )

    if not enough_sample:
        reason = f"échantillon insuffisant ({articles} < {min_articles})"
    elif missing_evidence:
        reason = f"{missing_evidence} claims sans preuve; corriger la qualité avant tout LLM"
    elif candidate_ratio < 0.20:
        reason = f"articles ambigus trop rares ({candidate_ratio:.0%})"
    elif zero_ratio >= 0.15:
        reason = f"{zero_ratio:.0%} des articles riches restent sans claim"
    elif avg_claims < 1.50:
        reason = f"profondeur déterministe faible ({avg_claims:.2f} claim/article)"
    else:
        reason = "couverture déterministe suffisante"

    return {
        "source": source,
        "use_llm": use_llm,
        "reason": reason,
        "articles": articles,
        "rich_articles": rich_articles,
        "semantic_candidates": candidates,
        "semantic_candidate_ratio": round(candidate_ratio, 4),
        "zero_claim_articles": zero_claims,
        "zero_claim_ratio": round(zero_ratio, 4),
        "avg_claims_per_rich_article": round(avg_claims, 3),
        "claims_without_evidence": missing_evidence,
    }
