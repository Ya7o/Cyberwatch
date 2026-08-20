import json

from cyberwatch.collectors import editorial_semantic
from cyberwatch.collectors.frenchbreaches_rich import extract_frenchbreaches_rich_facts
from cyberwatch.rich_facts_observability import summarize_source_fact_rows
from cyberwatch.rich_facts_policy import semantic_decision


def _row(source, rich):
    return {
        "Source_ID": source,
        "Source_Metadata_JSON": json.dumps({"rich_facts": rich}, ensure_ascii=False),
    }


def test_frenchbreaches_keeps_profile_when_no_claim_is_extractable(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("RICH_FACTS_SEMANTIC_SOURCES", raising=False)
    rich = extract_frenchbreaches_rich_facts("Une organisation publie un bref avis de sécurité sans autre détail.")
    assert rich is not None
    assert rich["claims"] == []
    assert rich["profile"]["claims"] == 0
    assert rich["semantic"]["used"] is False


def test_semantic_is_opt_in_per_source(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("RICH_FACTS_SEMANTIC_SOURCES", "FRENCHBREACHES")
    assert editorial_semantic.enabled_for("FRENCHBREACHES") is True
    assert editorial_semantic.enabled_for("CYBERATTAQUE_ORG") is False


def test_candidate_detection_does_not_require_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert editorial_semantic.is_candidate(
        "Le groupe revendique une fuite. Les données pourraient inclure des documents RH.",
        {"affected_counts": [], "data_volumes": [], "timeline": [], "relations": [], "data_types": []},
    ) is True


def test_observability_exposes_source_quality_and_semantic_metrics():
    report = summarize_source_fact_rows([
        _row("FRENCHBREACHES", {
            "claims": [],
            "profile": {"semantic_candidate": True},
            "semantic": {"used": False, "candidate": True},
        }),
        _row("FRENCHBREACHES", {
            "claims": [{"type": "affected_count", "status": "claimed", "value": 42, "evidence": "42 comptes"}],
            "profile": {"semantic_candidate": True},
            "semantic": {"used": True, "candidate": True, "cache_hit": True, "rejected": 2},
        }),
    ])
    quality = report["source_quality"]["FRENCHBREACHES"]
    assert quality["articles"] == 2
    assert quality["rich_articles"] == 2
    assert quality["zero_claim_articles"] == 1
    assert quality["semantic_candidates"] == 2
    assert quality["semantic_used"] == 1
    assert quality["semantic_cache_hits"] == 1
    assert quality["semantic_rejected"] == 2
    assert quality["claims_without_evidence"] == 0


def test_policy_enables_llm_only_for_measured_deterministic_gap():
    report = {
        "source_quality": {
            "FRENCHBREACHES": {
                "articles": 20,
                "rich_articles": 20,
                "semantic_candidates": 10,
                "zero_claim_articles": 6,
                "avg_claims_per_rich_article": 0.9,
                "claims_without_evidence": 0,
            }
        }
    }
    decision = semantic_decision(report, "FRENCHBREACHES")
    assert decision["use_llm"] is True


def test_policy_refuses_llm_when_deterministic_coverage_is_sufficient():
    report = {
        "source_quality": {
            "FRENCHBREACHES": {
                "articles": 20,
                "rich_articles": 20,
                "semantic_candidates": 5,
                "zero_claim_articles": 1,
                "avg_claims_per_rich_article": 2.4,
                "claims_without_evidence": 0,
            }
        }
    }
    decision = semantic_decision(report, "FRENCHBREACHES")
    assert decision["use_llm"] is False
    assert decision["reason"] == "couverture déterministe suffisante"


def test_policy_blocks_llm_if_claims_without_evidence_exist():
    report = {
        "source_quality": {
            "FRENCHBREACHES": {
                "articles": 20,
                "rich_articles": 20,
                "semantic_candidates": 12,
                "zero_claim_articles": 8,
                "avg_claims_per_rich_article": 0.4,
                "claims_without_evidence": 1,
            }
        }
    }
    decision = semantic_decision(report, "FRENCHBREACHES")
    assert decision["use_llm"] is False
    assert "sans preuve" in decision["reason"]
