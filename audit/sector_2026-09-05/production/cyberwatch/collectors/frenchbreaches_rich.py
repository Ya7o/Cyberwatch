"""FrenchBreaches adapter for the shared evidence-first rich-facts model.

The deterministic pass is always used. A generic semantic fallback exists but is
strictly opt-in through RICH_FACTS_SEMANTIC_SOURCES; the closeout workflow enables
it only when corpus metrics show that deterministic coverage is insufficient.
"""
from __future__ import annotations

from .editorial_rich import EditorialRichFeedCollector
from . import cyberattaque_rich as deterministic
from . import editorial_semantic


def extract_frenchbreaches_rich_facts(text: str) -> dict | None:
    sentences = deterministic._sentences(text)
    systems, datasets = deterministic._extract_scopes(sentences)
    rich = {
        "version": "2",
        "engine": "generic-rich-facts",
        "source_adapter": "frenchbreaches",
        "affected_counts": deterministic._extract_counts(sentences),
        "data_volumes": deterministic._extract_volumes(sentences),
        "data_types": deterministic._extract_data_types(sentences),
        "affected_systems": systems,
        "affected_datasets": datasets,
        "timeline": deterministic._extract_timeline(sentences),
        "relations": deterministic._extract_relations(sentences),
        "vulnerabilities": [
            {
                "value": value.upper(),
                "status": "reported",
                "evidence": next((s[:420] for s in sentences if value.lower() in s.lower()), ""),
            }
            for value in sorted(set(deterministic._CVE_RE.findall(text)))
        ],
    }
    rich["claims"] = deterministic._claims_from_deterministic(rich)
    candidate = editorial_semantic.is_candidate(text, rich)
    semantic = editorial_semantic.enrich(text, rich, source_id="FRENCHBREACHES")
    if semantic:
        deterministic._merge_semantic(rich, semantic)
        rich["semantic"] = {
            "used": True,
            "candidate": candidate,
            "model": semantic.get("model", ""),
            "prompt_version": semantic.get("prompt_version", ""),
            "cache_hit": bool(semantic.get("cache_hit")),
            "rejected": int(semantic.get("rejected") or 0),
        }
    else:
        rich["semantic"] = {"used": False, "candidate": candidate}
    rich["profile"] = {
        "chars": len(text),
        "sentences": len(sentences),
        "claims": len(rich["claims"]),
        "hypotheses": sum(1 for c in rich["claims"] if c.get("status") == "hypothesis"),
        "semantic_candidate": candidate,
    }
    # Keep a profile even when no factual claim is extractable. Corpus audits need
    # to distinguish a genuinely poor article from a collector that did not run.
    return rich if text.strip() else None


class FrenchBreachesRichCollector(EditorialRichFeedCollector):
    name = "frenchbreaches_rich"
    source_id = "FRENCHBREACHES"

    def extract_rich_facts(self, text: str) -> dict | None:
        return extract_frenchbreaches_rich_facts(text)
