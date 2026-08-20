"""FrenchBreaches collector using the shared evidence-first rich-facts model.

The source stays RSS-based. We reuse the conservative deterministic primitives
already certified on Cyberattaque.org, but deliberately do not enable its
source-specific LLM fallback here: FrenchBreaches must earn semantic expansion
through corpus metrics rather than inherit it implicitly.
"""
from __future__ import annotations

from .editorial_rich import EditorialRichFeedCollector
from . import cyberattaque_rich as deterministic


def extract_frenchbreaches_rich_facts(text: str) -> dict | None:
    sentences = deterministic._sentences(text)
    systems, datasets = deterministic._extract_scopes(sentences)
    rich = {
        "version": "2",
        "engine": "generic-rich-facts",
        "source_adapter": "frenchbreaches",
        "semantic": {"used": False},
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
    rich["profile"] = {
        "chars": len(text),
        "sentences": len(sentences),
        "claims": len(rich["claims"]),
        "hypotheses": sum(1 for c in rich["claims"] if c.get("status") == "hypothesis"),
    }
    if not any(
        rich.get(key)
        for key in (
            "claims", "timeline", "relations", "affected_systems", "affected_datasets",
            "data_volumes", "data_types", "vulnerabilities",
        )
    ):
        return None
    return rich


class FrenchBreachesRichCollector(EditorialRichFeedCollector):
    name = "frenchbreaches_rich"
    source_id = "FRENCHBREACHES"

    def extract_rich_facts(self, text: str) -> dict | None:
        return extract_frenchbreaches_rich_facts(text)
