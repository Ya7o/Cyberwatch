from cyberwatch import source_facts as sf
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.model import Item


def test_frenchbreaches_fait_natif_prioritaire_sur_llm(monkeypatch):
    monkeypatch.setattr(sf.source_facts_ai, "enrich", lambda *_: {
        "affected_counts": [
            {"status": "confirmed", "confidence": .99, "evidence": "999 personnes"}
        ]
    })
    entry = RawEntry(
        title="Exemple SA",
        organisation="Exemple SA",
        content="Victimes : 1 023 victimes. Une autre phrase mentionne 999 personnes.",
    )
    item = Item(Item_ID="ITM-native-priority", Source_ID="FRENCHBREACHES", Organisation_Raw="Exemple SA")
    spec = SourceSpec(source_id="FRENCHBREACHES", layer="core", zone="France")

    fact = sf.extract_source_fact(item, entry, spec)

    assert fact["Affected_Count"] == "1023"
    assert fact["Affected_Unit"] == "people"
    assert fact["Affected_Count_Raw"] == "1 023 victimes"
