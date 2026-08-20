from __future__ import annotations

from cyberwatch.collectors.base import RawEntry
from cyberwatch.collectors.cyberattaque_rich import enrich_entry_metadata
from cyberwatch.collectors import cyberattaque_semantic


def _rich(content: str):
    entry = RawEntry(title="Incident", summary="", content=content)
    enrich_entry_metadata(entry)
    return entry.source_metadata["rich_facts"]


def test_hypothetical_data_types_are_not_promoted_to_confirmed():
    rich = _rich(
        "Le groupe revendique 160,20 Go de données. Les données pourraient comprendre "
        "des documents RH et des adresses e-mail, mais aucun inventaire n'est confirmé."
    )
    types = rich["data_types"]
    assert any(row["value"] == "données RH" and row["status"] == "hypothesis" for row in types)
    assert any(row["value"] == "adresses e-mail" and row["status"] == "hypothesis" for row in types)
    assert not any(row["status"] == "confirmed" for row in types)


def test_negated_scope_is_kept_as_negated_not_affected_fact():
    rich = _rich(
        "La Commission confirme l'incident. Les systèmes internes n'ont pas été touchés. "
        "Le 27 mars 2026, l'incident a été rendu public."
    )
    assert any(row["status"] == "negated" for row in rich["claims"] if row.get("evidence") and "pas été touchés" in row["evidence"]) is False
    assert any(row["date"] == "2026-03-27" for row in rich["timeline"])


def test_multiple_volumes_counts_dates_and_cves_survive():
    rich = _rich(
        "Le 19 mars 2026, les attaquants ont compromis un secret cloud. "
        "Le groupe affirme avoir volé 91,7 Go compressés, soit environ 340 Go après décompression, "
        "concernant 71 clients. L'incident mentionne CVE-2026-12345."
    )
    volumes = {(row["value"], row["unit"]) for row in rich["data_volumes"]}
    assert (91.7, "GO") in volumes
    assert (340.0, "GO") in volumes
    assert any(row["value"] == 71 and row["unit"] == "clients" for row in rich["affected_counts"])
    assert any(row["value"] == "CVE-2026-12345" for row in rich["vulnerabilities"])
    assert any(row["date"] == "2026-03-19" for row in rich["timeline"])


def test_semantic_validator_rejects_invented_evidence_and_numbers():
    article = "La société confirme que 42 comptes ont été compromis."
    assert cyberattaque_semantic._clean_claim(
        {"type": "affected_count", "status": "confirmed", "value": 42, "unit": "accounts", "evidence": article}, article
    )
    assert cyberattaque_semantic._clean_claim(
        {"type": "affected_count", "status": "confirmed", "value": 9000, "unit": "accounts", "evidence": article}, article
    ) is None
    assert cyberattaque_semantic._clean_claim(
        {"type": "statement", "status": "confirmed", "value": "x", "evidence": "phrase inventée"}, article
    ) is None


def test_semantic_llm_is_disabled_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert cyberattaque_semantic.should_use_llm("x" * 6000, {"claims": []}) is False
