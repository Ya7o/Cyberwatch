"""Source facts LLM : grounding, cache et budget, sans appel réseau réel."""
from __future__ import annotations

import json

from cyberwatch import source_facts_ai as sfa
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Item


def _item(source="CYBERATTAQUE_ORG"):
    return Item(
        Item_ID="ITM-ai", Source_ID=source, Organisation_Raw="Exemple SA",
        Published_Date="2026-08-16",
    )


def _payload(output: dict):
    return {
        "output_text": json.dumps(output, ensure_ascii=False),
        "usage": {"input_tokens": 100, "output_tokens": 50},
    }


def _empty_output():
    blank = {"value": "", "confidence": 0.0, "evidence": ""}
    return {
        "summary": blank,
        "activity_description": blank,
        "threat_actor": blank,
        "third_party": blank,
        "claim_status": blank,
        "impact": blank,
        "data_types": [],
        "affected_counts": [],
        "data_volumes": [],
        "file_counts": [],
    }


def test_pas_de_cle_pas_dappel(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    called = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: called.append(True))
    assert sfa.enrich(_item(), RawEntry(title="X", content="Incident")) is None
    assert not called


def test_grounding_et_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    calls = []

    output = _empty_output()
    output.update({
        "summary": {
            "value": "Une fuite de données est confirmée.",
            "confidence": .9,
            "evidence": "confirme une fuite de données",
        },
        "threat_actor": {
            "value": "LockBit",
            "confidence": .95,
            "evidence": "revendiquée par LockBit",
        },
        "data_types": [
            {"value": "adresses e-mail", "confidence": .92, "evidence": "adresses e-mail exposées"}
        ],
        "affected_counts": [
            {"status": "confirmed", "confidence": .94, "evidence": "138 000 personnes confirmées"}
        ],
    })

    def fake_post(*_args):
        calls.append(1)
        return _payload(output)

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    entry = RawEntry(
        title="Exemple SA",
        content="Exemple SA confirme une fuite de don~ées revendiquée par LockBit. 138 000 personnes confirmées, adresses e-mail exposées.",
    )
    first = sfa.enrich(_item(), entry)
    second = sfa.enrich(_item(), entry)
    assert len(calls) == 1
    assert first == second
    assert first["threat_actor"]["value"] == "LockBit"
    assert first["affected_counts"][0]["status"] == "confirmed"
    assert (tmp_path / "cache.json").exists()


def test_evidence_non_presente_est_rejetee(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    output = _empty_output()
    output["threat_actor"] = {
        "value": "LockBit", "confidence": .99, "evidence": "texte inventé absent"
    }
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: _payload(output))
    result = sfa.enrich(_item(), RawEntry(title="Exemple", content="Aucun acteur n'est cité."))
    assert "threat_actor" not in result


def test_changement_contenu_invalide_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    calls = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: calls.append(1) or _payload(_empty_output()))
    sfa.enrich(_item(), RawEntry(title="Exemple", content="Version un"))
    sfa.enrich(_item(), RawEntry(title="Exemple", content="Version deux"))
    assert len(calls) == 2


def test_autres_sources_jamais_envoyees_au_llm(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    called = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: called.append(1))
    item = _item("BONJOURLAFUITE")
    assert sfa.enrich(item, RawEntry(title="X", content="Données")) is None
    assert not called


def test_acteur_et_tiers_doivent_etre_nommes_dans_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    output = _empty_output()
    output["threat_actor"] = {"value": "LockBit", "confidence": .99, "evidence": "incident confirmé"}
    output["third_party"] = {"value": "Example Cloud", "confidence": .99, "evidence": "via un prestataire externe"}
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: _payload(output))
    result = sfa.enrich(_item(), RawEntry(title="Exemple", content="incident confirmé via un prestataire externe"))
    assert "threat_actor" not in result
    assert "third_party" not in result


def test_tiers_nomme_dans_evidence_est_accepte(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    output = _empty_output()
    output["third_party"] = {"value": "Example Cloud", "confidence": .99, "evidence": "prestataire Example Cloud"}
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: _payload(output))
    result = sfa.enrich(_item(), RawEntry(title="Exemple", content="incident via le prestataire Example Cloud"))
    assert result["third_party"]["value"] == "Example Cloud"
