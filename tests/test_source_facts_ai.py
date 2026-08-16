"""Source facts LLM : préflight, grounding, cache, budget et télémétrie."""
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


def _output_for(body: dict, **values):
    result = {}
    properties = body["text"]["format"]["schema"]["properties"]
    for field in properties:
        if field in {"data_types", "affected_counts", "data_volumes", "file_counts"}:
            result[field] = values.get(field, [])
        else:
            result[field] = values.get(
                field, {"value": "", "confidence": 0.0, "evidence": ""}
            )
    return result


def _configure(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    sfa.reset_runtime_for_tests()


def test_pas_de_cle_pas_dappel(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    called = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: called.append(True))
    assert sfa.enrich(_item(), RawEntry(title="X", content="Incident")) is None
    assert not called


def test_types_de_donnees_deterministes_sans_api(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    sfa.reset_runtime_for_tests()
    entry = RawEntry(
        title="Exemple",
        content="Une fuite a exposé des adresses e-mail et des numéros de téléphone.",
    )
    result = sfa.enrich(_item(), entry)
    values = {fact["value"] for fact in result["data_types"]}
    assert "adresses e-mail" in values
    assert "numéros de téléphone" in values
    assert sfa.runtime_stats()["calls_attempted"] == 0


def test_preflight_deterministe_evite_appel(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    called = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: called.append(True))
    entry = RawEntry(
        title="Exemple SA",
        content="L'attaque a été revendiquée par LockBit.",
    )
    assert sfa.fields_needed_for_ai(_item(), entry) == set()
    assert sfa.enrich(_item(), entry) is None
    assert not called
    assert sfa.runtime_stats()["items_skipped_no_missing_fields"] == 1


def test_schema_dynamique_acteur_uniquement_plus_resume(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    bodies = []

    def fake_post(body, _runtime):
        bodies.append(body)
        return _payload(_output_for(
            body,
            summary={
                "value": "L'attaque est attribuée à LockBit.",
                "confidence": .9,
                "evidence": "attaque a été attribuée à LockBit",
            },
            threat_actor={
                "value": "LockBit",
                "confidence": .95,
                "evidence": "attaque a été attribuée à LockBit",
            },
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(
        _item(), RawEntry(title="Exemple", content="L'attaque a été attribuée à LockBit.")
    )
    assert len(bodies) == 1
    props = set(bodies[0]["text"]["format"]["schema"]["properties"])
    assert props == {"summary", "threat_actor"}
    assert result["threat_actor"]["value"] == "LockBit"


def test_evidence_non_presente_est_rejetee(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    def fake_post(body, _runtime):
        return _payload(_output_for(
            body,
            threat_actor={
                "value": "LockBit", "confidence": .99, "evidence": "texte inventé absent"
            },
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(
        _item(), RawEntry(title="Exemple", content="L'attaque est attribuée à LockBit.")
    ) or {}
    assert "threat_actor" not in result


def test_acteur_et_tiers_doivent_etre_nommes_dans_evidence(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    def fake_post(body, _runtime):
        return _payload(_output_for(
            body,
            threat_actor={"value": "LockBit", "confidence": .99, "evidence": "incident attribué"},
            third_party={"value": "Example Cloud", "confidence": .99, "evidence": "via le prestataire externe"},
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(
        _item(),
        RawEntry(
            title="Exemple",
            content=(
                "Incident attribué à LockBit. La victime indique être hébergée via le "
                "prestataire externe Example Cloud, affecté par l'incident."
            ),
        ),
    ) or {}
    assert "threat_actor" not in result
    assert "third_party" not in result


def test_cache_et_changement_contenu(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    calls = []

    def fake_post(body, _runtime):
        calls.append(1)
        actor = "LockBit" if "LockBit" in json.dumps(body) else "Qilin"
        evidence = f"attaque a été attribuée à {actor}"
        return _payload(_output_for(
            body,
            summary={"value": evidence, "confidence": .9, "evidence": evidence},
            threat_actor={"value": actor, "confidence": .9, "evidence": evidence},
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    first = RawEntry(title="Exemple", content="L'attaque a été attribuée à LockBit.")
    second = RawEntry(title="Exemple", content="L'attaque a été attribuée à Qilin.")
    sfa.enrich(_item(), first)
    sfa.enrich(_item(), first)
    sfa.enrich(_item(), second)
    assert len(calls) == 2
    assert sfa.runtime_stats()["cache_hits"] == 1
    sfa._flush_runtime()
    assert (tmp_path / "cache.json").exists()
    assert (tmp_path / "stats.json").exists()


def test_budget_appels_est_respecte(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    monkeypatch.setenv("SOURCE_FACTS_AI_MAX_CALLS_PER_RUN", "1")
    sfa.reset_runtime_for_tests()
    calls = []

    def fake_post(body, _runtime):
        calls.append(1)
        return _payload(_output_for(body))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    sfa.enrich(_item(), RawEntry(title="A", content="L'attaque a été attribuée à LockBit."))
    item2 = _item()
    item2.Item_ID = "ITM-ai-2"
    sfa.enrich(item2, RawEntry(title="B", content="L'attaque a été attribuée à Qilin."))
    assert len(calls) == 1
    assert sfa.runtime_stats()["calls_budget_blocked"] == 1


def test_autres_sources_jamais_envoyees_au_llm(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    called = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: called.append(1))
    item = _item("BONJOURLAFUITE")
    assert sfa.enrich(item, RawEntry(title="X", content="Données")) is None
    assert not called
