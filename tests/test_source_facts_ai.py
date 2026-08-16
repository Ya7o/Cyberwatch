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


def test_schema_dynamique_ne_demande_que_faits_utiles(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    bodies = []

    def fake_post(body, _runtime):
        bodies.append(body)
        return _payload(_output_for(
            body,
            summary={
                "value": "Des données de contact ont été exposées.",
                "confidence": .9,
                "evidence": "adresses e-mail et numéros de téléphone ont été exposés",
            },
            data_types=[
                {
                    "value": "adresses e-mail",
                    "confidence": .92,
                    "evidence": "adresses e-mail et numéros de téléphone ont été exposés",
                }
            ],
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    entry = RawEntry(
        title="Exemple SA",
        content="Des adresses e-mail et numéros de téléphone ont été exposés.",
    )
    result = sfa.enrich(_item(), entry)
    assert len(bodies) == 1
    props = set(bodies[0]["text"]["format"]["schema"]["properties"])
    assert props == {"summary", "data_types"}
    assert result["data_types"][0]["value"] == "adresses e-mail"


def test_acteur_non_deterministe_est_demande_et_grounde(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    def fake_post(body, _runtime):
        assert set(body["text"]["format"]["schema"]["properties"]) == {
            "summary", "threat_actor"
        }
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
    entry = RawEntry(title="Exemple", content="L'attaque a été attribuée à LockBit.")
    result = sfa.enrich(_item(), entry)
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
    )
    assert "threat_actor" not in result


def test_acteur_et_tiers_doivent_etre_nommes_dans_evidence(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    def fake_post(body, _runtime):
        return _payload(_output_for(
            body,
            threat_actor={"value": "LockBit", "confidence": .99, "evidence": "incident attribué"},
            third_party={"value": "Example Cloud", "confidence": .99, "evidence": "via un prestataire externe"},
        ))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(
        _item(),
        RawEntry(
            title="Exemple",
            content="incident attribué à LockBit via un prestataire externe Example Cloud",
        ),
    )
    assert "threat_actor" not in result
    assert "third_party" not in result


def test_cache_et_changement_contenu(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    calls = []

    def fake_post(body, _runtime):
        calls.append(1)
        return _payload(_output_for(body))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    first = RawEntry(title="Exemple", content="Des adresses e-mail ont été exposées.")
    second = RawEntry(title="Exemple", content="Des numéros de téléphone ont été exposés.")
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
    monkeypatch.setattr(
        sfa, "_post_openai", lambda body, _runtime: calls.append(1) or _payload(_output_for(body))
    )
    sfa.enrich(_item(), RawEntry(title="A", content="Des adresses e-mail ont été exposées."))
    item2 = _item()
    item2.Item_ID = "ITM-ai-2"
    sfa.enrich(item2, RawEntry(title="B", content="Des téléphones ont été exposés."))
    assert len(calls) == 1


def test_autres_sources_jamais_envoyees_au_llm(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    called = []
    monkeypatch.setattr(sfa, "_post_openai", lambda *_: called.append(1))
    item = _item("BONJOURLAFUITE")
    assert sfa.enrich(item, RawEntry(title="X", content="Données")) is None
    assert not called
