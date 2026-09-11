from __future__ import annotations

import json

import pytest
import requests

from cyberwatch import llm_runtime
from cyberwatch.collectors import semantic_claims


class _Response:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def _payload(data, *, input_tokens=100, output_tokens=20):
    return {
        "status": "completed",
        "output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": json.dumps(data)}],
        }],
        "usage": {
            "input_tokens": input_tokens,
            "input_tokens_details": {"cached_tokens": 10},
            "output_tokens": output_tokens,
            "output_tokens_details": {"reasoning_tokens": 2},
            "total_tokens": input_tokens + output_tokens,
        },
    }


def _simple_schema():
    return {
        "type": "object",
        "properties": {"value": {"type": "string"}},
        "required": ["value"],
        "additionalProperties": False,
    }


def test_model_routing_defaults_and_legacy_default(monkeypatch):
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("SOURCE_FACTS_MODEL", raising=False)
    monkeypatch.delenv("CYBERATTAQUE_SEMANTIC_MODEL", raising=False)
    monkeypatch.delenv("EDITORIAL_SEMANTIC_MODEL", raising=False)
    monkeypatch.delenv("DEDUP_MODEL", raising=False)
    assert llm_runtime.model_for_task("identity") == "gpt-5-nano"
    assert llm_runtime.model_for_task("source_facts") == "gpt-5-mini"
    assert llm_runtime.model_for_task("cyberattaque_semantic") == "gpt-5-mini"
    assert llm_runtime.model_for_task("editorial_semantic") == "gpt-5-mini"
    assert llm_runtime.model_for_task("dedup") == "gpt-5-mini"
    # Un ancien DEFAULT_MODEL métier ne doit plus neutraliser le routage riche.
    assert llm_runtime.model_for_task("source_facts", "gpt-5-nano") == "gpt-5-mini"


def test_model_routing_task_override_wins(monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    monkeypatch.setenv("SOURCE_FACTS_MODEL", "gpt-5-nano")
    assert llm_runtime.model_for_task("source_facts") == "gpt-5-nano"
    assert llm_runtime.model_for_task("identity") == "gpt-4o"


def test_runtime_does_not_retry_by_default(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.delenv("LLM_MAX_RETRIES", raising=False)
    runtime = llm_runtime.LlmRuntime()
    assert runtime.max_retries == 0


@pytest.mark.parametrize("task, expected_model, expected_cost", [
    ("unit", "gpt-5-nano", 0.00001255),
    ("source_facts", "gpt-5-mini", 0.00006275),
])
def test_runtime_uses_strict_structured_outputs(monkeypatch, task, expected_model, expected_cost):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv(f"{task.upper()}_MODEL", raising=False)
    runtime = llm_runtime.LlmRuntime()
    seen = {}

    def fake_post(url, *, json, headers, timeout):
        seen.update(json)
        return _Response(payload=_payload({"value": "ok"}))

    monkeypatch.setattr(llm_runtime.requests, "post", fake_post)
    result = runtime.call_json(
        task=task,
        model="gpt-5-nano",
        system_prompt="system",
        user_content="user",
        schema_name="unit_schema",
        schema=_simple_schema(),
        max_output_tokens=50,
    )

    assert result.data == {"value": "ok"}
    assert seen["text"]["format"]["type"] == "json_schema"
    assert seen["text"]["format"]["strict"] is True
    assert seen["reasoning"] == {"effort": "minimal"}
    assert result.usage.input_tokens == 100
    assert seen["model"] == expected_model
    assert result.model == expected_model
    assert result.usage.estimated_cost_usd == pytest.approx(expected_cost)
    assert runtime.stats.calls_succeeded == 1
    assert runtime.stats.by_task[task]["calls_succeeded"] == 1


def test_post_response_enforces_rich_model_for_legacy_body(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("SOURCE_FACTS_MODEL", raising=False)
    runtime = llm_runtime.LlmRuntime()
    seen = {}

    def fake_post(url, *, json, headers, timeout):
        seen.update(json)
        return _Response(payload=_payload({"value": "ok"}))

    monkeypatch.setattr(llm_runtime.requests, "post", fake_post)
    result = runtime.post_response(
        task="source_facts",
        body={"model": "gpt-5-nano", "input": [], "reasoning": {"effort": "minimal"}},
    )
    assert seen["model"] == "gpt-5-mini"
    assert seen["reasoning"] == {"effort": "minimal"}
    assert result.model == "gpt-5-mini"
    assert runtime.stats.by_task["source_facts"]["last_model"] == "gpt-5-mini"


def test_runtime_retries_429(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("LLM_MAX_RETRIES", "2")
    runtime = llm_runtime.LlmRuntime()
    responses = iter([
        _Response(status_code=429, text="rate limited"),
        _Response(payload=_payload({"value": "ok"})),
    ])
    monkeypatch.setattr(llm_runtime.time, "sleep", lambda _: None)
    monkeypatch.setattr(llm_runtime.requests, "post", lambda *args, **kwargs: next(responses))

    result = runtime.call_json(
        task="retry",
        model="gpt-5-nano",
        system_prompt="system",
        user_content="user",
        schema_name="unit_schema",
        schema=_simple_schema(),
        max_output_tokens=50,
    )

    assert result.data["value"] == "ok"
    assert result.retries == 1
    assert runtime.stats.http_429 == 1
    assert runtime.stats.retries == 1


def test_runtime_retries_timeout_then_fails(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("LLM_MAX_RETRIES", "1")
    runtime = llm_runtime.LlmRuntime()
    monkeypatch.setattr(llm_runtime.time, "sleep", lambda _: None)

    def timeout(*args, **kwargs):
        raise requests.Timeout("boom")

    monkeypatch.setattr(llm_runtime.requests, "post", timeout)
    with pytest.raises(llm_runtime.LlmError):
        runtime.call_json(
            task="timeout",
            model="gpt-5-nano",
            system_prompt="system",
            user_content="user",
            schema_name="unit_schema",
            schema=_simple_schema(),
            max_output_tokens=50,
        )
    assert runtime.stats.timeouts == 2
    assert runtime.stats.calls_failed == 1


def test_global_budget_blocks_before_transport(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("LLM_MAX_CALLS_PER_RUN", "0")
    runtime = llm_runtime.LlmRuntime()
    called = False

    def fake_post(*args, **kwargs):
        nonlocal called
        called = True
        return _Response(payload=_payload({"value": "ok"}))

    monkeypatch.setattr(llm_runtime.requests, "post", fake_post)
    with pytest.raises(llm_runtime.LlmBudgetExceeded):
        runtime.call_json(
            task="budget",
            model="gpt-5-nano",
            system_prompt="system",
            user_content="user",
            schema_name="unit_schema",
            schema=_simple_schema(),
            max_output_tokens=50,
        )
    assert called is False
    assert runtime.stats.calls_budget_blocked == 1


def test_task_budget_blocks_before_global_budget(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("LLM_MAX_CALLS_PER_RUN", "10")
    monkeypatch.setenv("LLM_SOURCE_FACTS_MAX_CALLS_PER_RUN", "0")
    runtime = llm_runtime.LlmRuntime()
    called = False

    def fake_post(*args, **kwargs):
        nonlocal called
        called = True
        return _Response(payload=_payload({"value": "ok"}))

    monkeypatch.setattr(llm_runtime.requests, "post", fake_post)
    with pytest.raises(llm_runtime.LlmBudgetExceeded):
        runtime.post_response(task="source_facts", body={"model": "gpt-5-nano", "input": []})
    assert called is False
    assert runtime.stats.calls_attempted == 0
    assert runtime.stats.by_task["source_facts"]["calls_budget_blocked"] == 1


def test_semantic_claim_validator_requires_exact_evidence_and_number():
    article = "La société confirme que 42 comptes ont été compromis."
    assert semantic_claims._clean_claim(
        {
            "type": "affected_count",
            "status": "confirmed",
            "value": 42,
            "unit": "accounts",
            "evidence": article,
        },
        article,
    )
    assert semantic_claims._clean_claim(
        {
            "type": "affected_count",
            "status": "confirmed",
            "value": 9000,
            "unit": "accounts",
            "evidence": article,
        },
        article,
    ) is None
    assert semantic_claims._clean_claim(
        {
            "type": "statement",
            "status": "confirmed",
            "value": "inventé",
            "evidence": "phrase absente",
        },
        article,
    ) is None


def test_candidate_requires_gap_for_length_only():
    text = "Article factuel. " * 400
    complete = {
        "affected_counts": [{"value": 1}],
        "data_volumes": [{"value": 1}],
        "timeline": [{"date": "2026-01-01"}],
        "relations": [{"relation": "affects"}],
        "data_types": [{"value": "email"}],
    }
    assert len(text) > 4500
    assert semantic_claims.is_candidate(text, complete) is True


def test_extract_output_json_rejects_missing_text():
    with pytest.raises(llm_runtime.LlmError):
        llm_runtime.extract_output_json({"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}})


def test_cost_uses_cached_input_price_and_dated_model():
    payload = _payload({}, input_tokens=1000, output_tokens=100)
    payload["usage"]["input_tokens_details"]["cached_tokens"] = 800
    usage = llm_runtime.extract_usage(payload, "gpt-5-mini-2025-08-07")
    assert usage.estimated_cost_usd == pytest.approx(0.00027)


def test_unknown_price_is_never_silently_nano(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("UNIT_MODEL", "unknown-model")
    runtime = llm_runtime.LlmRuntime()
    monkeypatch.setattr(llm_runtime.requests, "post", lambda *a, **kw: pytest.fail("transport interdit"))
    with pytest.raises(llm_runtime.LlmError, match="tarif"):
        runtime.post_response(task="unit", body={"input": []})


@pytest.mark.parametrize("status_value", ["incomplete", "failed", "cancelled", "in_progress"])
def test_parseable_json_is_not_a_completed_response(status_value):
    payload = _payload({"value": "plausible"})
    payload["status"] = status_value
    with pytest.raises(llm_runtime.LlmError):
        llm_runtime.extract_output_json(payload)


def test_refusal_cannot_be_hidden_by_parseable_text():
    payload = _payload({"value": "plausible"})
    payload["output"][0]["content"].append({"type": "refusal", "refusal": "Refus"})
    with pytest.raises(llm_runtime.LlmError):
        llm_runtime.extract_output_json(payload)


def test_semantic_cache_and_provenance_follow_resolved_model(monkeypatch, tmp_path):
    from types import SimpleNamespace

    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("AUDIT_CACHE_PATH", str(tmp_path / "cache.json"))
    policy = semantic_claims.SemanticPolicy("editorial_semantic", "audit-v1", "system", "AUDIT", "cache.json")
    monkeypatch.setattr(semantic_claims, "is_candidate", lambda *args: True)
    calls = []

    def fake_call(**kwargs):
        model = llm_runtime.model_for_task(kwargs["task"], kwargs["model"])
        calls.append(model)
        return SimpleNamespace(data={"claims": [], "timeline": [], "relations": []},
            model=model, declared_model=model + "-2025-08-07", usage=llm_runtime.LlmUsage(),
            duration_seconds=0, retries=0)

    monkeypatch.setattr(llm_runtime, "runtime", lambda: SimpleNamespace(call_json=fake_call, enabled=True))
    monkeypatch.setenv("EDITORIAL_SEMANTIC_MODEL", "gpt-5-mini")
    first = semantic_claims.enrich("Article.", {}, source_id="TEST", policy=policy)
    assert first["model"] == "gpt-5-mini"
    assert first["declared_model"] == "gpt-5-mini-2025-08-07"
    assert semantic_claims.enrich("Article.", {}, source_id="TEST", policy=policy)["cache_hit"]
    monkeypatch.setenv("EDITORIAL_SEMANTIC_MODEL", "gpt-5-nano")
    assert not semantic_claims.enrich("Article.", {}, source_id="TEST", policy=policy)["cache_hit"]
    assert calls == ["gpt-5-mini", "gpt-5-nano"]
