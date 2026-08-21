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


def test_runtime_uses_strict_structured_outputs(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    runtime = llm_runtime.LlmRuntime()
    seen = {}

    def fake_post(url, *, json, headers, timeout):
        seen.update(json)
        return _Response(payload=_payload({"value": "ok"}))

    monkeypatch.setattr(llm_runtime.requests, "post", fake_post)
    result = runtime.call_json(
        task="unit",
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
    assert runtime.stats.calls_succeeded == 1
    assert runtime.stats.by_task["unit"]["calls_succeeded"] == 1


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
    assert semantic_claims.is_candidate(text, complete) is True  # richness itself justifies semantic review


def test_extract_output_json_rejects_missing_text():
    with pytest.raises(llm_runtime.LlmError):
        llm_runtime.extract_output_json({"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}})
