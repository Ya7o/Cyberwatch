from __future__ import annotations

from cyberwatch import llm_runtime


class _Response:
    status_code = 200
    text = ""

    def json(self):
        return {
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "{}"}],
            }],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 2,
                "total_tokens": 12,
            },
        }


def test_dedup_schema_is_attributed_to_dedup_budget(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    runtime = llm_runtime.LlmRuntime()
    seen = {}

    def fake_post(url, *, json, headers, timeout):
        seen.update(json)
        return _Response()

    monkeypatch.setattr(llm_runtime.requests, "post", fake_post)
    runtime.post_response(
        task="qualification",
        body={
            "model": "gpt-4o-mini",
            "input": [],
            "text": {"format": {"name": "cyberwatch_dedup_audit"}},
        },
    )

    assert seen["model"] == "gpt-4o-mini"
    assert "dedup" in runtime.stats.by_task
    assert runtime.stats.by_task["dedup"]["calls_succeeded"] == 1
    assert "qualification" not in runtime.stats.by_task
