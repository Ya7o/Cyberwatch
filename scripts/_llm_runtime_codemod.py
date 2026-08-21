from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"pattern not found in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_regex(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"regex count={count} in {path}: {pattern[:80]!r}")
    path.write_text(updated, encoding="utf-8")


# ---------------------------------------------------------------------------
# Shared runtime: expose the raw Responses transport so legacy business layers
# can keep their schemas/accounting while sharing retries + global budget.
# ---------------------------------------------------------------------------
runtime = ROOT / "cyberwatch" / "llm_runtime.py"
replace_once(
    runtime,
    "@dataclass(frozen=True)\nclass LlmCallResult:\n    data: dict[str, Any]\n    usage: LlmUsage\n    duration_seconds: float\n    retries: int\n\n\n@dataclass\nclass LlmRuntimeStats:",
    "@dataclass(frozen=True)\nclass LlmCallResult:\n    data: dict[str, Any]\n    usage: LlmUsage\n    duration_seconds: float\n    retries: int\n\n\n@dataclass(frozen=True)\nclass LlmTransportResult:\n    payload: dict[str, Any]\n    usage: LlmUsage\n    duration_seconds: float\n    retries: int\n\n\n@dataclass\nclass LlmRuntimeStats:",
)

new_methods = '''    def post_response(\n        self,\n        *,\n        task: str,\n        body: dict[str, Any],\n        api_key: str | None = None,\n    ) -> LlmTransportResult:\n        key = (api_key or self.api_key or "").strip()\n        if not key:\n            raise LlmError("OPENAI_API_KEY absente")\n        self._reserve_call(task)\n        headers = {\n            "Authorization": f"Bearer {key}",\n            "Content-Type": "application/json",\n        }\n        started = time.monotonic()\n        retries = 0\n        try:\n            while True:\n                try:\n                    response = requests.post(\n                        OPENAI_URL,\n                        json=body,\n                        headers=headers,\n                        timeout=self.timeout_seconds,\n                    )\n                except requests.Timeout as exc:\n                    with self._lock:\n                        self.stats.timeouts += 1\n                    if retries >= self.max_retries:\n                        raise LlmError("timeout OpenAI après retries") from exc\n                    retries += 1\n                    time.sleep(2**retries)\n                    continue\n                except requests.RequestException as exc:\n                    if retries >= self.max_retries:\n                        raise LlmError(f"réseau OpenAI: {type(exc).__name__}") from exc\n                    retries += 1\n                    time.sleep(2**retries)\n                    continue\n\n                if response.status_code == 200:\n                    try:\n                        payload = response.json()\n                    except ValueError as exc:\n                        raise LlmError("réponse OpenAI JSON invalide") from exc\n                    model = str(body.get("model") or DEFAULT_MODEL)\n                    usage = extract_usage(payload, model)\n                    duration = time.monotonic() - started\n                    self._record_success(task, usage, duration, retries)\n                    return LlmTransportResult(\n                        payload=payload,\n                        usage=usage,\n                        duration_seconds=duration,\n                        retries=retries,\n                    )\n\n                retryable = response.status_code == 429 or 500 <= response.status_code < 600\n                if response.status_code == 429:\n                    with self._lock:\n                        self.stats.http_429 += 1\n                elif 500 <= response.status_code < 600:\n                    with self._lock:\n                        self.stats.http_5xx += 1\n                if retryable and retries < self.max_retries:\n                    retries += 1\n                    time.sleep(2**retries)\n                    continue\n                raise LlmError(f"HTTP {response.status_code}: {response.text[:200]}")\n        except Exception:\n            self._record_failure(task, time.monotonic() - started, retries)\n            raise\n\n    def call_json(\n        self,\n        *,\n        task: str,\n        model: str,\n        system_prompt: str,\n        user_content: str,\n        schema_name: str,\n        schema: dict[str, Any],\n        max_output_tokens: int,\n        reasoning_effort: str | None = "minimal",\n    ) -> LlmCallResult:\n        body: dict[str, Any] = {\n            "model": model,\n            "input": [\n                {"role": "system", "content": system_prompt},\n                {"role": "user", "content": user_content},\n            ],\n            "text": {\n                "format": {\n                    "type": "json_schema",\n                    "name": schema_name,\n                    "schema": schema,\n                    "strict": True,\n                }\n            },\n            "max_output_tokens": max_output_tokens,\n        }\n        if reasoning_effort:\n            body["reasoning"] = {"effort": reasoning_effort}\n        transport = self.post_response(task=task, body=body)\n        data = extract_output_json(transport.payload)\n        return LlmCallResult(\n            data=data,\n            usage=transport.usage,\n            duration_seconds=transport.duration_seconds,\n            retries=transport.retries,\n        )\n\n'''
replace_regex(
    runtime,
    r"    def call_json\(.*?\n\ndef pricing_for\(",
    new_methods + "\ndef pricing_for(",
)

# ---------------------------------------------------------------------------
# Main qualification + dedup challenger (dedup reuses ai._post_openai).
# ---------------------------------------------------------------------------
ai = ROOT / "cyberwatch" / "ai.py"
replace_once(
    ai,
    "from . import config, org_enrichment, store",
    "from . import config, llm_runtime, org_enrichment, store",
)
replace_regex(
    ai,
    r"def _estimate_cost\(model: str, input_tokens: int, output_tokens: int\) -> float:\n.*?\n\n",
    "def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:\n    return llm_runtime.estimate_cost(model, input_tokens, output_tokens)\n\n\n",
)
replace_regex(
    ai,
    r"def _post_openai\(body: dict, state: AiRunState\) -> dict:\n.*?\n\ndef _call_openai\(",
    '''def _post_openai(body: dict, state: AiRunState) -> dict:\n    started = time.monotonic()\n    try:\n        try:\n            result = llm_runtime.runtime().post_response(\n                task="qualification",\n                body=body,\n                api_key=state.api_key,\n            )\n            return result.payload\n        except llm_runtime.LlmError as exc:\n            raise AiCallError(str(exc)) from exc\n    finally:\n        state.llm_duration_seconds += time.monotonic() - started\n\n\ndef _call_openai(''',
)

# ---------------------------------------------------------------------------
# Source facts keeps its field cache/quality counters but shares HTTP transport,
# retries and the process-wide budget. Existing local telemetry is synchronized
# from the shared runtime so reports keep their historical columns.
# ---------------------------------------------------------------------------
sfa = ROOT / "cyberwatch" / "source_facts_ai.py"
replace_once(
    sfa,
    "import requests\n\nfrom .collectors.base import RawEntry",
    "import requests\n\nfrom . import llm_runtime\nfrom .collectors.base import RawEntry",
)
replace_regex(
    sfa,
    r"def _post_openai\(body: dict, runtime: _Runtime\) -> dict:\n.*?\n\ndef _usage\(",
    '''def _post_openai(body: dict, runtime: _Runtime) -> dict:\n    shared = llm_runtime.runtime()\n    before_retries = shared.stats.retries\n    before_timeouts = shared.stats.timeouts\n    before_429 = shared.stats.http_429\n    before_5xx = shared.stats.http_5xx\n    try:\n        result = shared.post_response(\n            task="source_facts",\n            body=body,\n            api_key=runtime.api_key,\n        )\n        return result.payload\n    except llm_runtime.LlmError as exc:\n        raise SourceFactsAiError(str(exc)) from exc\n    finally:\n        runtime.retries += max(0, shared.stats.retries - before_retries)\n        runtime.timeouts += max(0, shared.stats.timeouts - before_timeouts)\n        runtime.http_429 += max(0, shared.stats.http_429 - before_429)\n        runtime.http_5xx += max(0, shared.stats.http_5xx - before_5xx)\n\n\ndef _usage(''',
)
replace_regex(
    sfa,
    r"def _usage_cost\(payload: dict, model: str\) -> float:\n.*?\n\n",
    '''def _usage_cost(payload: dict, model: str) -> float:\n    input_tokens, output_tokens = _usage(payload)\n    return llm_runtime.estimate_cost(model, input_tokens, output_tokens)\n\n\n''',
)

# Temporary codemod machinery removes itself from the resulting branch.
(ROOT / ".github" / "workflows" / "llm-runtime-codemod.yml").unlink(missing_ok=True)
Path(__file__).unlink(missing_ok=True)
