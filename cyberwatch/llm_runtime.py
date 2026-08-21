"""Infrastructure commune pour les appels LLM de Cyberwatch.

Le runtime centralise transport, routage par tâche, budgets, retries,
Structured Outputs et télémétrie. Les modules métier décident quand appeler le
LLM et revalident ses sorties ; ils ne doivent pas être la source de vérité du
modèle effectivement utilisé.
"""
from __future__ import annotations

import atexit
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import threading
import time
from time import monotonic as _monotonic
from typing import Any

import requests

DEFAULT_MODEL = "gpt-5-nano"
RICH_MODEL = "gpt-4o-mini"
OPENAI_URL = "https://api.openai.com/v1/responses"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_RETRIES = 2
DEFAULT_PRICING = {
    "gpt-5-nano": {"input": 0.05, "output": 0.40},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-5-mini": {"input": 0.25, "output": 2.00},
    "gpt-4o": {"input": 2.50, "output": 10.00},
}

RICH_TASK_MARKERS = ("semantic", "source_facts", "source-facts", "dedup")
DEFAULT_TASK_BUDGETS = {
    "qualification": {"max_calls": 2000, "max_cost_usd": 0.25},
    "source_facts": {"max_calls": 250, "max_cost_usd": 0.75},
    "cyberattaque_semantic": {"max_calls": 250, "max_cost_usd": 0.75},
    "editorial_semantic": {"max_calls": 250, "max_cost_usd": 0.75},
    "dedup": {"max_calls": 200, "max_cost_usd": 0.50},
}


def _task_env_key(task: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in task.upper())


def _is_rich_task(task: str) -> bool:
    low = task.lower()
    return any(marker in low for marker in RICH_TASK_MARKERS)


def model_for_task(task: str, explicit: str | None = None) -> str:
    """Résout le modèle effectif selon une politique unique.

    Ordre : override tâche, override global, modèle explicite réellement
    spécifique, puis politique par tâche. Le cas ``explicit == DEFAULT_MODEL``
    est traité comme un ancien default métier afin qu'il ne court-circuite plus
    le routage riche. Pour forcer nano sur une tâche riche, utiliser
    ``<TASK>_MODEL=gpt-5-nano``.
    """
    override = os.getenv(f"{_task_env_key(task)}_MODEL", "").strip()
    if override:
        return override
    global_override = os.getenv("OPENAI_MODEL", "").strip()
    if global_override:
        return global_override
    if explicit and explicit.strip() and explicit.strip() != DEFAULT_MODEL:
        return explicit.strip()
    return RICH_MODEL if _is_rich_task(task) else DEFAULT_MODEL


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


class LlmError(Exception):
    pass


class LlmBudgetExceeded(LlmError):
    pass


@dataclass(frozen=True)
class LlmUsage:
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


@dataclass(frozen=True)
class LlmCallResult:
    data: dict[str, Any]
    usage: LlmUsage
    duration_seconds: float
    retries: int
    model: str = ""


@dataclass(frozen=True)
class LlmTransportResult:
    payload: dict[str, Any]
    usage: LlmUsage
    duration_seconds: float
    retries: int
    model: str = ""


@dataclass
class LlmRuntimeStats:
    calls_attempted: int = 0
    calls_succeeded: int = 0
    calls_failed: int = 0
    calls_budget_blocked: int = 0
    retries: int = 0
    http_429: int = 0
    http_5xx: int = 0
    timeouts: int = 0
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    duration_seconds: float = 0.0
    by_task: dict[str, dict[str, Any]] = field(default_factory=dict)


class LlmRuntime:
    def __init__(self) -> None:
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self.max_calls = _env_int("LLM_MAX_CALLS_PER_RUN", 3000)
        self.max_cost_usd = _env_float("LLM_MAX_COST_USD_PER_RUN", 2.0)
        self.timeout_seconds = _env_int("LLM_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        self.max_retries = _env_int("LLM_MAX_RETRIES", DEFAULT_MAX_RETRIES)
        self.stats = LlmRuntimeStats()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _task_budget(self, task: str) -> tuple[int, float]:
        defaults = DEFAULT_TASK_BUDGETS.get(task, {})
        key = _task_env_key(task)
        max_calls = _env_int(
            f"LLM_{key}_MAX_CALLS_PER_RUN",
            int(defaults.get("max_calls", self.max_calls)),
        )
        max_cost = _env_float(
            f"LLM_{key}_MAX_COST_USD_PER_RUN",
            float(defaults.get("max_cost_usd", self.max_cost_usd)),
        )
        return max_calls, max_cost

    def _task_bucket(self, task: str) -> dict[str, Any]:
        max_calls, max_cost = self._task_budget(task)
        return self.stats.by_task.setdefault(
            task,
            {
                "calls_attempted": 0,
                "calls_succeeded": 0,
                "calls_failed": 0,
                "calls_budget_blocked": 0,
                "retries": 0,
                "input_tokens": 0,
                "cached_input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "total_tokens": 0,
                "estimated_cost_usd": 0.0,
                "duration_seconds": 0.0,
                "max_calls": max_calls,
                "max_cost_usd": max_cost,
                "last_model": "",
            },
        )

    def _reserve_call(self, task: str) -> None:
        with self._lock:
            bucket = self._task_bucket(task)
            global_exhausted = (
                self.stats.calls_attempted >= self.max_calls
                or self.stats.estimated_cost_usd >= self.max_cost_usd
            )
            task_exhausted = (
                int(bucket["calls_attempted"]) >= int(bucket["max_calls"])
                or float(bucket["estimated_cost_usd"]) >= float(bucket["max_cost_usd"])
            )
            if global_exhausted or task_exhausted:
                self.stats.calls_budget_blocked += 1
                bucket["calls_budget_blocked"] += 1
                scope = "global" if global_exhausted else task
                raise LlmBudgetExceeded(f"budget LLM {scope} épuisé")
            self.stats.calls_attempted += 1
            bucket["calls_attempted"] += 1

    def _record_success(
        self, task: str, model: str, usage: LlmUsage, duration: float, retries: int
    ) -> None:
        with self._lock:
            s = self.stats
            s.calls_succeeded += 1
            s.retries += retries
            s.input_tokens += usage.input_tokens
            s.cached_input_tokens += usage.cached_input_tokens
            s.output_tokens += usage.output_tokens
            s.reasoning_tokens += usage.reasoning_tokens
            s.total_tokens += usage.total_tokens
            s.estimated_cost_usd += usage.estimated_cost_usd
            s.duration_seconds += duration
            b = self._task_bucket(task)
            b["calls_succeeded"] += 1
            b["retries"] += retries
            b["input_tokens"] += usage.input_tokens
            b["cached_input_tokens"] += usage.cached_input_tokens
            b["output_tokens"] += usage.output_tokens
            b["reasoning_tokens"] += usage.reasoning_tokens
            b["total_tokens"] += usage.total_tokens
            b["estimated_cost_usd"] += usage.estimated_cost_usd
            b["duration_seconds"] += duration
            b["last_model"] = model

    def _record_failure(self, task: str, duration: float, retries: int) -> None:
        with self._lock:
            self.stats.calls_failed += 1
            self.stats.retries += retries
            self.stats.duration_seconds += duration
            b = self._task_bucket(task)
            b["calls_failed"] += 1
            b["retries"] += retries
            b["duration_seconds"] += duration

    def post_response(self, *, task: str, body: dict, api_key: str | None = None):
        key = (api_key or self.api_key or "").strip()
        if not key:
            raise LlmError("OPENAI_API_KEY absente")

        request_body = dict(body)
        request_body["model"] = model_for_task(task, str(body.get("model") or ""))
        model = request_body["model"]
        self._reserve_call(task)
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        started = _monotonic()
        retries = 0
        try:
            while True:
                try:
                    response = requests.post(
                        OPENAI_URL,
                        json=request_body,
                        headers=headers,
                        timeout=self.timeout_seconds,
                    )
                except requests.Timeout as exc:
                    with self._lock:
                        self.stats.timeouts += 1
                    if retries >= self.max_retries:
                        raise LlmError("timeout OpenAI après retries") from exc
                    retries += 1
                    time.sleep(2**retries)
                    continue
                except requests.RequestException as exc:
                    if retries >= self.max_retries:
                        raise LlmError(f"réseau OpenAI: {type(exc).__name__}") from exc
                    retries += 1
                    time.sleep(2**retries)
                    continue

                if response.status_code == 200:
                    try:
                        payload = response.json()
                    except ValueError as exc:
                        raise LlmError("réponse OpenAI JSON invalide") from exc
                    usage = extract_usage(payload, model)
                    duration = _monotonic() - started
                    self._record_success(task, model, usage, duration, retries)
                    return LlmTransportResult(payload, usage, duration, retries, model)

                retryable = response.status_code == 429 or 500 <= response.status_code < 600
                if response.status_code == 429:
                    with self._lock:
                        self.stats.http_429 += 1
                elif 500 <= response.status_code < 600:
                    with self._lock:
                        self.stats.http_5xx += 1
                if retryable and retries < self.max_retries:
                    retries += 1
                    time.sleep(2**retries)
                    continue
                raise LlmError(f"HTTP {response.status_code}: {response.text[:200]}")
        except Exception:
            self._record_failure(task, _monotonic() - started, retries)
            raise

    def call_json(
        self,
        *,
        task: str,
        model: str | None = None,
        system_prompt: str,
        user_content: str,
        schema_name: str,
        schema: dict,
        max_output_tokens: int,
        reasoning_effort: str = "minimal",
    ):
        chosen = model_for_task(task, model)
        body = {
            "model": chosen,
            "input": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": schema_name,
                    "schema": schema,
                    "strict": True,
                }
            },
            "max_output_tokens": max_output_tokens,
        }
        if reasoning_effort and not chosen.startswith("gpt-4o"):
            body["reasoning"] = {"effort": reasoning_effort}
        t = self.post_response(task=task, body=body)
        return LlmCallResult(
            extract_output_json(t.payload), t.usage, t.duration_seconds, t.retries, t.model
        )


def pricing_for(model: str) -> dict:
    return DEFAULT_PRICING.get(model, DEFAULT_PRICING[DEFAULT_MODEL])


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    rates = pricing_for(model)
    return (
        input_tokens / 1_000_000 * rates["input"]
        + output_tokens / 1_000_000 * rates["output"]
    )


def extract_usage(payload: dict, model: str = DEFAULT_MODEL) -> LlmUsage:
    u = payload.get("usage") or {}
    i = int(u.get("input_tokens", 0) or 0)
    c = int((u.get("input_tokens_details") or {}).get("cached_tokens", 0) or 0)
    o = int(u.get("output_tokens", 0) or 0)
    r = int((u.get("output_tokens_details") or {}).get("reasoning_tokens", 0) or 0)
    total = int(u.get("total_tokens") or i + o)
    return LlmUsage(i, c, o, r, total, estimate_cost(model, i, o))


def extract_output_json(payload: dict) -> dict:
    text = payload.get("output_text")
    if not isinstance(text, str) or not text.strip():
        text = ""
        for item in payload.get("output") or []:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            for part in item.get("content") or []:
                if (
                    isinstance(part, dict)
                    and part.get("type") in {"output_text", "text"}
                    and isinstance(part.get("text"), str)
                    and part["text"].strip()
                ):
                    text = part["text"]
                    break
            if text:
                break
    if not text:
        raise LlmError(f"réponse sans texte structuré (status={payload.get('status')})")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LlmError(f"JSON structuré invalide: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LlmError("réponse structurée non objet")
    return parsed


def _stats_path() -> Path:
    raw = os.getenv("LLM_USAGE_PATH", "").strip()
    return Path(raw) if raw else Path(__file__).resolve().parents[1] / "data" / "llm_usage.json"


def _write_stats() -> None:
    runtime_ = _RUNTIME
    if runtime_.stats.calls_attempted == 0 and runtime_.stats.calls_budget_blocked == 0:
        return
    path = _stats_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(runtime_.stats)
        payload["routing"] = {
            "default_model": DEFAULT_MODEL,
            "rich_model": RICH_MODEL,
            "rich_task_markers": list(RICH_TASK_MARKERS),
        }
        payload["max_calls"] = runtime_.max_calls
        payload["max_cost_usd"] = runtime_.max_cost_usd
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        tmp.replace(path)
    except OSError:
        pass


_RUNTIME = LlmRuntime()
atexit.register(_write_stats)


def runtime() -> LlmRuntime:
    return _RUNTIME


def reset_runtime_for_tests() -> None:
    global _RUNTIME
    _RUNTIME = LlmRuntime()
