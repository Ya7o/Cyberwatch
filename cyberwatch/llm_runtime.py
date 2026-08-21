"""Infrastructure commune pour les appels LLM de Cyberwatch.

Le runtime centralise le transport OpenAI Responses, les retries, Structured
Outputs, le calcul de coût, un budget global de processus et une télémétrie
agrégée. Les modules métier gardent la responsabilité de décider *quand* un
appel est utile et de valider les faits retournés.

Le runtime est volontairement sans agent ni outil : un modèle reçoit du texte
et retourne une structure JSON. Il ne peut jamais modifier directement les
données canoniques.
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

# Les tâches LLM Cyberwatch sont des extractions/classifications structurées,
# revalidées mécaniquement après réponse. GPT-4o mini est donc le défaut coût /
# latence. Chaque tâche peut toujours le surcharger via sa variable *_MODEL ou
# OPENAI_MODEL sans changer le code.
DEFAULT_MODEL = "gpt-4o-mini"
OPENAI_URL = "https://api.openai.com/v1/responses"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_RETRIES = 2
DEFAULT_PRICING = {
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    # Compatibilité des caches/runs historiques encore étiquetés ainsi.
    "gpt-5-nano": {"input": 0.05, "output": 0.40},
}


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
    """Erreur de transport ou de contrat LLM."""


class LlmBudgetExceeded(LlmError):
    """Budget global du processus épuisé."""


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


@dataclass(frozen=True)
class LlmTransportResult:
    payload: dict[str, Any]
    usage: LlmUsage
    duration_seconds: float
    retries: int


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
    by_task: dict[str, dict[str, float | int]] = field(default_factory=dict)


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

    def _task_bucket(self, task: str) -> dict[str, float | int]:
        return self.stats.by_task.setdefault(
            task,
            {
                "calls_attempted": 0,
                "calls_succeeded": 0,
                "calls_failed": 0,
                "calls_budget_blocked": 0,
                "retries": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "estimated_cost_usd": 0.0,
                "duration_seconds": 0.0,
            },
        )

    def _reserve_call(self, task: str) -> None:
        with self._lock:
            if (
                self.stats.calls_attempted >= self.max_calls
                or self.stats.estimated_cost_usd >= self.max_cost_usd
            ):
                self.stats.calls_budget_blocked += 1
                bucket = self._task_bucket(task)
                bucket["calls_budget_blocked"] = int(bucket["calls_budget_blocked"]) + 1
                raise LlmBudgetExceeded("budget LLM global épuisé")
            self.stats.calls_attempted += 1
            bucket = self._task_bucket(task)
            bucket["calls_attempted"] = int(bucket["calls_attempted"]) + 1

    def _record_success(self, task: str, usage: LlmUsage, duration: float, retries: int) -> None:
        with self._lock:
            self.stats.calls_succeeded += 1
            self.stats.retries += retries
            self.stats.input_tokens += usage.input_tokens
            self.stats.cached_input_tokens += usage.cached_input_tokens
            self.stats.output_tokens += usage.output_tokens
            self.stats.reasoning_tokens += usage.reasoning_tokens
            self.stats.total_tokens += usage.total_tokens
            self.stats.estimated_cost_usd += usage.estimated_cost_usd
            self.stats.duration_seconds += duration
            bucket = self._task_bucket(task)
            bucket["calls_succeeded"] = int(bucket["calls_succeeded"]) + 1
            bucket["retries"] = int(bucket["retries"]) + retries
            bucket["input_tokens"] = int(bucket["input_tokens"]) + usage.input_tokens
            bucket["output_tokens"] = int(bucket["output_tokens"]) + usage.output_tokens
            bucket["total_tokens"] = int(bucket["total_tokens"]) + usage.total_tokens
            bucket["estimated_cost_usd"] = float(bucket["estimated_cost_usd"]) + usage.estimated_cost_usd
            bucket["duration_seconds"] = float(bucket["duration_seconds"]) + duration

    def _record_failure(self, task: str, duration: float, retries: int) -> None:
        with self._lock:
            self.stats.calls_failed += 1
            self.stats.retries += retries
            self.stats.duration_seconds += duration
            bucket = self._task_bucket(task)
            bucket["calls_failed"] = int(bucket["calls_failed"]) + 1
            bucket["retries"] = int(bucket["retries"]) + retries
            bucket["duration_seconds"] = float(bucket["duration_seconds"]) + duration

    def post_response(self, *, task: str, body: dict[str, Any], api_key: str | None = None) -> LlmTransportResult:
        key = (api_key or self.api_key or "").strip()
        if not key:
            raise LlmError("OPENAI_API_KEY absente")
        self._reserve_call(task)
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        started = _monotonic()
        retries = 0
        try:
            while True:
                try:
                    response = requests.post(OPENAI_URL, json=body, headers=headers, timeout=self.timeout_seconds)
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
                    model = str(body.get("model") or DEFAULT_MODEL)
                    usage = extract_usage(payload, model)
                    duration = _monotonic() - started
                    self._record_success(task, usage, duration, retries)
                    return LlmTransportResult(payload=payload, usage=usage, duration_seconds=duration, retries=retries)
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

    def call_json(self, *, task: str, model: str, system_prompt: str, user_content: str, schema_name: str, schema: dict[str, Any], max_output_tokens: int, reasoning_effort: str | None = "minimal") -> LlmCallResult:
        body: dict[str, Any] = {
            "model": model,
            "input": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}],
            "text": {"format": {"type": "json_schema", "name": schema_name, "schema": schema, "strict": True}},
            "max_output_tokens": max_output_tokens,
        }
        # GPT-4o / GPT-4o mini n'acceptent pas le paramètre reasoning. Les
        # modèles de raisonnement peuvent toujours l'utiliser via override.
        if reasoning_effort and not model.startswith("gpt-4o"):
            body["reasoning"] = {"effort": reasoning_effort}
        transport = self.post_response(task=task, body=body)
        data = extract_output_json(transport.payload)
        return LlmCallResult(data=data, usage=transport.usage, duration_seconds=transport.duration_seconds, retries=transport.retries)


def pricing_for(model: str) -> dict[str, float]:
    return DEFAULT_PRICING.get(model, DEFAULT_PRICING[DEFAULT_MODEL])


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    rates = pricing_for(model)
    return (input_tokens / 1_000_000) * rates["input"] + (output_tokens / 1_000_000) * rates["output"]


def extract_usage(payload: dict[str, Any], model: str = DEFAULT_MODEL) -> LlmUsage:
    usage = payload.get("usage") or {}
    input_tokens = int(usage.get("input_tokens", 0) or 0)
    cached = int((usage.get("input_tokens_details") or {}).get("cached_tokens", 0) or 0)
    output_tokens = int(usage.get("output_tokens", 0) or 0)
    reasoning = int((usage.get("output_tokens_details") or {}).get("reasoning_tokens", 0) or 0)
    total = int(usage.get("total_tokens") or input_tokens + output_tokens)
    return LlmUsage(input_tokens=input_tokens, cached_input_tokens=cached, output_tokens=output_tokens, reasoning_tokens=reasoning, total_tokens=total, estimated_cost_usd=estimate_cost(model, input_tokens, output_tokens))


def extract_output_json(payload: dict[str, Any]) -> dict[str, Any]:
    text = payload.get("output_text")
    if not isinstance(text, str) or not text.strip():
        text = ""
        for item in payload.get("output") or []:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            for part in item.get("content") or []:
                if isinstance(part, dict) and part.get("type") in {"output_text", "text"}:
                    candidate = part.get("text")
                    if isinstance(candidate, str) and candidate.strip():
                        text = candidate
                        break
            if text:
                break
    if not text:
        reason = (payload.get("incomplete_details") or {}).get("reason")
        detail = f"status={payload.get('status')}"
        if reason:
            detail += f", incomplete_reason={reason}"
        raise LlmError(f"réponse sans texte structuré ({detail})")
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
    runtime = _RUNTIME
    if runtime.stats.calls_attempted == 0 and runtime.stats.calls_budget_blocked == 0:
        return
    path = _stats_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(runtime.stats)
        payload["model_pricing_default"] = DEFAULT_MODEL
        payload["max_calls"] = runtime.max_calls
        payload["max_cost_usd"] = runtime.max_cost_usd
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
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
