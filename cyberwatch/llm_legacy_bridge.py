"""Pont temporaire entre les runtimes LLM historiques et le contrat central.

Le but est de rendre les anciens modules sûrs pendant leur migration sans leur
laisser choisir un modèle ou une forme de requête incompatibles avec la
politique centrale. Ce module ne déclenche aucun appel réseau.
"""
from __future__ import annotations

from typing import Any

from . import llm_runtime

_INSTALLED = False


def normalize_legacy_request(task: str, body: dict[str, Any]) -> dict[str, Any]:
    """Retourne une copie alignée sur le routage central.

    Les modèles GPT-4o ne prennent pas le paramètre ``reasoning`` utilisé par
    les modèles de raisonnement. Les appels historiques SourceFacts le
    transmettaient encore, ce qui pouvait transformer une migration de modèle
    en série d'erreurs HTTP 400.
    """
    normalized = dict(body)
    chosen = llm_runtime.model_for_task(task, str(body.get("model") or ""))
    normalized["model"] = chosen
    if chosen.startswith("gpt-4o"):
        normalized.pop("reasoning", None)
    return normalized


def install() -> None:
    """Installe le pont SourceFacts une seule fois."""
    global _INSTALLED
    if _INSTALLED:
        return

    from . import source_facts_ai

    original = source_facts_ai._post_openai

    def _post_openai(body, runtime):
        normalized = normalize_legacy_request("source_facts", body)
        # La clé de cache et la métrique locale doivent refléter le modèle
        # réellement envoyé, pas un ancien DEFAULT_MODEL métier.
        runtime.model = normalized["model"]
        return original(normalized, runtime)

    source_facts_ai._post_openai = _post_openai
    _INSTALLED = True
