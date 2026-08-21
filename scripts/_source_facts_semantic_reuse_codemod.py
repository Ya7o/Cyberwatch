from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "cyberwatch" / "source_facts_ai.py"


def replace_once(old: str, new: str) -> None:
    text = TARGET.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"pattern not found: {old[:100]!r}")
    TARGET.write_text(text.replace(old, new, 1), encoding="utf-8")


old_seed = '''def _deterministic_seed(entry: RawEntry) -> dict:\n    context = _full_context(entry)\n    seed: dict = {}\n    data_types = _deterministic_data_types(context)\n    if data_types:\n        seed["data_types"] = data_types\n    initial_access = _deterministic_initial_access(context)\n    if initial_access:\n        seed["initial_access"] = initial_access\n    impact = _deterministic_impact(context)\n    if impact:\n        seed["impact"] = impact\n    return seed\n'''

new_seed = '''def _rich_semantic_seed(entry: RawEntry) -> dict:\n    """Réutilise les claims riches déjà validés au lieu de relire le même article.\n\n    Seuls ``confirmed``/``reported`` sont promus dans SourceFacts. Les claims\n    ``claimed``/``hypothesis``/``negated`` restent dans rich_facts afin de ne pas\n    transformer une revendication ou hypothèse en fait observé. Chaque preuve est\n    re-groundée dans le texte source avant réutilisation.\n    """\n    metadata = entry.source_metadata if isinstance(entry.source_metadata, dict) else {}\n    rich = metadata.get("rich_facts")\n    if not isinstance(rich, dict):\n        return {}\n    claims = rich.get("claims")\n    if not isinstance(claims, list):\n        return {}\n\n    context = _full_context(entry)\n    result: dict = {}\n    attack_flow: list[dict] = []\n    data_types: list[dict] = []\n    seen_actions: set[str] = set()\n    seen_types: set[str] = set()\n\n    for claim in claims:\n        if not isinstance(claim, dict):\n            continue\n        status = str(claim.get("status") or "unknown").strip().lower()\n        if status not in {"confirmed", "reported"}:\n            continue\n        evidence = " ".join(str(claim.get("evidence") or "").split()).strip()\n        if not evidence or len(evidence) > MAX_EVIDENCE_CHARS or not _grounded(evidence, context):\n            continue\n        claim_type = str(claim.get("type") or "").strip().lower()\n        value = " ".join(str(claim.get("value") or "").split()).strip()\n        if not value:\n            continue\n\n        if claim_type == "initial_access" and value in INITIAL_ACCESS_VALUES:\n            result.setdefault("initial_access", {"value": value, "confidence": 1.0, "evidence": evidence})\n        elif claim_type == "impact":\n            window = _evidence_window(evidence, context)\n            if not _HYPOTHETICAL_RE.search(window) and not _RESPONSE_ACTION_RE.search(window):\n                result.setdefault("impact", {"value": value[:MAX_SUMMARY_CHARS], "confidence": 1.0, "evidence": evidence})\n        elif claim_type == "actor" and searchable(value) in searchable(evidence):\n            result.setdefault("threat_actor", {"value": value, "confidence": 1.0, "evidence": evidence})\n        elif claim_type == "third_party" and searchable(value) in searchable(evidence):\n            result.setdefault("third_party", {"value": value, "confidence": 1.0, "evidence": evidence})\n        elif claim_type == "data_type":\n            key = searchable(value)\n            if key and key not in seen_types:\n                seen_types.add(key)\n                data_types.append({"value": value, "confidence": 1.0, "evidence": evidence})\n        elif claim_type == "attack_action":\n            combined = f"{value} {evidence}"\n            key = searchable(value)\n            if (\n                key\n                and key not in seen_actions\n                and not _HYPOTHETICAL_RE.search(combined)\n                and not _RESPONSE_ACTION_RE.search(combined)\n                and (_ATTACK_ACTION_RE.search(combined) or "exfiltr" in searchable(combined))\n            ):\n                seen_actions.add(key)\n                attack_flow.append({"action": value, "confidence": 1.0, "evidence": evidence})\n\n    if data_types:\n        result["data_types"] = data_types[:20]\n    if attack_flow:\n        result["attack_flow"] = attack_flow[:MAX_ATTACK_FLOW_STEPS]\n    return result\n\n\ndef _deterministic_seed(entry: RawEntry) -> dict:\n    context = _full_context(entry)\n    seed: dict = {}\n    data_types = _deterministic_data_types(context)\n    if data_types:\n        seed["data_types"] = data_types\n    initial_access = _deterministic_initial_access(context)\n    if initial_access:\n        seed["initial_access"] = initial_access\n    impact = _deterministic_impact(context)\n    if impact:\n        seed["impact"] = impact\n\n    rich_seed = _rich_semantic_seed(entry)\n    for field, value in rich_seed.items():\n        if field == "data_types" and seed.get("data_types"):\n            existing = {searchable(row.get("value", "")) for row in seed["data_types"] if isinstance(row, dict)}\n            seed["data_types"].extend(\n                row for row in value\n                if isinstance(row, dict) and searchable(row.get("value", "")) not in existing\n            )\n        elif field not in seed:\n            seed[field] = value\n    return seed\n'''
replace_once(old_seed, new_seed)

old_legacy = '''    if not actor and _ACTOR_TRIGGER.search(text):\n        requested.add("threat_actor")\n'''
new_legacy = '''    if not actor and not seed.get("threat_actor") and _ACTOR_TRIGGER.search(text):\n        requested.add("threat_actor")\n'''
replace_once(old_legacy, new_legacy)
replace_once(
    '''    if not third_party and _THIRD_PARTY_TRIGGER.search(text):\n        requested.add("third_party")\n''',
    '''    if not third_party and not seed.get("third_party") and _THIRD_PARTY_TRIGGER.search(text):\n        requested.add("third_party")\n''',
)

old_fields = '''def _fields_needed(item: Item, entry: RawEntry, seed: dict | None = None) -> set[str]:\n    requested = _legacy_fields_needed(item, entry, seed)\n    if not _has_semantic_context(entry):\n        return requested\n    requested.update({"summary", "initial_access", "attack_flow"})\n    if not (seed or {}).get("impact"):\n        requested.add("impact")\n    return requested\n'''
new_fields = '''def _fields_needed(item: Item, entry: RawEntry, seed: dict | None = None) -> set[str]:\n    seed = seed or {}\n    requested = _legacy_fields_needed(item, entry, seed)\n    if not _has_semantic_context(entry):\n        return requested\n    requested.add("summary")\n    for field in ("initial_access", "attack_flow", "impact"):\n        if not seed.get(field):\n            requested.add(field)\n    return requested\n'''
replace_once(old_fields, new_fields)

# Self-remove the one-shot machinery.
(ROOT / ".github" / "workflows" / "source-facts-semantic-reuse-codemod.yml").unlink(missing_ok=True)
Path(__file__).unlink(missing_ok=True)
