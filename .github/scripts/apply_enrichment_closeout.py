from pathlib import Path
import re


def replace_once(text, old, new, label):
    if old not in text:
        raise SystemExit(f"marker missing: {label}")
    return text.replace(old, new, 1)


def replace_func(text, name, new_body):
    pattern = re.compile(rf"^def {re.escape(name)}\(.*?(?=^def |\Z)", re.M | re.S)
    match = pattern.search(text)
    if not match:
        raise SystemExit(f"function missing: {name}")
    return text[:match.start()] + new_body.rstrip() + "\n\n" + text[match.end():]


# source_facts_ai.py
path = Path("cyberwatch/source_facts_ai.py")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '    "attack_flow": "attack-flow-v1",\n    "impact": "impact-v1",',
    '    "attack_flow": "attack-flow-v2",\n    "impact": "impact-v2",',
    "field versions",
)
text = replace_once(
    text,
    'LEGACY_REUSABLE_FIELDS = {"threat_actor", "third_party", "data_types"}\n',
    'LEGACY_REUSABLE_FIELDS = {"threat_actor", "third_party", "data_types"}\n'
    'PREVIOUS_FIELD_VERSIONS = {\n'
    '    "attack_flow": "attack-flow-v1",\n'
    '    "impact": "impact-v1",\n'
    '}\n',
    "previous field versions",
)
start = text.index("_HYPOTHETICAL_RE = re.compile(")
end = text.index("\n\n\ndef _env_int", start)
regex_block = r'''_HYPOTHETICAL_RE = re.compile(
    r"\b(?:pourrait|pourraient|peut[- ]?[êe]tre|possible|possiblement|potentiellement|probable|probablement|"
    r"hypoth[èe]se|sc[ée]nario|suspect[ée]?|suppos[ée]?|envisag[ée]?|pr[ée]sum[ée]e?s?|semblerait|"
    r"serait|aurait|auraient|susceptible(?:s)?|non\s+confirm[ée]|sans\s+confirmation|reste\s+inconnu)\b",
    re.I,
)
_RESPONSE_ACTION_RE = re.compile(
    r"\b(?:isol(?:er|[ée]e?s?)|confinement|rem[ée]diation|restaur(?:er|ation|[ée]e?s?)|"
    r"r[ée]initialis(?:er|ation|[ée]e?s?)|investigation|forensic|enqu[êe]te|notification|CNIL|"
    r"d[ée]branch(?:er|[ée]e?s?)|d[ée]connect(?:er|[ée]e?s?)|correctif|rotation\s+des\s+(?:secrets|identifiants)|"
    r"mesures?\s+de\s+s[ée]curit[ée])\b",
    re.I,
)
_ATTACK_ACTION_RE = re.compile(
    r"\b(?:attaquant|pirate|hacker|intrusion|compromission|compromis|acc[èe]s\s+(?:non\s+autoris[ée]|frauduleux|initial)|"
    r"exploit(?:ation|[ée]e?)|vuln[ée]rabilit[ée]|faille|IDOR|injection\s+SQL|phishing|hame[cç]onnage|"
    r"usurpation|exfiltrat|extract(?:ion|[ée]e?)|vol(?:[ée]e|er)?|fuite|diffus(?:ion|[ée]e)|publi(?:cation|[ée]e)|"
    r"mis(?:e)?\s+en\s+vente|chiffr(?:ement|[ée]e)|ransomware|ran[cç]ongiciel|malware)\b",
    re.I,
)'''
text = text[:start] + regex_block + text[end:]
text = replace_func(text, "_normalize_attack_flow", r'''def _normalize_attack_flow(raw, context: str) -> list[dict]:
    if not isinstance(raw, list):
        return []
    result: list[dict] = []
    seen = set()
    for candidate in raw[:MAX_ATTACK_FLOW_STEPS]:
        if not isinstance(candidate, dict):
            continue
        action = " ".join(str(candidate.get("action") or "").split()).strip()
        evidence = " ".join(str(candidate.get("evidence") or "").split()).strip()
        confidence = _valid_confidence(candidate.get("confidence"))
        if not action or confidence is None or confidence < CONFIDENCE_THRESHOLD:
            continue
        if not evidence or len(evidence) > MAX_EVIDENCE_CHARS or not _grounded(evidence, context):
            continue
        combined = f"{action} {evidence}"
        if _HYPOTHETICAL_RE.search(combined) or _RESPONSE_ACTION_RE.search(combined):
            continue
        if not _ATTACK_ACTION_RE.search(combined):
            continue
        key = searchable(action)
        if not key or key in seen:
            continue
        seen.add(key)
        result.append({"action": action, "confidence": confidence, "evidence": evidence})
    return result
''')
marker = "def _normalize(raw: dict, context: str, fields: set[str]) -> dict:"
idx = text.index(marker)
helper = '''def _normalize_impact(raw, context: str) -> dict | None:
    fact = _normalize_fact(raw, context)
    if not fact:
        return None
    window = _evidence_window(fact["evidence"], context)
    combined = f"{fact['value']} {window}"
    if _HYPOTHETICAL_RE.search(combined) or _RESPONSE_ACTION_RE.search(combined):
        return None
    return fact


'''
text = text[:idx] + helper + text[idx:]
text = replace_once(
    text,
    '    if "impact" in fields:\n        fact = _normalize_fact(raw.get("impact"), context)\n        if fact and not _HYPOTHETICAL_RE.search(_evidence_window(fact["evidence"], context)):\n            result["impact"] = fact\n',
    '    if "impact" in fields:\n        fact = _normalize_impact(raw.get("impact"), context)\n        if fact:\n            result["impact"] = fact\n',
    "impact normalization",
)
insertion = r'''_INITIAL_ACCESS_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("compromised_credentials", re.compile(
        r"(?:\b(?:intrusion|acc[èe]s|connexion|p[ée]n[ée]tr\w*)\b.{0,120}\b(?:compte|identifiants?|credentials?)\b.{0,70}\bcompromis\w*\b|"
        r"\b(?:compte|identifiants?|credentials?)\b.{0,70}\bcompromis\w*\b.{0,120}\b(?:intrusion|acc[èe]s|utilis[ée]\w*|p[ée]n[ée]tr\w*)\b)", re.I)),
    ("phishing", re.compile(
        r"\b(?:phishing|hame[cç]onnage)\b.{0,120}\b(?:a\s+permis|ayant\s+permis|permettant|acc[èe]s|intrusion|compte)\b", re.I)),
    ("vulnerability_exploitation", re.compile(
        r"(?:\bexploit\w*\b.{0,100}\b(?:vuln[ée]rabilit[ée]|faille|IDOR|injection\s+SQL|CVE-\d{4}-\d+)\b|"
        r"\b(?:vuln[ée]rabilit[ée]|faille|IDOR|injection\s+SQL|CVE-\d{4}-\d+)\b.{0,120}\b(?:a\s+permis|ayant\s+permis|permettant)\b.{0,80}\b(?:acc[èe]s|intrusion|compromission)\b)", re.I)),
    ("third_party", re.compile(
        r"\b(?:via|chez)\b.{0,80}\b(?:prestataire|fournisseur|sous[- ]traitant|tiers)\b.{0,80}\bcompromis\w*\b", re.I)),
    ("remote_access", re.compile(
        r"\b(?:RDP|VPN|bureau\s+[àa]\s+distance|acc[èe]s\s+distant)\b.{0,100}\b(?:compromis|exploit[ée]|intrusion|acc[èe]s\s+non\s+autoris[ée])\b", re.I)),
)


def _deterministic_initial_access(context: str) -> dict | None:
    if not context or _INITIAL_ACCESS_UNKNOWN_RE.search(context):
        return None
    for segment in re.split(r"(?<=[.!?;])\s+|\n+", context):
        cleaned = " ".join(segment.split()).strip()
        if not cleaned or _HYPOTHETICAL_RE.search(cleaned):
            continue
        for category, pattern in _INITIAL_ACCESS_PATTERNS:
            if pattern.search(cleaned):
                evidence = cleaned[:MAX_EVIDENCE_CHARS]
                return {"value": category, "confidence": 1.0, "evidence": evidence}
    return None


'''
idx = text.index("def _deterministic_data_types")
text = text[:idx] + insertion + text[idx:]
text = replace_func(text, "_deterministic_impact", r'''def _deterministic_impact(context: str) -> dict | None:
    for segment in re.split(r"(?<=[.!?;])\s+|\n+", context or ""):
        cleaned = " ".join(segment.split()).strip()
        if not cleaned or not _IMPACT_TRIGGER.search(cleaned):
            continue
        if _HYPOTHETICAL_RE.search(cleaned) or _RESPONSE_ACTION_RE.search(cleaned):
            continue
        evidence = cleaned[:MAX_EVIDENCE_CHARS]
        return {"value": evidence, "confidence": 1.0, "evidence": evidence}
    return None
''')
text = replace_func(text, "_deterministic_seed", '''def _deterministic_seed(entry: RawEntry) -> dict:
    context = _full_context(entry)
    seed: dict = {}
    data_types = _deterministic_data_types(context)
    if data_types:
        seed["data_types"] = data_types
    initial_access = _deterministic_initial_access(context)
    if initial_access:
        seed["initial_access"] = initial_access
    impact = _deterministic_impact(context)
    if impact:
        seed["impact"] = impact
    return seed
''')
text = replace_func(text, "_fields_needed", '''def _fields_needed(item: Item, entry: RawEntry, seed: dict | None = None) -> set[str]:
    requested = _legacy_fields_needed(item, entry, seed)
    if not _has_semantic_context(entry):
        return requested
    seed = seed or {}
    requested.update({"summary", "attack_flow"})
    if not seed.get("initial_access"):
        requested.add("initial_access")
    if not seed.get("impact"):
        requested.add("impact")
    return requested
''')
idx = text.index("def _read_field_cache")
helper = '''def _revalidate_previous_cached_value(field: str, value, context: str):
    if value is None:
        return None
    if field == "attack_flow":
        cleaned = _normalize_attack_flow(value, context)
        return cleaned or None
    if field == "impact":
        return _normalize_impact(value, context)
    return value


'''
text = text[:idx] + helper + text[idx:]
text = replace_func(text, "_read_field_cache", '''def _read_field_cache(runtime: _Runtime, key: str, fields: set[str], context: str = "") -> tuple[dict, set[str]]:
    entry = runtime.cache.get(key)
    if not isinstance(entry, dict) or not isinstance(entry.get("fields"), dict):
        return {}, set()
    result: dict = {}
    satisfied: set[str] = set()
    for field in fields:
        cached = entry["fields"].get(field)
        if not isinstance(cached, dict):
            continue
        current_version = FIELD_VERSIONS[field]
        if cached.get("version") != current_version:
            previous = PREVIOUS_FIELD_VERSIONS.get(field)
            if previous and cached.get("version") == previous:
                cached["value"] = _revalidate_previous_cached_value(field, cached.get("value"), context)
                cached["version"] = current_version
            else:
                runtime.fields_invalidated += 1
                continue
        satisfied.add(field)
        runtime.field_cache_hits += 1
        if cached.get("value") is not None:
            result[field] = cached["value"]
    return result, satisfied
''')
text = replace_once(text, "    cached, satisfied = _read_field_cache(runtime, key, fields)\n", "    cached, satisfied = _read_field_cache(runtime, key, fields, full_context)\n", "cache context")
text = replace_once(text, "            legacy_values, legacy_satisfied = _read_field_cache(runtime, key, migrated)\n", "            legacy_values, legacy_satisfied = _read_field_cache(runtime, key, migrated, full_context)\n", "legacy cache context")
path.write_text(text, encoding="utf-8")

# source_facts.py
path = Path("cyberwatch/source_facts.py")
text = path.read_text(encoding="utf-8")
marker = "def _from_frenchbreaches(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:"
idx = text.index(marker)
helper = '''_INITIAL_ACCESS_LABELS = {
    "phishing": "un hameçonnage",
    "compromised_credentials": "des identifiants compromis",
    "vulnerability_exploitation": "l’exploitation d’une vulnérabilité",
    "remote_access": "un accès distant compromis",
    "third_party": "la compromission d’un tiers",
    "malware": "un logiciel malveillant",
    "other": "un vecteur documenté",
}


def _derive_summary(fact: dict, evidence: dict) -> None:
    if str(fact.get("Summary") or "").strip():
        return
    parts: list[str] = []
    proofs: list[str] = []
    initial = str(fact.get("Initial_Access") or "").strip()
    if initial:
        parts.append(f"Vecteur d’entrée documenté : {_INITIAL_ACCESS_LABELS.get(initial, initial)}.")
        proof = evidence.get("Initial_Access")
        if isinstance(proof, str) and proof:
            proofs.append(proof)
    flow = _loads_json(str(fact.get("Attack_Flow_JSON") or ""))
    if isinstance(flow, list) and flow:
        actions = [str(step.get("action") or "").strip() for step in flow if isinstance(step, dict)]
        actions = [action for action in actions if action][:2]
        if actions:
            parts.append("Déroulé documenté : " + " → ".join(actions) + ".")
        flow_proofs = evidence.get("Attack_Flow_JSON") or []
        if isinstance(flow_proofs, str):
            flow_proofs = [flow_proofs]
        if isinstance(flow_proofs, list):
            proofs.extend(str(value).strip() for value in flow_proofs[:2] if str(value).strip())
    impact = str(fact.get("Impact") or "").strip()
    if impact:
        parts.append("Impact documenté : " + impact.rstrip(" .") + ".")
        proof = evidence.get("Impact")
        if isinstance(proof, str) and proof:
            proofs.append(proof)
    if not parts:
        return
    summary = " ".join(parts)
    if len(summary) > source_facts_ai.MAX_SUMMARY_CHARS:
        summary = summary[:source_facts_ai.MAX_SUMMARY_CHARS - 1].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"
    fact["Summary"] = summary
    if proofs:
        evidence["Summary"] = " | ".join(proofs)[:source_facts_ai.MAX_EVIDENCE_CHARS]


'''
text = text[:idx] + helper + text[idx:]
needle = "    _apply_semantic_enrichment(fact, evidence, ai_result)\n\n    cves = _extract_cves(text)"
if text.count(needle) != 2:
    raise SystemExit(f"semantic enrichment marker count={text.count(needle)}")
text = text.replace(needle, "    _apply_semantic_enrichment(fact, evidence, ai_result)\n    _derive_summary(fact, evidence)\n\n    cves = _extract_cves(text)")
text = replace_func(text, "merge_source_facts", '''def merge_source_facts(existing: list[dict], incoming: list[dict]) -> list[dict]:
    refreshable = {"Summary", "Initial_Access", "Attack_Flow_JSON", "Impact"}
    base = {"Item_ID", "Source_ID", "Extraction_Method", "Extraction_Version", "Source_Metadata_JSON"}

    def merge_row(old: dict, new: dict) -> dict:
        merged = dict(old)
        old_evidence = _loads_json(str(old.get("Evidence_JSON") or ""))
        new_evidence = _loads_json(str(new.get("Evidence_JSON") or ""))
        evidence = dict(old_evidence) if isinstance(old_evidence, dict) else {}
        for field in refreshable:
            evidence.pop(field, None)
        if isinstance(new_evidence, dict):
            evidence.update(new_evidence)
        for column in SOURCE_FACT_COLUMNS:
            if column == "Evidence_JSON":
                continue
            value = new.get(column, "")
            if column in refreshable:
                merged[column] = value or ""
            elif column in base:
                if value not in (None, ""):
                    merged[column] = value
            elif value not in (None, ""):
                merged[column] = value
        merged["Evidence_JSON"] = _dumps_json(evidence)
        return merged

    by_id: dict[str, dict] = {}
    for row in existing:
        item_id = row.get("Item_ID")
        if item_id:
            by_id[item_id] = dict(row)
    for row in incoming:
        item_id = row.get("Item_ID")
        if not item_id:
            continue
        previous = by_id.get(item_id)
        by_id[item_id] = merge_row(previous, row) if previous else dict(row)
    return [by_id[key] for key in sorted(by_id)]
''')
path.write_text(text, encoding="utf-8")

# site.py
path = Path("cyberwatch/site.py")
text = path.read_text(encoding="utf-8")
text = replace_once(text, "from . import config, identity, sources, status, store\n", "from . import config, identity, incident_identity, sources, status, store\n", "site import")
marker = "def _source_facts_by_incident(items: list[Item], fact_rows: list[dict]) -> dict[str, list[dict]]:"
idx = text.index(marker)
helper = '''def _components_with_stable_incident_ids(items: list[Item]) -> list[tuple[list[Item], str]]:
    components = group_components(items)
    assigned, _ = incident_identity.assign_incident_ids(
        components, store.load_incident_id_registry()
    )
    return list(zip(components, assigned))


'''
text = text[:idx] + helper + text[idx:]
text = replace_once(
    text,
    "    for component in group_components(items):\n        ordered = identity.sort_items(component)\n        if not ordered:\n            continue\n        incident_id = _component_incident_id(ordered)\n",
    "    for component, incident_id in _components_with_stable_incident_ids(items):\n        ordered = identity.sort_items(component)\n        if not ordered:\n            continue\n",
    "source facts stable join",
)
text = replace_once(
    text,
    '    for component in group_components(items):\n        ordered = identity.sort_items(component)\n        if not ordered:\n            continue\n        llm_items = [item for item in ordered if item.Source_ID == "VEILLE_LLM"]\n        if not llm_items:\n            continue\n        incident_id = _component_incident_id(ordered)\n',
    '    for component, incident_id in _components_with_stable_incident_ids(items):\n        ordered = identity.sort_items(component)\n        if not ordered:\n            continue\n        llm_items = [item for item in ordered if item.Source_ID == "VEILLE_LLM"]\n        if not llm_items:\n            continue\n',
    "veille stable join",
)
path.write_text(text, encoding="utf-8")

# focused tests
Path("tests/test_enrichment_closeout.py").write_text('''from __future__ import annotations

import json

from cyberwatch import source_facts, source_facts_ai as sfa


def test_attack_flow_rejects_conditional_remediation_and_business_action():
    context = (
        "Une vulnérabilité aurait pu permettre l'accès aux données. "
        "La mairie déconnecte les serveurs pour empêcher la propagation. "
        "Valve fournit des informations client à CEVA Logistics pour les livraisons. "
        "L'attaquant a exfiltré des données clients."
    )
    raw = [
        {"action": "Exploitation d'une vulnérabilité", "confidence": .99, "evidence": "Une vulnérabilité aurait pu permettre l'accès aux données."},
        {"action": "La mairie déconnecte les serveurs", "confidence": .99, "evidence": "La mairie déconnecte les serveurs pour empêcher la propagation."},
        {"action": "Fournir des informations client à CEVA Logistics", "confidence": .99, "evidence": "Valve fournit des informations client à CEVA Logistics pour les livraisons."},
        {"action": "Exfiltration de données clients", "confidence": .99, "evidence": "L'attaquant a exfiltré des données clients."},
    ]
    assert [x["action"] for x in sfa._normalize_attack_flow(raw, context)] == ["Exfiltration de données clients"]


def test_deterministic_impact_rejects_conditionnel_et_remediation():
    assert sfa._deterministic_impact("L'attaque aurait entraîné une indisponibilité des systèmes.") is None
    assert sfa._deterministic_impact("Scalingo a mis le service hors ligne puis appliqué un correctif de sécurité.") is None
    assert sfa._deterministic_impact("Une interruption des services a duré plusieurs heures.") is not None


def test_initial_access_deterministe_strict():
    explicit = "Une intrusion sur l'intranet a été réalisée à partir du compte compromis d'un membre."
    result = sfa._deterministic_initial_access(explicit)
    assert result and result["value"] == "compromised_credentials"
    assert sfa._deterministic_initial_access("Il s'agirait d'une campagne de phishing ayant permis l'accès à certains comptes.") is None
    assert sfa._deterministic_initial_access("Le point d'entrée reste inconnu. Un phishing est possible.") is None


def test_summary_derivee_depuis_faits_valides():
    fact = {
        "Summary": "",
        "Initial_Access": "compromised_credentials",
        "Attack_Flow_JSON": json.dumps([{"action": "Exfiltration de données", "evidence": "preuve flow"}]),
        "Impact": "Interruption du service",
    }
    evidence = {"Initial_Access": "preuve accès", "Attack_Flow_JSON": ["preuve flow"], "Impact": "preuve impact"}
    source_facts._derive_summary(fact, evidence)
    assert fact["Summary"]
    assert len(fact["Summary"]) <= sfa.MAX_SUMMARY_CHARS
    assert evidence["Summary"]


def test_merge_source_facts_preserve_legacy_but_clear_refreshable():
    existing = [{
        "Item_ID": "ITM-1", "Source_ID": "FRENCHBREACHES", "Threat_Actor": "ZeroBytes",
        "Attack_Flow_JSON": "old-flow", "Impact": "old-impact",
        "Evidence_JSON": json.dumps({"Threat_Actor": "proof actor", "Attack_Flow_JSON": ["old"], "Impact": "old impact"}),
    }]
    incoming = [{
        "Item_ID": "ITM-1", "Source_ID": "FRENCHBREACHES", "Threat_Actor": "",
        "Attack_Flow_JSON": "", "Impact": "", "Evidence_JSON": "",
    }]
    merged = source_facts.merge_source_facts(existing, incoming)[0]
    assert merged["Threat_Actor"] == "ZeroBytes"
    assert merged["Attack_Flow_JSON"] == ""
    assert merged["Impact"] == ""
    evidence = json.loads(merged["Evidence_JSON"])
    assert evidence["Threat_Actor"] == "proof actor"
    assert "Attack_Flow_JSON" not in evidence
    assert "Impact" not in evidence
''', encoding="utf-8")
