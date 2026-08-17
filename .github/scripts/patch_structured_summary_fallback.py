from pathlib import Path

SOURCE = Path("cyberwatch/source_facts.py")
TESTS = Path("tests/test_enrichment_closeout.py")

old = '''def _derive_summary(fact: dict, evidence: dict) -> None:
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

new = '''def _format_int_fr(value: str) -> str:
    try:
        return f"{int(str(value).strip()):,}".replace(",", " ")
    except (TypeError, ValueError):
        return str(value or "").strip()


def _join_fr(values: list[str]) -> str:
    values = [str(value).strip() for value in values if str(value).strip()]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} et {values[1]}"
    return ", ".join(values[:-1]) + f" et {values[-1]}"


def _evidence_values(value) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, dict):
        return [str(item).strip() for item in value.values() if str(item).strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _structured_summary(fact: dict, evidence: dict) -> tuple[str, list[str]]:
    details: list[str] = []
    proofs: list[str] = []

    volume = str(fact.get("Data_Volume_Raw") or "").strip()
    if volume:
        details.append(f"{volume} de données")
        proofs.extend(_evidence_values(evidence.get("Data_Volume_Raw")) or [volume])

    affected_raw = str(fact.get("Affected_Count_Raw") or "").strip()
    affected_unit = str(fact.get("Affected_Unit") or "").strip()
    if affected_raw:
        details.append(affected_raw)
        proofs.extend(_evidence_values(evidence.get("Affected_Count_Raw")) or [affected_raw])

    file_count = str(fact.get("File_Count") or "").strip()
    if file_count and affected_unit != "files":
        details.append(f"{_format_int_fr(file_count)} fichiers")
        proofs.extend(_evidence_values(evidence.get("File_Count")))

    data_types = _loads_json(str(fact.get("Data_Types_JSON") or ""))
    if not isinstance(data_types, list):
        data_types = []
    data_types = [str(value).strip() for value in data_types if str(value).strip()][:3]
    if data_types:
        proofs.extend(_evidence_values(evidence.get("Data_Types_JSON")))

    # Un seul type de donnée sans volume ni comptage est trop pauvre pour
    # justifier une carte de synthèse. On préfère l'abstention à un doublon UI.
    if not details and len(data_types) < 2:
        return "", []

    if details:
        summary = "Éléments documentés : " + _join_fr(details)
        if data_types:
            summary += " ; données concernées : " + _join_fr(data_types)
        summary += "."
    else:
        summary = "Données concernées : " + _join_fr(data_types) + "."
    return summary, proofs


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
    if parts:
        summary = " ".join(parts)
    else:
        summary, structured_proofs = _structured_summary(fact, evidence)
        proofs.extend(structured_proofs)
        if not summary:
            return
    if len(summary) > source_facts_ai.MAX_SUMMARY_CHARS:
        summary = summary[:source_facts_ai.MAX_SUMMARY_CHARS - 1].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"
    fact["Summary"] = summary
    if proofs:
        evidence["Summary"] = " | ".join(dict.fromkeys(proofs))[:source_facts_ai.MAX_EVIDENCE_CHARS]
'''

text = SOURCE.read_text(encoding="utf-8")
if old not in text:
    raise SystemExit("source_facts.py target block not found")
SOURCE.write_text(text.replace(old, new), encoding="utf-8")

addition = r'''


def test_summary_fallback_depuis_faits_structures_sans_appel_ai():
    fact = {
        "Summary": "",
        "Initial_Access": "",
        "Attack_Flow_JSON": "",
        "Impact": "",
        "Data_Volume_Raw": "20,6 Go",
        "Affected_Count_Raw": "",
        "Affected_Unit": "",
        "File_Count": "39000",
        "Data_Types_JSON": json.dumps(["adresses e-mail", "données bancaires"]),
    }
    evidence = {
        "Data_Volume_Raw": "20,6 Go",
        "File_Count": "39 000 fichiers",
        "Data_Types_JSON": {
            "adresses e-mail": "adresses e-mail",
            "données bancaires": "données bancaires",
        },
    }
    source_facts._derive_summary(fact, evidence)
    assert fact["Summary"] == (
        "Éléments documentés : 20,6 Go de données et 39 000 fichiers ; "
        "données concernées : adresses e-mail et données bancaires."
    )
    assert evidence["Summary"]


def test_summary_fallback_ne_duplique_pas_un_compteur_de_fichiers():
    fact = {
        "Summary": "",
        "Initial_Access": "",
        "Attack_Flow_JSON": "",
        "Impact": "",
        "Data_Volume_Raw": "3,7 Go",
        "Affected_Count_Raw": "49 168 fichiers",
        "Affected_Unit": "files",
        "File_Count": "49168",
        "Data_Types_JSON": "",
    }
    evidence = {"Affected_Count_Raw": "49 168 fichiers"}
    source_facts._derive_summary(fact, evidence)
    assert fact["Summary"] == "Éléments documentés : 3,7 Go de données et 49 168 fichiers."


def test_summary_fallback_s_abstient_sur_un_seul_type_isole():
    fact = {
        "Summary": "",
        "Initial_Access": "",
        "Attack_Flow_JSON": "",
        "Impact": "",
        "Data_Volume_Raw": "",
        "Affected_Count_Raw": "",
        "Affected_Unit": "",
        "File_Count": "",
        "Data_Types_JSON": json.dumps(["mots de passe"]),
    }
    evidence = {"Data_Types_JSON": {"mots de passe": "mots de passe"}}
    source_facts._derive_summary(fact, evidence)
    assert fact["Summary"] == ""
'''

tests = TESTS.read_text(encoding="utf-8")
marker = "test_summary_fallback_depuis_faits_structures_sans_appel_ai"
if marker not in tests:
    TESTS.write_text(tests + addition, encoding="utf-8")
