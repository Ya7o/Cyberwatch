from __future__ import annotations

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
