"""Politique d'application des verdicts LLM de déduplication.

Un verdict du modèle n'écrit jamais directement dans un registre : il est
d'abord ancré dans les preuves de la paire, puis rejoué à travers les
garde-fous déterministes de `dedup.decide_merge`. Ce module contient
uniquement ces contrôles, séparés du transport et de la préparation.
"""

from __future__ import annotations

import datetime as dt
import json

from . import config, incident_dedup
from .dedup import MERGE, STRONG_KEEP_REASON_CODES, _temporal_pair, decide_merge
from .dedup_ai_contract import (
    DIFFERENT,
    DIFFERENT_CONFIDENCE_THRESHOLD,
    DAILY_BATCH_PROMPT_VERSION,
    DedupAiDecision,
    ORG_IDENTITY_CONFIDENCE_THRESHOLD,
    SAME,
    STATUS_CACHE_HIT,
    STATUS_OK,
)
from .duplicate_audit import DedupAuditCandidate
from .normalize import organisation_key, searchable


def _rank_alias_canonical(
    left_key: str, left_raw: str, right_key: str, right_raw: str,
) -> tuple[str, str, str, str]:
    """Choix déterministe : la clé la plus courte (moins de mots) devient
    l'alias, la plus longue devient canonique. Purement conventionnel — le
    résultat de dédoublonnage ne dépend pas de ce choix, seule la stabilité
    entre deux runs identiques compte."""
    def rank(key: str) -> tuple:
        return (len(key.split()), len(key), key)

    if rank(left_key) <= rank(right_key):
        return left_key, left_raw, right_key, right_raw
    return right_key, right_raw, left_key, left_raw


def _identity_evidence_covers_both(
    candidate: DedupAuditCandidate, decision: DedupAiDecision,
) -> bool:
    """Vérifie que la justification du modèle traite bien les deux victimes.

    Les décisions batch peuvent accidentellement réutiliser les faits d'un seul
    côté. Une confiance élevée ne remplace pas une preuve qui nomme les deux
    libellés comparés.
    """
    evidence = searchable(" ".join((decision.evidence, *decision.matched_facts)))
    def covered(item) -> bool:
        key = organisation_key(item.Organisation_Raw) or item.Organisation_Key
        normalized = searchable(key)
        return bool(normalized) and normalized in evidence

    return covered(candidate.left) and covered(candidate.right)


def _identity_decision_is_grounded(
    candidate: DedupAuditCandidate, decision: DedupAiDecision,
) -> bool:
    """Garde qualité commune aux écritures organisation et incident."""
    signals = candidate.signals
    if signals is None:
        # Les anciens candidats d'audit manuel n'alimentent pas le filet
        # quotidien. Leur contrat historique reste inchangé.
        return True
    if not signals.any_signal or not _identity_evidence_covers_both(candidate, decision):
        return False
    left_threat = candidate.left.Threat
    right_threat = candidate.right.Threat
    known_threats = {
        value for value in (left_threat, right_threat)
        if value and value != config.THREAT_UNKNOWN
    }
    # Une simple ressemblance floue ne suffit pas quand les deux sources
    # décrivent des familles de menace différentes. Un signal structurel
    # d'identité (nom compact, acronyme, domaine, identifiant) reste requis.
    if len(known_threats) > 1 and signals.strong_signal_count == 0:
        return False
    return True


def validate_ai_dedup_decision(
    candidate: DedupAuditCandidate,
    decision: DedupAiDecision,
    *,
    model: str = "",
    input_hash: str = "",
    now: str = "",
) -> dict[str, str] | None:
    """Politique déterministe d'application d'une décision LLM (§Lot 5).

    Seule porte d'entrée vers le registre d'identité organisationnelle : le
    LLM ne modifie jamais directement la base. Une proposition n'est renvoyée
    que si TOUTES ces conditions sont réunies :

    - la décision provient effectivement d'un appel ou d'un cache valide
      (`OK`/`CACHE_HIT`) ;
    - ``same_organisation == SAME`` ;
    - ``confidence >= ORG_IDENTITY_CONFIDENCE_THRESHOLD`` ;
    Les veto d'incident ne bloquent pas l'identité organisationnelle : deux
    attaques distinctes ou deux identifiants source différents peuvent viser
    exactement la même organisation. ``same_incident`` est persisté séparément
    par :func:`validate_ai_incident_decision`.
    """
    if decision.status not in {STATUS_OK, STATUS_CACHE_HIT}:
        return None
    if decision.same_organisation != SAME:
        return None
    if decision.confidence < ORG_IDENTITY_CONFIDENCE_THRESHOLD:
        return None
    if not _identity_decision_is_grounded(candidate, decision):
        return None
    left_key = organisation_key(candidate.left.Organisation_Raw) or candidate.left.Organisation_Key
    right_key = organisation_key(candidate.right.Organisation_Raw) or candidate.right.Organisation_Key
    if not left_key or not right_key or left_key == right_key:
        return None

    alias_key, alias_raw, canonical_key, canonical_raw = _rank_alias_canonical(
        left_key, candidate.left.Organisation_Raw,
        right_key, candidate.right.Organisation_Raw,
    )

    stamp = now or dt.datetime.now(dt.timezone.utc).isoformat()
    return {
        "Alias_Key": alias_key,
        "Canonical_Key": canonical_key,
        "Alias_Raw": alias_raw,
        "Canonical_Raw": canonical_raw,
        "Decision": "SAME",
        "Origin": "LLM_CONFIRMED",
        "Confidence": f"{decision.confidence:.4f}",
        "Evidence": decision.evidence,
        "First_Seen": stamp,
        "Last_Validated": stamp,
        "Model": model,
        "Prompt_Version": DAILY_BATCH_PROMPT_VERSION,
        "Input_Hash": input_hash,
    }


def validate_ai_incident_decision(
    candidate: DedupAuditCandidate,
    decision: DedupAiDecision,
    *,
    model: str = "",
    input_hash: str = "",
    now: str = "",
) -> dict[str, str] | None:
    """Produit une décision d'incident persistante, ou s'abstient.

    Seuls ``SAME`` et ``DIFFERENT`` à confiance forte sont actionnables. Un
    verdict ``SAME`` ne peut pas contourner un veto déterministe fort. Un
    verdict ``DIFFERENT`` ne peut pas davantage casser une fusion déjà
    certaine pour le moteur déterministe ; il n'est persistant que lorsque
    le moteur s'abstient ou conserve déjà les deux événements séparés.
    """
    if decision.status not in {STATUS_OK, STATUS_CACHE_HIT}:
        return None
    if decision.same_organisation != SAME:
        return None
    if decision.same_incident not in {SAME, DIFFERENT}:
        return None
    if decision.confidence < ORG_IDENTITY_CONFIDENCE_THRESHOLD:
        return None
    if not _identity_decision_is_grounded(candidate, decision):
        return None
    if (
        decision.same_incident == DIFFERENT
        and decision.confidence < DIFFERENT_CONFIDENCE_THRESHOLD
    ):
        return None
    native = decide_merge(candidate.left, candidate.right)
    if decision.same_incident == SAME:
        # Validate time independently of canonical-name equality. Previously
        # NO_DECISION on different spellings bypassed this check before aliasing.
        temporal = _temporal_pair(candidate.left, candidate.right)
        if temporal is None or abs((temporal[0] - temporal[1]).days) > config.INCIDENT_GAP_DAYS:
            return None
        if (candidate.left.Event_Date and candidate.right.Event_Date
                and candidate.left.Event_Date != candidate.right.Event_Date):
            return None
        # Rejouer la décision dans le moteur déterministe permet d'appliquer
        # la borne temporelle dure (et les veto forts) avant toute écriture du
        # registre. Une organisation peut rester la même à long terme, mais
        # deux incidents ne sont jamais fusionnés par le LLM au-delà de la
        # fenêtre opérationnelle.
        llm_checked = decide_merge(
            candidate.left,
            candidate.right,
            {incident_dedup.pair_key(candidate.left.Item_ID, candidate.right.Item_ID): SAME},
        )
        if llm_checked.reason_code in STRONG_KEEP_REASON_CODES:
            return None
    if decision.same_incident == DIFFERENT and native.action == MERGE:
        return None

    left_id, right_id = sorted((candidate.left.Item_ID, candidate.right.Item_ID))
    if not left_id or not right_id or left_id == right_id:
        return None
    stamp = now or dt.datetime.now(dt.timezone.utc).isoformat()
    return {
        "Pair_Key": incident_dedup.pair_key(left_id, right_id),
        "Left_Item_ID": left_id,
        "Right_Item_ID": right_id,
        "Decision": decision.same_incident,
        "Confidence": f"{decision.confidence:.4f}",
        "Evidence": decision.evidence,
        "Reason": decision.reason,
        "Matched_Facts_JSON": json.dumps(list(decision.matched_facts), ensure_ascii=False),
        "Conflicting_Facts_JSON": json.dumps(list(decision.conflicting_facts), ensure_ascii=False),
        "First_Seen": stamp,
        "Last_Validated": stamp,
        "Model": model,
        "Prompt_Version": DAILY_BATCH_PROMPT_VERSION,
        "Input_Hash": input_hash,
    }

