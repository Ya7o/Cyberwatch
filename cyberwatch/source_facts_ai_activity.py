"""Validation atomique et reprise ciblée du couple activité/secteur."""
from __future__ import annotations

from . import config
from .sector_activity import (
    ACTIVITY_FIELDS,
    activity_from_text,
    contextual_proof,
    institutional_proof,
    names_third_party,
    supported_activity,
    victim_is_identifiable,
)
from .source_facts_ai_contract import (
    CACHE_STATUS_REJECTED,
    CACHE_STATUS_REJECTED_EXHAUSTED,
)

#: Familles de motifs. Elles séparent ce que le rapport doit distinguer : une
#: absence explicite d'activité dans l'article (jamais un échec) des cinq
#: manières dont une proposition peut être refusée.
KIND_ABSENT = "ABSENT"
KIND_ACTIVITY_NOT_DESCRIBED = "ACTIVITY_NOT_DESCRIBED"
KIND_THIRD_PARTY_ACTIVITY = "THIRD_PARTY_ACTIVITY"
KIND_AMBIGUOUS_IDENTITY = "AMBIGUOUS_IDENTITY"
KIND_EVIDENCE_NOT_FOUND = "EVIDENCE_NOT_FOUND"
#: Une citation exacte mais au-delà de la limite contractuelle n'est pas une
#: citation introuvable : les deux appellent une reprise différente.
KIND_EVIDENCE_TOO_LONG = "EVIDENCE_TOO_LONG"
KIND_SECTOR_CONTRADICTION = "SECTOR_CONTRADICTION"
#: Familles hors couple activité/secteur : headline refusée par son contrat,
#: autre validateur de champ, ou traitement qui n'a pas eu lieu.
KIND_HEADLINE_VALIDATION = "HEADLINE_VALIDATION"
KIND_FIELD_VALIDATION = "FIELD_VALIDATION"
KIND_NOT_PROCESSED = "NOT_PROCESSED"
KIND_LOW_CONFIDENCE = "LOW_CONFIDENCE"
KIND_UNCLASSIFIED = "UNCLASSIFIED"
#: Familles qui ne qualifient que le couple activité/secteur.
ACTIVITY_KINDS = frozenset({
    KIND_ACTIVITY_NOT_DESCRIBED, KIND_THIRD_PARTY_ACTIVITY,
    KIND_AMBIGUOUS_IDENTITY, KIND_SECTOR_CONTRADICTION,
})

REJECTION_KINDS: dict[str, str] = {
    "MISSING_MODEL_FIELD": KIND_ABSENT,
    "EMPTY_MODEL_VALUE": KIND_ABSENT,
    "CONFIDENCE_REJECTED": KIND_ACTIVITY_NOT_DESCRIBED,
    "EVIDENCE_MISSING": KIND_EVIDENCE_NOT_FOUND,
    "EVIDENCE_TOO_LONG": KIND_EVIDENCE_TOO_LONG,
    "EVIDENCE_NOT_GROUNDED": KIND_EVIDENCE_NOT_FOUND,
    "ACTIVITY_NOT_DESCRIBED": KIND_ACTIVITY_NOT_DESCRIBED,
    "ACTIVITY_THIRD_PARTY": KIND_THIRD_PARTY_ACTIVITY,
    "ACTIVITY_IDENTITY_AMBIGUOUS": KIND_AMBIGUOUS_IDENTITY,
    "ACTIVITY_VICTIM_BINDING_REJECTED": KIND_ACTIVITY_NOT_DESCRIBED,
    "NO_VALID_ACTIVITY_PAIR": KIND_ACTIVITY_NOT_DESCRIBED,
    "NO_VALID_TAXONOMY_MATCH": KIND_ACTIVITY_NOT_DESCRIBED,
    "EMPTY_OR_REJECTED_BY_VALIDATOR": KIND_ACTIVITY_NOT_DESCRIBED,
    "SECTOR_CONTRADICTS_ACTIVITY_EVIDENCE": KIND_SECTOR_CONTRADICTION,
    "SECTOR_ACTIVITY_EVIDENCE_MISMATCH": KIND_SECTOR_CONTRADICTION,
    "FIELD_VALIDATION_REJECTED": KIND_FIELD_VALIDATION,
    "TECHNICAL_FAILURE": KIND_NOT_PROCESSED,
    "CALL_LIMIT": KIND_NOT_PROCESSED,
    "COST_LIMIT": KIND_NOT_PROCESSED,
}


def rejection_kind(reason: str, default: str = KIND_ACTIVITY_NOT_DESCRIBED) -> str:
    """Famille d'un motif technique, pour le rapport et les compteurs."""
    code = str(reason or "").strip()
    if code in REJECTION_KINDS:
        return REJECTION_KINDS[code]
    if code.startswith("HEADLINE_"):
        return KIND_HEADLINE_VALIDATION
    return default


def field_rejection_kind(field: str, reason: str) -> str:
    """Famille d'un motif pour ce champ, sans lui prêter celle d'un autre.

    Une famille propre au couple activité/secteur ne qualifie que ce couple ;
    un motif inconnu reste non classé plutôt que rangé par défaut.
    """
    kind = rejection_kind(reason, default=KIND_UNCLASSIFIED)
    if field in ACTIVITY_FIELDS or kind not in ACTIVITY_KINDS:
        return kind
    if str(reason or "").strip() == "CONFIDENCE_REJECTED":
        return KIND_LOW_CONFIDENCE
    return KIND_UNCLASSIFIED


#: Champs dont le validateur juge la **citation**, jamais la valeur : un refus
#: `FIELD_VALIDATION_REJECTED` y désigne une preuve inadaptée à une valeur qui,
#: elle, reste recevable. Le couple activité/secteur en est exclu : son refus
#: porte sur l'identité de la victime ou sur la taxonomie, deux décisions
#: sémantiques qu'aucune nouvelle citation ne doit pouvoir retourner.
EVIDENCE_BOUND_FIELDS = frozenset({"threat_candidate", "summary", "incident_summary"})

#: Familles réparables sans toucher à la valeur proposée. `EVIDENCE_TOO_LONG`
#: et `EVIDENCE_NOT_FOUND` disent l'un et l'autre que la citation est mauvaise,
#: pas que la valeur l'est.
_REPAIRABLE_KINDS = frozenset({KIND_EVIDENCE_TOO_LONG, KIND_EVIDENCE_NOT_FOUND})


def evidence_repair_eligibility(field: str, rejection_code: str, rejection_kind_value: str = "") -> bool:
    """Ce refus peut-il être levé par une meilleure citation, à valeur égale ?

    La réparation de preuve ne rejuge rien : elle cherche, dans l'article, un
    extrait exact qui soutient la valeur **déjà proposée**. Un retry ne modifie
    jamais `value`. Une famille qui exprime un doute du modèle
    (`LOW_CONFIDENCE`), une abstention (`ABSENT`), une identité incertaine
    (`AMBIGUOUS_IDENTITY`) ou une taxonomie refusée (`ACTIVITY_NOT_DESCRIBED`,
    qui recouvre `NO_VALID_ACTIVITY_PAIR` et `NO_VALID_TAXONOMY_MATCH`) n'est
    donc pas réparable : la citer autrement ne la rendrait pas vraie.
    """
    code = str(rejection_code or "").strip()
    kind = str(rejection_kind_value or "").strip() or field_rejection_kind(field, code)
    if kind in _REPAIRABLE_KINDS:
        return True
    if kind == KIND_FIELD_VALIDATION or code == "FIELD_VALIDATION_REJECTED":
        return field in EVIDENCE_BOUND_FIELDS
    return False


def is_abstention(reason: str) -> bool:
    """Le modèle n'a rien proposé : décision terminale, pas un échec."""
    return rejection_kind(reason) == KIND_ABSENT


def binding_rejection(organisation: str, proof: str, context: str = "") -> str:
    """Pourquoi cette citation ne rattache pas l'activité à la victime.

    Un seul code recouvrait jusqu'ici trois situations que la collecte
    RUN-20260910T125214 a montrées distinctes : l'activité décrite est celle
    d'un prestataire, la citation ne désigne pas la victime, ou elle la
    désigne mais ne lui prête aucune activité.
    """
    if names_third_party(organisation, proof):
        return "ACTIVITY_THIRD_PARTY"
    if not victim_is_identifiable(organisation, proof):
        return "ACTIVITY_IDENTITY_AMBIGUOUS"
    return "ACTIVITY_NOT_DESCRIBED"


def pair_outcome(fields: dict) -> str:
    """Issue du couple activité/secteur, lue dans ses deux enregistrements.

    Un `miss` hérité compte comme un rejet : l'abstention est réservée au
    refus explicite du modèle, jamais déduite d'une absence de réponse.
    """
    statuses = {
        str((fields.get(field) or {}).get("status") or "").strip().lower()
        for field in ACTIVITY_FIELDS
    }
    if CACHE_STATUS_REJECTED_EXHAUSTED in statuses:
        return CACHE_STATUS_REJECTED_EXHAUSTED
    if statuses & {CACHE_STATUS_REJECTED, "miss"}:
        return CACHE_STATUS_REJECTED
    if statuses == {"accepted"}:
        return "accepted"
    return "abstained"


def rejection_reason(raw, context: str, organisation: str = "") -> str:
    from .source_facts_ai_normalize import evidence_rejection
    reason = evidence_rejection(raw, context)
    if reason:
        return reason
    return binding_rejection(organisation, " ".join(str(raw.get("evidence")).split()), context)


def normalize_activity(raw: dict, context: str, organisation: str) -> tuple[dict, dict]:
    from .source_facts_ai import _normalize_fact
    from .sector import classify_sector_activity

    result: dict = {}
    reasons: dict = {}
    activity = _normalize_fact(raw.get("activity_description"), context)
    matched = _normalize_fact(raw.get("activity_sector_match"), context)
    if not activity:
        reasons["activity_description"] = rejection_reason(
            raw.get("activity_description"), context, organisation
        )
    if not matched:
        reasons["activity_sector_match"] = rejection_reason(
            raw.get("activity_sector_match"), context, organisation
        )
    if activity:
        cited = activity["evidence"]
        proof = cited
        if not supported_activity(organisation, activity["value"], proof):
            proof = contextual_proof(organisation, proof, context)
        if proof and supported_activity(organisation, activity["value"], proof):
            activity = {**activity, "evidence": proof}
        else:
            # Une anaphore institutionnelle ne nomme jamais la victime : elle
            # est admise à part, et seulement si la phrase citée ou celle qui la
            # précède la rattache explicitement, sans collectivité concurrente.
            proof = institutional_proof(organisation, cited, context)
            if proof:
                activity = {**activity, "evidence": proof}
            else:
                activity = None
                reasons["activity_description"] = binding_rejection(organisation, cited, context)
    # Le secteur n'est pas promu seul : sa citation complète peut cependant
    # fournir une description littérale validée, sans nouvelle inférence LLM.
    if not activity and matched:
        expanded = contextual_proof(organisation, matched["evidence"], context)
        value, proof = activity_from_text(organisation, expanded or matched["evidence"])
        if value:
            activity = {"value": value, "evidence": proof, "confidence": matched["confidence"]}
            reasons.pop("activity_description", None)
    if not activity:
        for field in ACTIVITY_FIELDS:
            reasons.setdefault(field, "NO_VALID_ACTIVITY_PAIR")
        return result, reasons
    proposed_sector = classify_sector_activity(str(activity["value"]))
    evidence_sector = classify_sector_activity(str(activity["evidence"]))
    if (
        proposed_sector != config.SECTOR_UNKNOWN
        and evidence_sector != config.SECTOR_UNKNOWN
        and proposed_sector != evidence_sector
    ):
        # La citation est la donnée source. Si le libellé du modèle la
        # contredit, conserver la phrase littérale permet au déterministe de
        # classer ce qui est réellement écrit.
        activity = {**activity, "value": activity["evidence"]}
        proposed_sector = evidence_sector
        reasons["activity_description"] = "ACTIVITY_VALUE_REPLACED_BY_EVIDENCE"
    result["activity_description"] = activity
    if matched and matched["value"] in config.SECTORS and matched["value"] != config.SECTOR_UNKNOWN:
        from .normalize import searchable
        proof = searchable(activity["evidence"])
        other = searchable(matched["evidence"])
        matched_sector = str(matched["value"])
        if proposed_sector != config.SECTOR_UNKNOWN and matched_sector != proposed_sector:
            reasons["activity_sector_match"] = "SECTOR_CONTRADICTS_ACTIVITY_EVIDENCE"
        elif other in proof or proof in other:
            result["activity_sector_match"] = {**matched, "evidence": activity["evidence"]}
        else:
            reasons["activity_sector_match"] = "SECTOR_ACTIVITY_EVIDENCE_MISMATCH"
    else:
        reasons["activity_sector_match"] = "NO_VALID_TAXONOMY_MATCH"
    return result, reasons


def revalidate_activity_cache(entry: dict, context: str, organisation: str, versions: dict) -> None:
    fields = entry.get("fields", {})
    if not ACTIVITY_FIELDS.intersection(fields):
        return
    if all(fields.get(field, {}).get("version") == versions[field] for field in ACTIVITY_FIELDS):
        return
    raw = {field: fields.get(field, {}).get("value") for field in ACTIVITY_FIELDS}
    normalized, _ = normalize_activity(raw, context, organisation)
    for field, value in normalized.items():
        fields[field] = {"version": versions[field], "status": "accepted", "misses": 0,
                         "value": value, "validation": "REVALIDATED_ACTIVITY_PAIR"}
