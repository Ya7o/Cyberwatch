"""Contrat commun de preuve activité/victime, indépendant du transport LLM."""
from __future__ import annotations

import re

from .normalize import searchable

ACTIVITY_FIELDS = {"activity_description", "activity_sector_match"}
_ACTIVITY = re.compile(
    r"\b(?:specialis\w*|commercialis\w*|vend\w*|vente|boutique|negoce|"
    r"distribu\w*|fabric\w*|produi\w*|production|edite\w*|editeur|developp\w*|"
    r"formation|enseignement|teleconsult\w*|transports?|logistique|reexpedition|"
    r"expedition|livraison|restauration|restaurants?|repas|hebergement|hotell\w*|"
    r"logiciels?|applications?|cloud|stockage|chimie|batiment|second oeuvre|"
    r"agric\w*|horticulture|syndica\w*|represente|accompagne|"
    r"municipalite|organisme public|etablissement public|sante|foncier\w*|"
    r"gestion|assurance|banque|conseil|sport\w*|football|mobilite|immobili\w*|"
    r"repar\w*|plomberie|chauffage|climatisation|fidelis\w*|emploi|tourisme)\b"
)
_THIRD_PARTY = re.compile(r"\b(?:prestataire|fournisseur|partenaire|client|filiale|sous traitant)\b")
_PREFIX = re.compile(
    r"(?:(?:la |le |l |une |un )?(?:societe|entreprise|reseau|plateforme) ?|"
    r"(?:une |la )?(?:importante |nouvelle )?(?:fuite(?: de donnees)?|cyberattaque|attaque) "
    r"(?:visant|attribuee a|contre|touche|touchant)|la|le|l)?$"
)
_SUBJECT = re.compile(
    r"^(?:est|sont|etait|entreprise|societe|reseau|plateforme|service|dispositif|"
    r"cooperative|organisme|etablissement|association|groupe|specialis\w*|"
    r"commercialis\w*|vend\w*|propose|permet|intervient|exerce|assure|"
    r"developp\w*|edite\w*|editeur|fabrique|represente|accompagne|"
    r"transporte|distribue|gere|informe|confirme|le service|la plateforme)\b"
)


def organisation_span(organisation: str, evidence: str) -> tuple[int, int] | None:
    """Normalized spelling, including spaces and a final plural ``s`` variant."""
    org = searchable(organisation)
    proof = searchable(evidence)
    if not org:
        return None
    compact = org.replace(" ", "")
    base = compact[:-1] if len(compact) >= 6 and compact.endswith("s") else compact
    plural = "s?" if len(base) >= 6 else ""
    pattern = r"(?<!\w)" + r"\s*".join(re.escape(c) for c in base) + plural + r"(?!\w)"
    match = re.search(pattern, proof)
    return match.span() if match else None


def supported_activity(organisation: str, value: str, evidence: str) -> bool:
    proof = searchable(evidence)
    segments = re.split(r"(?<=[.!?;])\s+|\n+", evidence)
    if len(segments) > 1:
        return any(supported_activity(organisation, value, part) for part in segments if part.strip())
    span = organisation_span(organisation, evidence)
    if span is None:
        # Keep the existing, controlled institutional acronym contract.
        from .source_facts import _activity_evidence_matches_organisation
        if not _activity_evidence_matches_organisation(organisation, evidence):
            return False
        body = proof
    else:
        if _THIRD_PARTY.search(proof[:span[0]]):
            return False
        body = proof[span[1]:].strip()
        if not _SUBJECT.search(body):
            return False
    if re.search(r"\b(?:son|ses|le|un|du|d un) (?:prestataire|fournisseur|partenaire|client)\b", body):
        return False
    if re.search(r"\b(?:utilise|fait appel|client de|via)\b", body):
        return False
    return bool(value and _ACTIVITY.search(body))


def contextual_proof(organisation: str, evidence: str, context: str) -> str:
    """Étend la citation à sa phrase si la victime en est le sujet explicite."""
    org = searchable(organisation)
    needle = searchable(evidence)
    if not org or not needle:
        return ""
    for sentence in re.split(r"(?<=[.!?;])\s+|\n+", context):
        normalized = searchable(sentence)
        if needle not in normalized or len(sentence) > 300:
            continue
        span = organisation_span(organisation, sentence)
        if span is None or not _PREFIX.fullmatch(normalized[:span[0]].strip()):
            continue
        if supported_activity(organisation, sentence, sentence):
            return sentence.strip()
    return ""


def activity_from_text(organisation: str, *texts: str) -> tuple[str, str]:
    from . import config
    from .sector import classify_sector_activity

    candidates = []
    for text in texts:
        for sentence in re.split(r"(?<=[.!?;])\s+|\n+", text or ""):
            proof = contextual_proof(organisation, sentence, sentence)
            if proof:
                # Prefer a classifiable, explicit business activity over an
                # ambiguous teaser. Keep source order on equally strong proofs.
                known = classify_sector_activity(proof) != config.SECTOR_UNKNOWN
                concrete = bool(re.search(r"\b(?:commercialis\w*|vend\w*|fabrique|edite|intervient)\b", searchable(proof)))
                candidates.append(((known, concrete), proof))
    if not candidates:
        return "", ""
    proof = max(candidates, key=lambda pair: pair[0])[1]
    return proof, proof
