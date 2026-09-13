"""Référentiel des preuves d'activité externes, avec TTL et invalidation.

Une activité prouvée à l'extérieur est une connaissance sur **l'organisation**,
pas sur l'incident : elle est donc stockée par clé canonique d'organisation et
réutilisée par tous les incidents suivants, sans nouvelle requête.

Deux propriétés font tout l'intérêt de ce fichier, et toutes deux tiennent à
une discipline de colonnes :

* ``Verified_At`` et ``Content_Hash`` décrivent le téléchargement qui a établi
  la preuve, et **n'avancent jamais** sur une simple relecture. Le suivi du TTL
  vit dans ``Last_Checked_At``, qui n'entre jamais dans le fait produit. Sans
  cette séparation, deux runs identiques écriraient des faits différents ;
* un échec est mémorisé (``Status`` + ``Rejection_Code``) au lieu d'être oublié.
  Une organisation sans preuve possible n'est pas re-interrogée chaque jour.

Ce module ne fait aucun appel réseau. L'écriture passe par ``store``, seul
responsable des fichiers.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass

from .organisation_activity import (
    VERIFICATION_METHODS,
    VerifiedActivityEvidence,
)
from .org_identity import effective_organisation_key

EVIDENCE_COLUMNS = [
    "Organisation_Key",
    "Organisation_Raw",
    "Activity_Description",
    "Evidence_Quote",
    "Evidence_URL",
    "Source_Type",
    "Provider",
    "Verified_At",
    "Content_Hash",
    "Status",
    # Dit quelle porte pure rejouer à la relecture : la prose et le registre
    # n'ont pas le même contrat de preuve.
    "Verification_Method",
    # Comptabilité du TTL, séparée de `Verified_At` — voir le docstring.
    "Last_Checked_At",
    "Rejection_Code",
    "Run_ID",
]

#: Toutes les portes ont été franchies : la preuve est applicable.
STATUS_VERIFIED = "VERIFIED"
#: Une porte a refusé pour une raison qui tient à la source elle-même.
STATUS_REJECTED = "REJECTED"
#: Aucun candidat n'existait : il n'y avait rien à vérifier.
STATUS_UNRESOLVED = "UNRESOLVED"
#: Une preuve auparavant vérifiée que la révalidation contredit, ou qu'un
#: opérateur invalide à la main. Collant : jamais réessayé automatiquement.
STATUS_WITHDRAWN = "WITHDRAWN"
#: Panne de transport ou budget épuisé : on n'a **rien** appris. Réessayé au
#: run suivant, car un zéro n'est un vrai zéro que si l'on a pu essayer.
STATUS_ERROR = "ERROR"

STATUSES = frozenset({
    STATUS_VERIFIED, STATUS_REJECTED, STATUS_UNRESOLVED, STATUS_WITHDRAWN, STATUS_ERROR,
})

#: Il n'existe **pas** de statut « shadow » : le mode shadow est une propriété
#: du run, pas de la preuve. Écrire `VERIFIED` pendant un run shadow est ce qui
#: fait de l'activation un simple basculement de drapeau, sans une seule requête.

#: Résultats de :func:`lookup`, pour que l'appelant sache pourquoi il doit (ou
#: non) aller chercher quelque chose.
HIT = "hit"
MISSING = "missing"
EXPIRED = "expired"
WITHDRAWN = "withdrawn"
INVALID = "invalid"


@dataclass(frozen=True)
class EvidenceRow:
    Organisation_Key: str = ""
    Organisation_Raw: str = ""
    Activity_Description: str = ""
    Evidence_Quote: str = ""
    Evidence_URL: str = ""
    Source_Type: str = ""
    Provider: str = ""
    Verified_At: str = ""
    Content_Hash: str = ""
    Status: str = ""
    Verification_Method: str = ""
    Last_Checked_At: str = ""
    Rejection_Code: str = ""
    Run_ID: str = ""

    def to_row(self) -> dict[str, str]:
        data = asdict(self)
        return {column: str(data.get(column, "") or "") for column in EVIDENCE_COLUMNS}

    @classmethod
    def from_row(cls, row: dict) -> "EvidenceRow":
        return cls(**{column: str(row.get(column) or "") for column in EVIDENCE_COLUMNS})


def _date_of(value: str) -> dt.date | None:
    """Date d'un horodatage ISO, jour seul ou complet. Jamais d'exception."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return dt.date.fromisoformat(text[:10])
        except ValueError:
            return None


def now_stamp() -> str:
    """Horodatage UTC à la seconde, stable et comparable."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def load(rows: list[dict]) -> dict[str, EvidenceRow]:
    """Indexe par clé canonique ; la dernière ligne d'une clé l'emporte."""
    indexed: dict[str, EvidenceRow] = {}
    for raw in rows:
        row = EvidenceRow.from_row(raw)
        if row.Organisation_Key.strip():
            indexed[row.Organisation_Key.strip()] = row
    return indexed


def _ttl_days(status: str, ttl_days: int, rejected_ttl_days: int,
              unresolved_ttl_days: int) -> int | None:
    """Nombre de jours avant re-contrôle ; ``None`` = jamais."""
    if status == STATUS_VERIFIED:
        return ttl_days
    if status == STATUS_REJECTED:
        return rejected_ttl_days
    if status == STATUS_UNRESOLVED:
        return unresolved_ttl_days
    if status == STATUS_ERROR:
        return 0
    return None


def invalidation(row: EvidenceRow) -> str:
    """Motif d'invalidité structurelle d'une ligne, hors TTL.

    Une évolution d'alias ou du registre d'identité peut avoir déplacé
    l'organisation : la ligne ne parle alors plus de la même entité. C'est
    exactement le risque que documente ``effective_organisation_key``.
    """
    if row.Status not in STATUSES:
        return INVALID
    if row.Status == STATUS_VERIFIED:
        if row.Verification_Method not in VERIFICATION_METHODS:
            return INVALID
        if not row.Activity_Description.strip() or not row.Evidence_Quote.strip():
            return INVALID
        if not row.Content_Hash.strip() or not row.Verified_At.strip():
            return INVALID
    if row.Organisation_Raw.strip():
        current = effective_organisation_key(row.Organisation_Raw, row.Organisation_Key)
        if current and current != row.Organisation_Key.strip():
            return INVALID
    return ""


def lookup(rows: dict[str, EvidenceRow], organisation_key: str, *, now: str,
           ttl_days: int, rejected_ttl_days: int,
           unresolved_ttl_days: int) -> tuple[EvidenceRow | None, str]:
    """Ligne utilisable pour cette organisation, et pourquoi.

    ``WITHDRAWN`` n'expire jamais : un retrait est une décision, pas une
    péremption. Le code rendu permet à l'appelant de distinguer « rien en
    cache » de « quelque chose en cache, mais à ne pas rejouer ».
    """
    row = rows.get((organisation_key or "").strip())
    if row is None:
        return None, MISSING
    if invalidation(row):
        return row, INVALID
    if row.Status == STATUS_WITHDRAWN:
        return row, WITHDRAWN
    horizon = _ttl_days(row.Status, ttl_days, rejected_ttl_days, unresolved_ttl_days)
    if horizon is None:
        return row, HIT
    checked = _date_of(row.Last_Checked_At or row.Verified_At)
    today = _date_of(now)
    if checked is None or today is None or (today - checked).days >= horizon:
        return row, EXPIRED
    return row, HIT


def upsert(rows: dict[str, EvidenceRow], row: EvidenceRow) -> dict[str, EvidenceRow]:
    """Remplace la ligne de cette organisation ; une clé vide n'écrit rien."""
    key = row.Organisation_Key.strip()
    if not key:
        return rows
    return {**rows, key: row}


def to_rows(rows: dict[str, EvidenceRow]) -> list[dict]:
    return [rows[key].to_row() for key in sorted(rows)]


def to_evidence(row: EvidenceRow) -> VerifiedActivityEvidence | None:
    """Preuve reconstituée depuis le cache, sans jamais rafraîchir sa datation."""
    if row.Status != STATUS_VERIFIED or invalidation(row):
        return None
    return VerifiedActivityEvidence(
        organisation=row.Organisation_Raw,
        organisation_key=row.Organisation_Key,
        activity_description=row.Activity_Description,
        evidence_quote=row.Evidence_Quote,
        evidence_url=row.Evidence_URL,
        source_type=row.Source_Type,
        provider=row.Provider,
        verified_at=row.Verified_At,
        content_hash=row.Content_Hash,
        verification_method=row.Verification_Method,
    )


def from_evidence(evidence: VerifiedActivityEvidence, *, run_id: str = "",
                  last_checked_at: str = "") -> EvidenceRow:
    return EvidenceRow(
        Organisation_Key=evidence.organisation_key,
        Organisation_Raw=evidence.organisation,
        Activity_Description=evidence.activity_description,
        Evidence_Quote=evidence.evidence_quote,
        Evidence_URL=evidence.evidence_url,
        Source_Type=evidence.source_type,
        Provider=evidence.provider,
        Verified_At=evidence.verified_at,
        Content_Hash=evidence.content_hash,
        Status=STATUS_VERIFIED,
        Verification_Method=evidence.verification_method,
        Last_Checked_At=last_checked_at or evidence.verified_at,
        Rejection_Code="",
        Run_ID=run_id,
    )


def outcome_row(organisation_raw: str, organisation_key: str, *, status: str,
                rejection_code: str, run_id: str = "",
                last_checked_at: str = "") -> EvidenceRow:
    """Ligne d'un résultat sans preuve : le motif est conservé, pas inventé."""
    return EvidenceRow(
        Organisation_Key=organisation_key,
        Organisation_Raw=organisation_raw,
        Status=status if status in STATUSES else STATUS_ERROR,
        Rejection_Code=rejection_code,
        Last_Checked_At=last_checked_at or now_stamp(),
        Run_ID=run_id,
    )
