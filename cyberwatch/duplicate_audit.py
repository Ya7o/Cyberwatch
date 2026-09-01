"""Détection conservatrice des cas de déduplication à examiner.

Ce module ne modifie jamais les items et ne rapproche aucune identité : il
produit uniquement des candidats étayés par des indices reproductibles. La
menace et la catégorie de l'organisation ne servent pas de filtre d'identité :
deux sources peuvent qualifier différemment le même événement, et les victimes
institutionnelles doivent rester auditables comme les autres.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from . import config
from .dedup import MERGE, NO_DECISION, decide_merge
from .model import Item
from .normalize import date_or_empty, organisation_acronym, organisation_key
from .org_identity import effective_organisation_key


DUPLICATE_CANDIDATE_NAME_CONTAINMENT = "DUPLICATE_CANDIDATE_NAME_CONTAINMENT"
#: Concaténation exacte : « france casse » vs « francecasse » (mêmes lettres,
#: espace en moins, un nombre de mots différent).
DUPLICATE_CANDIDATE_CONCATENATION = "DUPLICATE_CANDIDATE_CONCATENATION"
#: Permutation exacte des mêmes mots : « cravero motoculture » vs
#: « motoculture cravero » (mêmes mots, même nombre, ordre différent).
DUPLICATE_CANDIDATE_PERMUTATION = "DUPLICATE_CANDIDATE_PERMUTATION"
#: Deux identités textuelles distinctes résolues par le registre vers le même
#: identifiant d'entreprise. C'est une preuve d'identité, pas de même incident.
DUPLICATE_CANDIDATE_SHARED_COMPANY_ID = "DUPLICATE_CANDIDATE_SHARED_COMPANY_ID"

MERGE_REVIEW_WEAK_CANONICAL_NAME = "MERGE_REVIEW_WEAK_CANONICAL_NAME"
MERGE_REVIEW_WEAK_ALIAS = "MERGE_REVIEW_WEAK_ALIAS"
MERGE_REVIEW_RANSOMWARE_CORROBORATION = "MERGE_REVIEW_RANSOMWARE_CORROBORATION"

#: Candidat détecté par le filet quotidien LLM (§Lot 1/2) : un nouvel item
#: comparé au corpus historique, avec des signaux plus larges (fuzzy compris)
#: que les motifs stricts ci-dessus. Sert uniquement à sélectionner des paires
#: à soumettre au LLM : aucun de ces signaux, fuzzy inclus, n'autorise une
#: fusion, un alias ou une modification d'Organisation_Key par lui-même.
DUPLICATE_CANDIDATE_DAILY_LLM = "DUPLICATE_CANDIDATE_DAILY_LLM"

RISK_MISSED_DUPLICATE = "POSSIBLE_MISSED_DUPLICATE"
RISK_FALSE_MERGE = "POSSIBLE_FALSE_MERGE"

#: Signaux "haute confiance" (§Lot 4, gate qualité) : correspondance EXACTE
#: sur l'ensemble des mots — rien en plus, rien en moins, juste réarrangés ou
#: recollés. Contrairement à l'inclusion, volontairement large et non
#: bloquante (des victimes institutionnelles légitimement distinctes s'y
#: recoupent, cf. tests), ces deux signaux n'ont pas de faux positif connu :
#: exiger l'ensemble exact des mots exclut structurellement les sous-entités
#: (« City Pro » / « City Pro Marionneau » ne matche ni l'un ni l'autre).
HIGH_CONFIDENCE_REASON_CODES = frozenset({
    DUPLICATE_CANDIDATE_CONCATENATION,
    DUPLICATE_CANDIDATE_PERMUTATION,
})


@dataclass(frozen=True)
class DuplicateCandidate:
    """Deux items proches, mais volontairement non fusionnés."""

    short: Item
    long: Item
    days_apart: int
    reason_code: str = DUPLICATE_CANDIDATE_NAME_CONTAINMENT


@dataclass(frozen=True)
class CandidateSignals:
    """Indices de génération de candidat, purement descriptifs.

    Aucun de ces signaux, individuellement ou combiné, n'autorise une fusion,
    un alias ou une réécriture d'``Organisation_Key`` : ils servent uniquement
    à sélectionner et classer les paires soumises au LLM (§Lot 1). Seule une
    décision LLM validée (confiance forte, absence de conflit déterministe) et
    persistée dans le registre d'identité peut influencer
    ``effective_organisation_key``.
    """

    exact_key: bool = False
    compact_match: bool = False
    token_permutation: bool = False
    containment: bool = False
    acronym_match: bool = False
    shared_company_id: bool = False
    shared_victim_domain: bool = False
    fuzzy_score: float = 0.0

    @property
    def strong_signal_count(self) -> int:
        return sum([
            self.compact_match,
            self.token_permutation,
            self.containment,
            self.acronym_match,
            self.shared_company_id,
            self.shared_victim_domain,
        ])

    @property
    def any_signal(self) -> bool:
        return self.strong_signal_count > 0 or self.fuzzy_score >= DAILY_LLM_FUZZY_THRESHOLD


#: Seuil minimal de similarité pour qu'une paire sans aucun signal structurel
#: entre malgré tout dans le périmètre du filet quotidien. Volontairement bas :
#: ce n'est qu'une porte d'entrée vers le LLM, jamais une preuve d'identité.
DAILY_LLM_FUZZY_THRESHOLD = 0.5

#: Nombre maximal de candidats historiques conservés par nouvel item, après
#: classement déterministe (§Lot 1). Limite le bruit envoyé au batch LLM.
DAILY_LLM_MAX_CANDIDATES_PER_ITEM = 5


@dataclass(frozen=True)
class DedupAuditCandidate:
    """Paire à challenger sans modifier la déduplication de production."""

    risk_type: str
    left: Item
    right: Item
    days_apart: int
    reason_code: str
    company_id: str = ""
    signals: CandidateSignals | None = None


def _contains_word_sequence(long_key: str, short_key: str) -> bool:
    long_words = long_key.split()
    short_words = short_key.split()
    if not short_words or len(short_words) >= len(long_words):
        return False
    width = len(short_words)
    return any(
        long_words[index:index + width] == short_words
        for index in range(len(long_words) - width + 1)
    )


def _same_concatenated(a_key: str, b_key: str) -> bool:
    """Vrai si les deux clés ne diffèrent que par la présence d'espaces."""
    a_tokens, b_tokens = a_key.split(), b_key.split()
    if len(a_tokens) == len(b_tokens):
        return False
    return "".join(a_tokens) == "".join(b_tokens)


def _same_permutation(a_key: str, b_key: str) -> bool:
    """Vrai si les deux clés partagent exactement les mêmes mots, dans un
    ordre différent."""
    a_tokens, b_tokens = a_key.split(), b_key.split()
    return a_key != b_key and len(a_tokens) > 1 and sorted(a_tokens) == sorted(b_tokens)


def _effective_key(item: Item) -> str:
    """Clé d'organisation actuelle, aliases compris, sans réécrire l'item."""
    return effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)


def _ordered_pair(left: Item, right: Item) -> tuple[Item, Item]:
    return tuple(sorted(
        (left, right),
        key=lambda item: (
            item.best_date,
            item.Source_ID,
            item.Source_Item_ID,
            item.Item_ID,
            item.URL,
        ),
    ))  # type: ignore[return-value]


def _days_apart(left: Item, right: Item) -> int | None:
    left_date = date_or_empty(left.best_date)
    right_date = date_or_empty(right.best_date)
    if not left_date or not right_date:
        return None
    return abs((left_date - right_date).days)


def _company_id(item: Item, company_ids: dict[str, str]) -> str:
    """Résout l'identifiant déjà validé dans le cache d'enrichissement."""
    return (
        company_ids.get(item.Organisation_Key, "")
        or company_ids.get(_effective_key(item), "")
    )


def find_duplicate_candidates(
    items: list[Item],
    max_days: int = config.INCIDENT_GAP_DAYS,
) -> list[DuplicateCandidate]:
    """Retourne des candidats d'audit sans jamais ordonner leur fusion.

    Critères strictement déterministes : sources distinctes, dates à moins de
    `max_days` et inclusion d'une séquence entière de mots d'organisation. La
    menace n'est pas un critère d'identité et aucun mot générique (agence,
    fédération, université, ville...) n'est exclu : ces cas doivent précisément
    rester visibles dans l'audit.

    La fenêtre d'audit suit la fenêtre maximale de la méthode (14 jours par
    défaut), tandis que la fusion automatique faible reste limitée à 3 jours
    dans ``dedup.decide_merge``. Entre J+4 et J+14, on observe sans fusionner.
    """
    candidates: list[DuplicateCandidate] = []
    ordered = sorted(
        items,
        key=lambda item: (
            item.Published_Date,
            item.Source_ID,
            item.Item_ID,
            item.URL,
        ),
    )

    for index, left in enumerate(ordered):
        left_date = date_or_empty(left.best_date)
        if not left.Organisation_Key or not left_date:
            continue

        for right in ordered[index + 1:]:
            if left.Source_ID == right.Source_ID:
                continue

            right_date = date_or_empty(right.best_date)
            if not right.Organisation_Key or not right_date:
                continue

            days_apart = abs((left_date - right_date).days)
            if days_apart > max_days:
                continue

            short, long = sorted(
                (left, right),
                key=lambda item: (
                    len(item.Organisation_Key.split()),
                    len(item.Organisation_Key),
                    item.Organisation_Key,
                ),
            )
            if _contains_word_sequence(long.Organisation_Key, short.Organisation_Key):
                candidates.append(DuplicateCandidate(short, long, days_apart))
            elif _same_concatenated(short.Organisation_Key, long.Organisation_Key):
                candidates.append(DuplicateCandidate(
                    short, long, days_apart, DUPLICATE_CANDIDATE_CONCATENATION
                ))
            elif _same_permutation(short.Organisation_Key, long.Organisation_Key):
                candidates.append(DuplicateCandidate(
                    short, long, days_apart, DUPLICATE_CANDIDATE_PERMUTATION
                ))

    return sorted(
        candidates,
        key=lambda candidate: (
            candidate.short.Organisation_Key,
            candidate.long.Organisation_Key,
            candidate.days_apart,
            candidate.short.Source_ID,
            candidate.long.Source_ID,
        ),
    )


def find_audit_candidates(
    items: list[Item],
    company_ids: dict[str, str] | None = None,
    max_days: int = config.INCIDENT_GAP_DAYS,
) -> list[DedupAuditCandidate]:
    """Retourne uniquement les décisions de déduplication qui méritent revue.

    Deux risques sont exposés sans jamais changer la production :
    - ``POSSIBLE_MISSED_DUPLICATE`` : le moteur reste en ``NO_DECISION`` mais
      un signal de nom ou un Company_ID commun suggère la même victime ;
    - ``POSSIBLE_FALSE_MERGE`` : le moteur fusionne sur une règle faible sans
      identifiant natif ni date d'événement égale.

    ``Company_ID`` est seulement un signal d'identité d'organisation : il ne
    suffit jamais à affirmer qu'il s'agit du même incident.
    """
    company_ids = company_ids or {}
    candidates: dict[tuple[str, str, str], DedupAuditCandidate] = {}

    def add(candidate: DedupAuditCandidate) -> None:
        left, right = _ordered_pair(candidate.left, candidate.right)
        normalized = DedupAuditCandidate(
            candidate.risk_type,
            left,
            right,
            candidate.days_apart,
            candidate.reason_code,
            candidate.company_id,
        )
        key = (normalized.risk_type, left.Item_ID, right.Item_ID)
        existing = candidates.get(key)
        if (
            existing
            and existing.reason_code == DUPLICATE_CANDIDATE_SHARED_COMPANY_ID
        ):
            return
        candidates[key] = normalized

    for lexical in find_duplicate_candidates(items, max_days=max_days):
        if _effective_key(lexical.short) == _effective_key(lexical.long):
            continue
        if decide_merge(lexical.short, lexical.long).action != NO_DECISION:
            continue
        add(DedupAuditCandidate(
            RISK_MISSED_DUPLICATE,
            lexical.short,
            lexical.long,
            lexical.days_apart,
            lexical.reason_code,
        ))

    ordered = sorted(
        items,
        key=lambda item: (
            item.best_date,
            item.Source_ID,
            item.Source_Item_ID,
            item.Item_ID,
            item.URL,
        ),
    )
    for index, left in enumerate(ordered):
        if not left.best_date:
            continue
        for right in ordered[index + 1:]:
            days_apart = _days_apart(left, right)
            if days_apart is None or days_apart > max_days:
                continue

            decision = decide_merge(left, right)
            if decision.action == NO_DECISION and _effective_key(left) != _effective_key(right):
                left_company = _company_id(left, company_ids)
                right_company = _company_id(right, company_ids)
                if left_company and left_company == right_company:
                    add(DedupAuditCandidate(
                        RISK_MISSED_DUPLICATE,
                        left,
                        right,
                        days_apart,
                        DUPLICATE_CANDIDATE_SHARED_COMPANY_ID,
                        left_company,
                    ))
                continue

            if decision.action != MERGE:
                continue
            if left.Source_ID == right.Source_ID and left.URL and left.URL == right.URL:
                continue
            if decision.reason_code == "INCIDENT_MERGE_CANONICAL_NAME":
                reason_code = MERGE_REVIEW_WEAK_CANONICAL_NAME
            elif decision.reason_code == "INCIDENT_MERGE_ALIAS":
                reason_code = MERGE_REVIEW_WEAK_ALIAS
            elif decision.reason_code == "INCIDENT_MERGE_RANSOMWARE_CORROBORATION":
                reason_code = MERGE_REVIEW_RANSOMWARE_CORROBORATION
            else:
                continue
            add(DedupAuditCandidate(
                RISK_FALSE_MERGE,
                left,
                right,
                days_apart,
                reason_code,
            ))

    return sorted(
        candidates.values(),
        key=lambda candidate: (
            candidate.risk_type,
            candidate.left.best_date,
            candidate.left.Organisation_Key,
            candidate.right.Organisation_Key,
            candidate.left.Source_ID,
            candidate.right.Source_ID,
            candidate.left.Item_ID,
            candidate.right.Item_ID,
        ),
    )


# --------------------------------------------------------------------------
# Filet quotidien LLM (§Lot 1/2) : périmètre restreint, signaux explicites
# --------------------------------------------------------------------------


def _compact(key: str) -> str:
    return key.replace(" ", "")


def _fuzzy_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return round(SequenceMatcher(None, a, b).ratio(), 4)


def compute_candidate_signals(
    left: Item,
    right: Item,
    *,
    company_ids: dict[str, str] | None = None,
    victim_websites: dict[str, str] | None = None,
) -> CandidateSignals:
    """Calcule les indices de rapprochement d'une paire, sans autoriser de fusion.

    Le fuzzy est comparé à la fois entre les deux formes compactes et entre
    chaque forme compacte et l'acronyme déterministe de l'autre libellé : cela
    permet de retrouver des cas réels (« DGFiP » vs le nom complet) où la
    similarité brute des deux chaînes serait trop faible pour être utile,
    sans jamais transformer ce score en preuve d'identité.
    """
    company_ids = company_ids or {}
    victim_websites = victim_websites or {}

    left_key = organisation_key(left.Organisation_Raw) or left.Organisation_Key
    right_key = organisation_key(right.Organisation_Raw) or right.Organisation_Key
    left_compact, right_compact = _compact(left_key), _compact(right_key)
    left_acronym = organisation_acronym(left.Organisation_Raw).lower()
    right_acronym = organisation_acronym(right.Organisation_Raw).lower()

    exact_key = bool(left_key) and left_key == right_key
    compact_match = _same_concatenated(left_key, right_key)
    token_permutation = _same_permutation(left_key, right_key)
    short, long = sorted((left_key, right_key), key=len)
    containment = _contains_word_sequence(long, short)
    acronym_match = bool(left_acronym) and (
        left_compact == right_acronym or right_compact == left_acronym
    )

    left_company = company_ids.get(left.Organisation_Key, "") or company_ids.get(left_key, "")
    right_company = company_ids.get(right.Organisation_Key, "") or company_ids.get(right_key, "")
    shared_company_id = bool(left_company) and left_company == right_company

    left_site = (victim_websites.get(left.Item_ID, "") or "").strip().lower()
    right_site = (victim_websites.get(right.Item_ID, "") or "").strip().lower()
    shared_victim_domain = bool(left_site) and left_site == right_site

    fuzzy_score = max(
        _fuzzy_ratio(left_compact, right_compact),
        _fuzzy_ratio(left_compact, right_acronym),
        _fuzzy_ratio(right_compact, left_acronym),
    )

    return CandidateSignals(
        exact_key=exact_key,
        compact_match=compact_match,
        token_permutation=token_permutation,
        containment=containment,
        acronym_match=acronym_match,
        shared_company_id=shared_company_id,
        shared_victim_domain=shared_victim_domain,
        fuzzy_score=fuzzy_score,
    )


def signal_rank(signals: CandidateSignals) -> tuple:
    """Clé de tri déterministe : plus de signaux forts, puis fuzzy plus élevé."""
    return (-signals.strong_signal_count, -signals.fuzzy_score)


def find_daily_llm_candidates(
    new_or_updated_items: list[Item],
    historical_items: list[Item],
    *,
    company_ids: dict[str, str] | None = None,
    victim_websites: dict[str, str] | None = None,
    max_candidates_per_item: int = DAILY_LLM_MAX_CANDIDATES_PER_ITEM,
) -> list[DedupAuditCandidate]:
    """Périmètre quotidien restreint (§Lot 2) : nouveaux/rafraîchis × historique.

    Le LLM intervient uniquement après le déterministe, sur les paires que ce
    dernier a laissées séparées. Il ne recontrôle donc pas les fusions déjà
    faites. La fonction ne compare jamais toute la base à elle-même : seulement
    le petit ensemble d'items nouveaux ou rafraîchis dans la fenêtre MAJ contre
    le corpus existant (et entre eux). Le classement est déterministe et borné
    à ``max_candidates_per_item`` candidats par nouvel item.
    """
    company_ids = company_ids or {}
    victim_websites = victim_websites or {}

    scope_ids = {item.Item_ID for item in new_or_updated_items if item.Item_ID}
    corpus = {item.Item_ID: item for item in historical_items if item.Item_ID}
    corpus.update({item.Item_ID: item for item in new_or_updated_items if item.Item_ID})

    scope_ordered = sorted(
        (item for item in new_or_updated_items if item.Item_ID),
        key=lambda item: item.Item_ID,
    )
    seen_pairs: set[tuple[str, str]] = set()
    selected: list[DedupAuditCandidate] = []

    for scope_item in scope_ordered:
        ranked: list[tuple[tuple, DedupAuditCandidate]] = []
        for other_id, other in corpus.items():
            if other_id == scope_item.Item_ID:
                continue
            # Une paire de deux items du périmètre du jour n'est évaluée qu'une
            # fois, quel que soit l'ordre de traitement.
            if other_id in scope_ids and other_id < scope_item.Item_ID:
                continue
            pair_key = tuple(sorted((scope_item.Item_ID, other_id)))
            if pair_key in seen_pairs:
                continue
            left, right = _ordered_pair(scope_item, other)
            deterministic = decide_merge(left, right)
            if deterministic.action != NO_DECISION:
                # Une fusion ou un veto déjà tranché reste déterministe. Le LLM
                # sert seulement de filet pour les doublons non détectés.
                continue
            signals = compute_candidate_signals(
                left, right, company_ids=company_ids, victim_websites=victim_websites,
            )
            if not signals.any_signal:
                continue
            days = _days_apart(left, right)
            candidate = DedupAuditCandidate(
                RISK_MISSED_DUPLICATE,
                left,
                right,
                days if days is not None else -1,
                DUPLICATE_CANDIDATE_DAILY_LLM,
                company_ids.get(left.Organisation_Key, "") or company_ids.get(right.Organisation_Key, ""),
                signals,
            )
            ranked.append((
                signal_rank(signals)
                + (abs(candidate.days_apart), left.Item_ID, right.Item_ID),
                candidate,
            ))

        ranked.sort(key=lambda pair: pair[0])
        for _, candidate in ranked[:max_candidates_per_item]:
            pair_key = tuple(sorted((candidate.left.Item_ID, candidate.right.Item_ID)))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)
            selected.append(candidate)

    return sorted(
        selected,
        key=lambda candidate: (candidate.left.Item_ID, candidate.right.Item_ID),
    )


def dedup_identity_benchmark(cases: list[dict]) -> dict:
    """Mesure `known_duplicate_recall` / `known_nonduplicate_false_merge_count`
    sur le corpus de régression (§Lot 0/16), sans aucun appel réseau.

    Chaque cas est un nom d'organisation seul (``left``/``right``), pas un
    item réel : ce benchmark qualifie la couverture du moteur déterministe
    (aliases, identités territoriales, registre) et de la génération de
    candidats, indépendamment de toute décision LLM effective. Pour une
    paire positive, la « couverture » est satisfaite si le moteur
    déterministe unifie déjà les deux libellés, ou si le filet quotidien
    produirait au moins un candidat à challenger (c'est-à-dire que le
    système *peut* la résoudre, même sans avoir encore appelé le LLM). Pour
    une paire négative, tout rapprochement déterministe déjà effectif est un
    faux positif d'identité — la seule mesure exigée bloquante (§Lot 16) :
    ``known_nonduplicate_false_merge_count == 0``.
    """
    from .org_identity import effective_organisation_key

    recall_hits = 0
    recall_total = 0
    false_merges: list[str] = []

    for case in cases:
        left_raw, right_raw = case.get("left", ""), case.get("right", "")
        case_id = case.get("case_id", f"{left_raw}|{right_raw}")
        left_key = effective_organisation_key(left_raw)
        right_key = effective_organisation_key(right_raw)
        already_unified = bool(left_key) and left_key == right_key

        if case.get("same_organisation"):
            recall_total += 1
            if already_unified:
                recall_hits += 1
            else:
                left_item = Item(Item_ID="BENCH-L", Organisation_Raw=left_raw, Organisation_Key=organisation_key(left_raw))
                right_item = Item(Item_ID="BENCH-R", Organisation_Raw=right_raw, Organisation_Key=organisation_key(right_raw))
                if find_daily_llm_candidates([left_item], [left_item, right_item]):
                    recall_hits += 1
        elif already_unified:
            false_merges.append(case_id)

    return {
        "known_duplicate_recall_hits": recall_hits,
        "known_duplicate_recall_total": recall_total,
        "known_duplicate_recall_pct": (
            round(100.0 * recall_hits / recall_total, 2) if recall_total else 100.0
        ),
        "known_nonduplicate_false_merge_count": len(false_merges),
        "known_nonduplicate_false_merge_cases": sorted(false_merges),
    }
