"""Moteur générique de résolution d'activité métier externe (niveau 2).

Seul module du niveau 2 à détenir un ``HttpClient``. Il orchestre : cache,
découverte, téléchargement sous garde, vérification, puis mémorisation. Il ne
décide **rien** lui-même sur le fond : chaque acceptation vient d'une porte pure
de :mod:`cyberwatch.organisation_activity`, chaque refus porte un motif du
vocabulaire fermé, et rien n'est jamais fatal pour la collecte.

Ce que le moteur produit est volontairement minimal : un triplet vérifié
``(activity_description, evidence_quote, evidence_url)``. Écrit dans le fait, il
active toute la chaîne sectorielle **existante** — déterministe d'abord, puis
l'unique mapper taxonomique — sans une ligne de logique sectorielle nouvelle.

Budget : le moteur possède son propre :class:`~cyberwatch.http.Budget` et ne
peut donc jamais consommer celui de la collecte, dont dépend la couverture des
sources. À noter, et c'est une imprécision assumée : ``HttpClient`` lit les
``robots.txt`` hors budget, donc vérifier une organisation sur un hôte inédit
coûte réellement une requête comptée et une non comptée.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

from . import config, url_safety
from . import organisation_activity as contract
from . import organisation_activity_candidates as discovery
from . import organisation_activity_registry as registry
from . import organisation_activity_store as evidence_store
from . import organisation_activity_llm as quote_llm
from . import status as status_codes
from .collectors.editorial_html import editorial_text, usable_detail
from .http import Budget, HttpClient
from .model import Item
from .org_identity import effective_organisation_key
from .organisation_activity import ActivityCandidate, VerifiedActivityEvidence

logger = logging.getLogger(__name__)

#: Motifs HTTP qui décrivent un refus de cible, et non une panne de transport.
_URL_REFUSALS = {
    status_codes.REASON_URL_REJECTED: contract.EXTERNAL_URL_REJECTED,
    status_codes.REASON_REDIRECT_REJECTED: contract.EXTERNAL_REDIRECT_REJECTED,
    status_codes.REASON_CONTENT_TOO_LARGE: contract.EXTERNAL_CONTENT_REJECTED,
    status_codes.REASON_CONTENT_TYPE: contract.EXTERNAL_CONTENT_REJECTED,
    status_codes.REASON_ROBOTS: contract.EXTERNAL_ROBOTS_DISALLOW,
    status_codes.REASON_BUDGET_RUN: contract.EXTERNAL_BUDGET_EXHAUSTED,
    status_codes.REASON_BUDGET_SOURCE: contract.EXTERNAL_BUDGET_EXHAUSTED,
}

#: Résultats de cache qui dispensent de toute requête.
_TERMINAL_CACHE = {evidence_store.HIT, evidence_store.WITHDRAWN}

#: Motifs qui décrivent le transport ou la découverte, pas la preuve. Ils sont
#: moins informatifs qu'un refus de vérification : « la page nommait un
#: homonyme » doit survivre au 404 du candidat suivant, sinon la trace et le
#: rapport de benchmark ne disent plus rien d'exploitable.
_WEAK_STATUSES = frozenset({
    contract.EXTERNAL_NO_CANDIDATE, contract.EXTERNAL_FETCH_FAILED,
    contract.EXTERNAL_URL_REJECTED, contract.EXTERNAL_HOST_NOT_ALLOWED,
    contract.EXTERNAL_CONTENT_REJECTED, contract.EXTERNAL_ROBOTS_DISALLOW,
    contract.EXTERNAL_REDIRECT_REJECTED, contract.EXTERNAL_SOURCE_NOT_AUTHORISED,
    contract.EXTERNAL_ERROR, contract.EXTERNAL_NO_TEXT,
})


def _most_informative(current: str, candidate: str) -> str:
    """Conserve le premier refus substantiel rencontré sur les candidats.

    Un refus de vérification l'emporte sur un refus de transport ; à force
    égale, le premier est gardé, pour que l'ordre des candidats ne change pas
    le motif rapporté.
    """
    if not candidate:
        return current
    if not current:
        return candidate
    if current in _WEAK_STATUSES and candidate not in _WEAK_STATUSES:
        return candidate
    return current


@dataclass
class ExternalActivityCounters:
    """Compteurs du niveau 2, tenus séparément de la télémétrie source_facts."""

    organisations_eligible: int = 0
    organisations_attempted: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    candidates_discovered: int = 0
    candidates_fetched: int = 0
    urls_rejected: int = 0
    fetch_failures: int = 0
    quotes_deterministic: int = 0
    quotes_llm: int = 0
    llm_calls: int = 0
    taxonomy_calls: int = 0
    verified: int = 0
    applied: int = 0
    shadowed: int = 0
    withdrawn: int = 0
    budget_blocked: int = 0
    rejected: dict[str, int] = field(default_factory=dict)

    def reject(self, external_status: str) -> None:
        self.rejected[external_status] = self.rejected.get(external_status, 0) + 1

    def as_dict(self) -> dict:
        return {
            "organisations_eligible": self.organisations_eligible,
            "organisations_attempted": self.organisations_attempted,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "candidates_discovered": self.candidates_discovered,
            "candidates_fetched": self.candidates_fetched,
            "urls_rejected": self.urls_rejected,
            "fetch_failures": self.fetch_failures,
            "quotes_deterministic": self.quotes_deterministic,
            "quotes_llm": self.quotes_llm,
            "llm_calls": self.llm_calls,
            "taxonomy_calls": self.taxonomy_calls,
            "verified": self.verified,
            "applied": self.applied,
            "shadowed": self.shadowed,
            "withdrawn": self.withdrawn,
            "budget_blocked": self.budget_blocked,
            "rejected": dict(sorted(self.rejected.items())),
        }


def _hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


class ExternalActivityEngine:
    """Resolver injecté dans ``blf_org_enrichment.enrich`` via ``provider=``.

    Le contrat vu par l'appelant est minuscule : ``resolve(item)`` rend une
    preuve vérifiée ou ``None``, et ``last_status`` dit pourquoi. L'appelant ne
    fait jamais confiance au résultat — il le repasse par
    ``organisation_activity.accepts``.
    """

    def __init__(self, *, items: list[Item], facts: list[dict], reference: dict,
                 policy: contract.SourcePolicy, client, budget: Budget,
                 rows: dict[str, evidence_store.EvidenceRow] | None = None,
                 run_id: str = "", now: str = "",
                 resolver: url_safety.Resolver | None = None,
                 quote_call: quote_llm.Caller | None = None):
        self.items = items
        self.facts_by_item = {str(row.get("Item_ID") or ""): row for row in facts}
        self.facts = facts
        self.reference = reference or {}
        self.policy = policy
        self.client = client
        self.budget = budget
        self.rows = dict(rows or {})
        self.run_id = run_id
        self.now = now or evidence_store.now_stamp()
        self.resolver = resolver
        self.quote_call = quote_call
        self.counters = ExternalActivityCounters()
        self.events: list[dict] = []
        self.last_status = contract.EXTERNAL_NOT_ELIGIBLE
        #: Décision par organisation, pour que plusieurs items d'une même
        #: composante ne relancent ni requête ni appel.
        self._memo: dict[str, tuple[VerifiedActivityEvidence | None, str]] = {}
        self._guard = url_safety.hop_guard(resolver=resolver)

    # -- entrée publique ---------------------------------------------------

    def resolve(self, item: Item) -> VerifiedActivityEvidence | None:
        """Preuve vérifiée pour l'organisation de cet item, ou ``None``."""
        key = effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
        if not self.policy.authorises(item.Source_ID) or not key:
            self.last_status = contract.EXTERNAL_SOURCE_NOT_AUTHORISED
            return None
        if key in self._memo:
            found, self.last_status = self._memo[key]
            return found
        found, self.last_status = self._decide(item, key)
        self._memo[key] = (found, self.last_status)
        self._record_event(item, key, found, self.last_status)
        return found

    # -- décision ----------------------------------------------------------

    def _decide(self, item: Item, key: str) -> tuple[VerifiedActivityEvidence | None, str]:
        self.counters.organisations_eligible += 1
        from .sector_resolution import _decision_from_reference

        if _decision_from_reference(item, self.reference):
            return None, contract.EXTERNAL_NOT_ELIGIBLE

        cached, verdict = self._cached(key)
        if verdict in _TERMINAL_CACHE:
            return cached, self.last_status
        if self.counters.organisations_attempted >= self.policy.budgets.max_orgs:
            return self._store_outcome(item, key, evidence_store.STATUS_ERROR,
                                       contract.EXTERNAL_BUDGET_EXHAUSTED)
        if self.budget.exhausted:
            return self._store_outcome(item, key, evidence_store.STATUS_ERROR,
                                       contract.EXTERNAL_BUDGET_EXHAUSTED)
        self.counters.organisations_attempted += 1
        return self._attempt(item, key)

    def _cached(self, key: str) -> tuple[VerifiedActivityEvidence | None, str]:
        """Lecture du référentiel. Une preuve est toujours re-vérifiée à la relecture."""
        budgets = self.policy.budgets
        row, verdict = evidence_store.lookup(
            self.rows, key, now=self.now, ttl_days=budgets.ttl_days,
            rejected_ttl_days=budgets.rejected_ttl_days,
            unresolved_ttl_days=budgets.unresolved_ttl_days)
        if verdict == evidence_store.WITHDRAWN:
            self.counters.withdrawn += 1
            self.last_status = contract.EXTERNAL_WITHDRAWN
            return None, evidence_store.WITHDRAWN
        if verdict != evidence_store.HIT or row is None:
            self.counters.cache_misses += 1
            return None, verdict
        self.counters.cache_hits += 1
        if row.Status != evidence_store.STATUS_VERIFIED:
            self.last_status = row.Rejection_Code or contract.EXTERNAL_NO_CANDIDATE
            return None, evidence_store.HIT
        self.last_status = contract.EXTERNAL_ACTIVITY_CACHE_HIT
        return evidence_store.to_evidence(row), evidence_store.HIT

    def _attempt(self, item: Item, key: str) -> tuple[VerifiedActivityEvidence | None, str]:
        """Essaie les candidats dans l'ordre ; le premier vérifié l'emporte."""
        candidates = discovery.discover(item.Organisation_Raw, key, self.items,
                                        self.facts, self.reference, self.policy)
        self.counters.candidates_discovered += len(candidates)
        if not candidates:
            return self._store_outcome(item, key, evidence_store.STATUS_UNRESOLVED,
                                       contract.EXTERNAL_NO_CANDIDATE)
        quote_used = False
        last = ""
        for candidate in candidates:
            if self.budget.exhausted:
                last = _most_informative(last, contract.EXTERNAL_BUDGET_EXHAUSTED)
                self.counters.budget_blocked += 1
                break
            body, refusal = self._fetch(candidate)
            if body is None:
                last = _most_informative(last, refusal)
                continue
            if candidate.source_type == contract.SOURCE_PUBLIC_REGISTRY:
                found, refusal = self._verify_structured(item, key, candidate, body)
            else:
                found, refusal, quote_used = self._verify_prose(
                    item, key, candidate, body, quote_used)
            if found is not None:
                self.counters.verified += 1
                return self._store_verified(item, key, found)
            last = _most_informative(last, refusal)
        last = last or contract.EXTERNAL_NO_CANDIDATE
        status = (evidence_store.STATUS_ERROR
                  if last in {contract.EXTERNAL_BUDGET_EXHAUSTED, contract.EXTERNAL_FETCH_FAILED,
                              contract.EXTERNAL_ERROR, contract.EXTERNAL_LLM_BUDGET_EXHAUSTED}
                  else evidence_store.STATUS_REJECTED)
        return self._store_outcome(item, key, status, last)

    # -- transport ---------------------------------------------------------

    def _fetch(self, candidate: ActivityCandidate) -> tuple[str | None, str]:
        """Corps téléchargé sous garde de cible, ou motif. Jamais d'exception."""
        spec = self.policy.source_type(candidate.source_type)
        if spec is None:
            return None, contract.EXTERNAL_SOURCE_NOT_AUTHORISED
        host_rejection = self.policy.host_rejection(
            candidate.source_type, _host(candidate.url))
        if host_rejection:
            self.counters.urls_rejected += 1
            return None, host_rejection
        rejection = url_safety.url_rejection(candidate.url, resolver=self.resolver,
                                             require_https=spec.require_https)
        if rejection:
            self.counters.urls_rejected += 1
            return None, contract.EXTERNAL_URL_REJECTED
        try:
            response = self.client.fetch(
                candidate.url, self.budget,
                max_content_bytes=spec.max_content_bytes,
                allowed_content_types=spec.allowed_content_types,
                url_guard=self._guard,
            )
        except Exception as exc:  # noqa: BLE001 — le niveau 2 n'échoue jamais fort
            logger.warning("external_activity_fetch_failed url=%s error=%s",
                           candidate.url, type(exc).__name__)
            return None, contract.EXTERNAL_ERROR
        self.counters.candidates_fetched += 1
        if not response.ok:
            mapped = _URL_REFUSALS.get(response.reason_code, contract.EXTERNAL_FETCH_FAILED)
            if mapped == contract.EXTERNAL_FETCH_FAILED:
                self.counters.fetch_failures += 1
            return None, mapped
        return response.text, ""

    # -- vérification ------------------------------------------------------

    def _verify_prose(self, item: Item, key: str, candidate: ActivityCandidate,
                      body: str, quote_used: bool,
                      ) -> tuple[VerifiedActivityEvidence | None, str, bool]:
        """Portes 5 à 14 du chemin prose, dans l'ordre du moins coûteux au plus.

        L'appel LLM de la porte 9 n'est atteignable qu'après les portes pures
        d'identité : c'est ce qui garantit qu'aucun chemin déterministe ne
        consomme d'appel, et qu'au plus un appel est émis par organisation.
        """
        from .sector_activity import activity_from_text, victim_is_identifiable

        text = editorial_text(body) or body
        if not text.strip():
            return None, contract.EXTERNAL_NO_TEXT, quote_used
        if not usable_detail(text, ""):
            return None, contract.EXTERNAL_CHALLENGE_BODY, quote_used
        if not victim_is_identifiable(item.Organisation_Raw, text):
            return None, contract.EXTERNAL_IDENTITY_NOT_NAMED, quote_used

        activity, quote = activity_from_text(item.Organisation_Raw, text)
        if quote:
            self.counters.quotes_deterministic += 1
        elif quote_used or not self.policy.quote_llm:
            return None, contract.EXTERNAL_NO_QUOTE, quote_used
        else:
            quote_used = True
            quote, origin = quote_llm.select_quote(
                item.Organisation_Raw, text, call=self.quote_call)
            if origin == quote_llm.ORIGIN_CALL:
                self.counters.llm_calls += 1
                self.counters.quotes_llm += 1
            if origin == quote_llm.ORIGIN_BUDGET:
                return None, contract.EXTERNAL_LLM_BUDGET_EXHAUSTED, quote_used
            if not quote:
                return None, contract.EXTERNAL_NO_QUOTE, quote_used
            # La valeur EST la citation : le modèle ne peut introduire aucune
            # valeur propre, seulement désigner une phrase de la page.
            activity = quote

        rejection = contract.verify_prose_evidence(
            item.Organisation_Raw, key, activity, quote, text)
        if rejection:
            return None, rejection, quote_used
        return self._evidence(item, key, candidate, activity, quote, text,
                              contract.VERIFY_PROSE_LITERAL), "", quote_used

    def _verify_structured(self, item: Item, key: str, candidate: ActivityCandidate,
                           body: str) -> tuple[VerifiedActivityEvidence | None, str]:
        """Chemin registre : identité unique, corroborée, puis libellé officiel."""
        record, rejection = registry.select(registry.parse(body), key)
        if record is None or rejection:
            return None, rejection or contract.EXTERNAL_IDENTITY_UNVERIFIED
        fact = self.facts_by_item.get(item.Item_ID, {})
        geo = registry.geographic_rejection(
            record, item.Location, str(fact.get("Fine_Location") or ""))
        if geo:
            return None, geo
        activity, naf_rejection = registry.activity_label(record)
        if naf_rejection:
            return None, naf_rejection
        quote = registry.structured_quote(record)
        verdict = contract.verify_structured_evidence(
            item.Organisation_Raw, key, activity, quote)
        if verdict:
            return None, verdict
        return self._evidence(item, key, candidate, activity, quote, body,
                              contract.VERIFY_REGISTRY_STRUCTURED), ""

    def _evidence(self, item: Item, key: str, candidate: ActivityCandidate,
                  activity: str, quote: str, body: str,
                  method: str) -> VerifiedActivityEvidence:
        return VerifiedActivityEvidence(
            organisation=item.Organisation_Raw,
            organisation_key=key,
            activity_description=activity,
            evidence_quote=quote,
            evidence_url=candidate.url,
            source_type=candidate.source_type,
            provider=candidate.provider,
            verified_at=self.now,
            content_hash=_hash(body),
            verification_method=method,
        )

    # -- mémorisation ------------------------------------------------------

    def _store_verified(self, item: Item, key: str, found: VerifiedActivityEvidence,
                        ) -> tuple[VerifiedActivityEvidence, str]:
        self.rows = evidence_store.upsert(self.rows, evidence_store.from_evidence(
            found, run_id=self.run_id, last_checked_at=self.now))
        return found, contract.EXTERNAL_ACTIVITY_VERIFIED

    def _store_outcome(self, item: Item, key: str, status: str, external_status: str,
                       ) -> tuple[None, str]:
        """Mémorise un résultat sans preuve, motif conservé.

        Un échec de transport ou de budget est écrit en ``ERROR`` et non en
        ``REJECTED`` : on n'a rien appris sur l'organisation, donc le run
        suivant doit réessayer. Distinguer les deux est la même discipline que
        celle de ``status.py`` — un zéro n'est un vrai zéro que si l'on a pu
        essayer.
        """
        if external_status == contract.EXTERNAL_BUDGET_EXHAUSTED:
            self.counters.budget_blocked += 1
        self.counters.reject(external_status)
        self.rows = evidence_store.upsert(self.rows, evidence_store.outcome_row(
            item.Organisation_Raw, key, status=status, rejection_code=external_status,
            run_id=self.run_id, last_checked_at=self.now))
        return None, external_status

    # -- observabilité -----------------------------------------------------

    def _record_event(self, item: Item, key: str, found: VerifiedActivityEvidence | None,
                      external_status: str) -> None:
        """Un événement par organisation éligible, jamais par requête.

        Même règle que ``sector_semantic._save_trace`` : cela distingue « rien à
        faire » de « essayé et refusé ». Ni le corps de la page, ni aucune clé
        d'API n'y figurent, et la citation est tronquée.
        """
        self.events.append({
            "organisation": item.Organisation_Raw,
            "organisation_key": key,
            "item_id": item.Item_ID,
            "source_id": item.Source_ID,
            "external_status": external_status,
            "shadow": self.policy.shadow,
            "verification_method": found.verification_method if found else "",
            "provider": found.provider if found else "",
            "source_type": found.source_type if found else "",
            "evidence_url": found.evidence_url if found else "",
            "content_hash": found.content_hash if found else "",
            "activity_description": found.activity_description if found else "",
            "evidence_quote": (found.evidence_quote[:300] if found else ""),
            "requests": self.budget.requests_made,
            "llm_calls": self.counters.llm_calls,
            "run_id": self.run_id,
        })

    @property
    def shadow(self) -> bool:
        """Mode de ce moteur, tel que sa policy l'a résolu.

        L'appelant lit cet attribut plutôt que de relire l'environnement :
        une seule source de vérité, et le mode reste injectable pour les tests
        et le benchmark.
        """
        return self.policy.shadow

    def note_decision(self, *, applied: bool) -> None:
        """Ce que l'appelant a réellement fait de la preuve.

        Distingue « vérifiée » de « appliquée » : en mode shadow une preuve est
        vérifiée et consignée sans toucher au secteur publié, et un
        durcissement de politique peut aussi faire refuser à l'application une
        preuve que le moteur avait acceptée.
        """
        if applied:
            self.counters.applied += 1
        else:
            self.counters.shadowed += 1

    def evidence_rows(self) -> list[dict]:
        """Lignes du référentiel de preuves, triées, prêtes à persister."""
        return evidence_store.to_rows(self.rows)

    def summary(self) -> dict:
        payload = self.counters.as_dict()
        payload.update({
            "shadow": self.policy.shadow,
            "requests": self.budget.requests_made,
            "seconds": round(self.budget.seconds_spent, 2),
        })
        return payload

    def summary_line(self) -> str:
        counters = self.counters
        rejects = ", ".join(f"{name}:{count}" for name, count in
                            sorted(counters.rejected.items())) or "aucun"
        return (
            f"mode={'shadow' if self.policy.shadow else 'actif'} "
            f"éligibles={counters.organisations_eligible} "
            f"vérifiées={counters.verified} appliquées={counters.applied} "
            f"shadow={counters.shadowed} "
            f"cache={counters.cache_hits}/{counters.cache_hits + counters.cache_misses} "
            f"requêtes={self.budget.requests_made} llm={counters.llm_calls} "
            f"rejets={rejects}"
        )


def _host(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return (urlsplit(str(url or "")).hostname or "").lower()
    except ValueError:
        return ""


def build_engine(items: list[Item], facts: list[dict], reference: dict, *,
                 offline: bool = False, run_id: str = "",
                 env: dict | None = None, client=None, rows: dict | None = None,
                 resolver: url_safety.Resolver | None = None,
                 quote_call: quote_llm.Caller | None = None,
                 now: str = "") -> ExternalActivityEngine | None:
    """Moteur prêt à l'emploi, ou ``None`` s'il n'y a rien à faire.

    Rend ``None`` — donc ``provider=None`` chez l'appelant, donc le chemin
    historique **octet pour octet** — dans trois cas : exécution hors ligne
    (REPLAY n'a pas de réseau et ne doit pas en acquérir), interrupteur maître
    éteint, ou aucun item d'une source autorisée dans le corpus.

    C'est ici, et nulle part ailleurs, que vit la garde ``offline``.
    """
    if offline or not contract.enabled(env):
        return None
    policy = contract.load_policy(env)
    if not any(policy.authorises(item.Source_ID) for item in items):
        return None
    if client is None:
        budget = Budget(policy.budgets.max_requests, policy.budgets.max_seconds,
                        "external_activity")
        client = HttpClient(run_budget=budget,
                            timeout=policy.budgets.timeout_seconds,
                            max_redirects=config.HTTP_MAX_REDIRECTS)
    else:
        budget = getattr(client, "run_budget", None) or Budget(
            policy.budgets.max_requests, policy.budgets.max_seconds, "external_activity")
    if rows is None:
        from . import store
        rows = evidence_store.load(store.load_organisation_activity_evidence_rows())
    return ExternalActivityEngine(
        items=items, facts=facts, reference=reference, policy=policy, client=client,
        budget=budget, rows=rows, run_id=run_id, now=now, resolver=resolver,
        quote_call=quote_call)


def run_stage(items: list[Item], facts: list[dict], reference: dict, *,
              offline: bool, run_id: str, persist_results: bool = True,
              ) -> ExternalActivityEngine | None:
    """Étape complète du niveau 2, telle que le runner l'exécute.

    Construit le moteur, ou rend ``None`` s'il n'y a rien à faire — auquel cas
    l'appelant passe ``provider=None`` et la chaîne historique reste inchangée,
    octet pour octet. La persistance est séparée pour qu'un run transitoire
    (`--persist=False`) calcule tout sans rien écrire.
    """
    engine = build_engine(items, facts, reference, offline=offline, run_id=run_id)
    if engine is None or not persist_results:
        return engine
    persist(engine)
    save_trace(engine.events)
    return engine


def persist(engine: ExternalActivityEngine | None) -> None:
    """Écrit le référentiel de preuves. Un échec d'écriture n'est jamais fatal."""
    if engine is None:
        return
    from . import store
    try:
        store.save_organisation_activity_evidence_rows(engine.evidence_rows())
    except OSError:
        logger.warning("external_activity_evidence_not_written")


def _trace_path():
    import os
    from pathlib import Path

    raw = os.getenv("EXTERNAL_ACTIVITY_TRACE_PATH", "").strip()
    if raw:
        return Path(raw)
    return Path(__file__).resolve().parents[1] / "data" / "external_activity_trace.json"


def save_trace(events: list[dict]) -> None:
    """Trace du niveau 2, distincte de la télémétrie ``source_facts_ai``."""
    if not events:
        return
    import json

    path = _trace_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(events, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass
