#!/usr/bin/env python3
"""Backfill volontaire du registre d'identité organisationnelle (§Lot 12).

Le filet quotidien (`runner.run_daily_dedup_net`) est borné à un seul appel
LLM par MAJ réelle et ne compare que le périmètre collecté aujourd'hui à la
base complète : il ne rattrape pas les doublons résiduels déjà présents dans
tout l'historique. Ce script est l'outil manuel équivalent pour un
rattrapage initial ou ponctuel : il peut challenger tout l'historique en
plusieurs appels, respecte le budget et le cache LLM existants, et ne
persiste jamais que les équivalences organisationnelles validées.

Comme le filet quotidien, ce script ne modifie jamais ITEMS ni INCIDENTS
directement : il propose des lignes de registre d'identité
(`data/organisation_identity_registry.csv`), que le moteur déterministe
(`dedup.build_incidents_with_registry`) consomme ensuite via
`effective_organisation_key`. Un rapport avant/après compare le nombre et le
hash des incidents reconstruits pour objectiver l'effet du backfill.

Usage :

    python scripts/backfill_dedup_identity.py                # dry-run
    python scripts/backfill_dedup_identity.py --apply         # persiste

Ne jamais lancer ce script automatiquement depuis `collect.yml` (§Lot 11) :
c'est une opération volontaire, réservée à un usage manuel ou à un mode de
backfill explicite (`DEDUP_AI_BACKFILL_ENABLED=1`), jamais au run quotidien.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import dedup_ai, duplicate_audit, org_identity, store  # noqa: E402
from cyberwatch.dedup import build_incidents_with_registry  # noqa: E402
from cyberwatch.identity import incidents_hash  # noqa: E402


def _company_ids_from_cache(rows: list[dict]) -> dict[str, str]:
    ids: dict[str, str] = {}
    for row in rows:
        key = (row.get("Organisation_Key") or "").strip()
        company_id = (row.get("Company_ID") or "").strip()
        if key and company_id and row.get("Match_Status") == "MATCHED":
            ids[key] = company_id
    return ids


def _facts_and_websites(rows: list[dict]) -> tuple[dict[str, dict], dict[str, str]]:
    facts_by_item: dict[str, dict] = {}
    victim_websites: dict[str, str] = {}
    for row in rows:
        item_id = (row.get("Item_ID") or "").strip()
        if not item_id:
            continue
        facts_by_item[item_id] = row
        website = (row.get("Victim_Website") or "").strip()
        if website:
            victim_websites[item_id] = website
    return facts_by_item, victim_websites


def run_backfill(
    *,
    items_path: Path,
    source_facts_path: Path,
    org_cache_path: Path,
    registry_path: Path,
    cache_path: Path,
    max_candidates_per_item: int,
    apply: bool,
) -> int:
    items = store.load_items(items_path)
    if not items:
        print("Aucun item : rien à backfiller.")
        return 0

    facts_by_item, victim_websites = _facts_and_websites(store.read_csv(source_facts_path))
    company_ids = _company_ids_from_cache(store.read_csv(org_cache_path))

    print(f"BACKFILL DEDUP IDENTITY — {len(items)} items")
    candidates = duplicate_audit.find_daily_llm_candidates(
        items, items,
        company_ids=company_ids, victim_websites=victim_websites,
        max_candidates_per_item=max_candidates_per_item,
    )
    print(f"  Candidats générés : {len(candidates)}")
    if not candidates:
        print("  Rien à challenger.")
        return 0

    state = dedup_ai.start_run(cache_path)
    if not state.enabled:
        print("  OPENAI_API_KEY absente : impossible de challenger (rien n'est appliqué).")
        return 1
    if not state.daily_enabled:
        # Le backfill est un usage volontaire distinct du filet quotidien :
        # il ignore l'interrupteur quotidien et se pilote uniquement via
        # --apply / le budget LLM existant.
        state.daily_enabled = True

    remaining = list(candidates)
    all_decisions: dict[str, dedup_ai.DedupAiDecision] = {}
    round_number = 0
    while remaining:
        round_number += 1
        decisions = dedup_ai.challenge_candidates_batch(
            remaining, facts_by_item, state, company_ids,
        )
        all_decisions.update(decisions)
        not_reviewed_ids = {
            cid for cid, decision in decisions.items()
            if decision.status == dedup_ai.STATUS_NOT_REVIEWED_CAPACITY
        }
        by_id = {dedup_ai.candidate_id(c): c for c in remaining}
        treated = len(decisions) - len(not_reviewed_ids)
        remaining = [by_id[cid] for cid in not_reviewed_ids if cid in by_id]
        print(f"  Round {round_number} : {treated} traité(s), {len(remaining)} restant(s)")
        if not remaining:
            break
        if state.calls_budget_blocked and not state.batch_calls_succeeded:
            print("  Budget épuisé : arrêt du backfill, reprise possible plus tard (cache conservé).")
            break

    candidates_by_id = {dedup_ai.candidate_id(c): c for c in candidates}
    registry_proposals = []
    for cid, decision in all_decisions.items():
        candidate = candidates_by_id.get(cid)
        if candidate is None:
            continue
        proposal = dedup_ai.validate_ai_dedup_decision(candidate, decision, model=state.model)
        if proposal is not None:
            registry_proposals.append(proposal)

    print(f"  Décisions obtenues : {len(all_decisions)}")
    print(f"  Équivalences organisationnelles validées : {len(registry_proposals)}")
    print(f"  Coût estimé : ${state.estimated_cost_usd:.4f} en {state.batch_calls_attempted} appel(s)")

    existing_rows = store.read_csv(registry_path)
    merged_rows, problems = org_identity.merge_organisation_identity_rows(
        existing_rows, registry_proposals,
    )
    for problem in problems:
        print(f"  ! {problem}")

    before_incidents, _ = build_incidents_with_registry(items, store.load_incident_id_registry())
    before_count, before_hash = len(before_incidents), incidents_hash(before_incidents)
    new_aliases = len(merged_rows) - len(existing_rows)

    if not apply:
        print("  Dry-run (sans --apply) : rien persisté.")
        print(f"  {new_aliases} ligne(s) de registre seraient ajoutée(s)/mises à jour.")
        dedup_ai.save_cache(state)  # le cache LLM n'est jamais une donnée canonique publiée
        return 0

    store.write_csv(registry_path, org_identity.ORGANISATION_IDENTITY_REGISTRY_COLUMNS, merged_rows)
    org_identity.reload_organisation_identity_registry(registry_path)
    dedup_ai.save_cache(state)

    after_incidents, _ = build_incidents_with_registry(items, store.load_incident_id_registry())
    after_count, after_hash = len(after_incidents), incidents_hash(after_incidents)

    print(f"  Registre persisté : {registry_path} ({new_aliases} ligne(s) nouvelle(s))")
    print(f"  Incidents avant   : {before_count} (hash {before_hash[:16]})")
    print(f"  Incidents après   : {after_count} (hash {after_hash[:16]})")
    if before_count != after_count:
        print(f"  -> {before_count - after_count} incident(s) regroupé(s) par les nouvelles équivalences.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--items", type=Path, default=store.ITEMS_CSV)
    parser.add_argument("--source-facts", type=Path, default=store.SOURCE_FACTS_CSV)
    parser.add_argument("--org-cache", type=Path, default=store.ORG_ENRICHMENT_CACHE_CSV)
    parser.add_argument("--registry", type=Path, default=store.ORGANISATION_IDENTITY_REGISTRY_CSV)
    parser.add_argument("--cache", type=Path, default=store.DATA_DIR / "dedup_ai_daily_cache.csv")
    parser.add_argument(
        "--max-candidates-per-item", type=int,
        default=duplicate_audit.DAILY_LLM_MAX_CANDIDATES_PER_ITEM,
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Persiste réellement le registre (sinon dry-run, rien n'est écrit).",
    )
    args = parser.parse_args(argv)
    return run_backfill(
        items_path=args.items,
        source_facts_path=args.source_facts,
        org_cache_path=args.org_cache,
        registry_path=args.registry,
        cache_path=args.cache,
        max_candidates_per_item=args.max_candidates_per_item,
        apply=args.apply,
    )


if __name__ == "__main__":
    sys.exit(main())
