#!/usr/bin/env python3
"""Audit offline déterministe des champs de qualité ITEMS."""
from __future__ import annotations
import argparse, csv, hashlib, json, random, re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from itertools import combinations

from cyberwatch import config, duplicate_audit, org_identity, source_facts as sf
from cyberwatch.dedup import STRONG_KEEP_REASON_CODES, decide_merge
from cyberwatch.enrichment import _UNKNOWN_LEAK_MARKERS
from cyberwatch.normalize import classify_threat, searchable
from cyberwatch.org_identity import DECISION_SAME, effective_organisation_key
from cyberwatch.quality import compare as compare_quality, metrics as quality_metrics
from cyberwatch.model import Item

DEDUP_IDENTITY_CORPUS = ROOT / "tests" / "fixtures" / "dedup_identity_cases.json"

FIELDS = ("Organisation_Raw", "Organisation_Key", "Threat", "Sector", "Location")
UNKNOWN = "Inconnu"

def load(path):
    return list(csv.DictReader(Path(path).open(encoding="utf-8", newline="")))

def load_optional(path):
    """Comme `load`, mais renvoie une liste vide si le fichier est absent —
    `source_facts.csv` peut ne pas encore exister sur un dépôt non initialisé."""
    p = Path(path)
    return load(p) if p.exists() else []

def key(row):
    return (row["Source_ID"], row["Source_Item_ID"]) if row.get("Source_Item_ID") else (row["Source_ID"], row["URL"], row["Published_Date"])

def summary(rows):
    sources=defaultdict(list)
    for row in rows: sources[row["Source_ID"]].append(row)
    def stats(values):
        return {"items":len(values), "threat_unknown":sum(r["Threat"]==UNKNOWN for r in values), "sector_unknown":sum(r["Sector"]==UNKNOWN for r in values), "location_unknown":sum(r["Location"]==UNKNOWN for r in values), "organisation_empty":sum(not r["Organisation_Raw"] for r in values)}
    aggregate = re.compile(r"\b\d+\s+(?:sdis|agences?|écoles?|ecoles?|hôpitaux?|hopitaux?)\b", re.I)
    return {"global":stats(rows), "sources":{s:stats(v) for s,v in sorted(sources.items())}, "threat":dict(sorted(Counter(r["Threat"] for r in rows).items())), "sector":dict(sorted(Counter(r["Sector"] for r in rows).items())), "location":dict(sorted(Counter(r["Location"] for r in rows).items())), "aggregates":sorted({r["Organisation_Raw"] for r in rows if any(x in r["Organisation_Raw"].lower() for x in ("&", "/", " et ")) or aggregate.search(r["Organisation_Raw"] or "")})}

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def diff(before, after):
    old={key(r):r for r in before}; new={key(r):r for r in after}; changes=[]
    added=[]
    removed=[]
    for value in sorted(set(new) - set(old)):
        row = new[value]
        added.append({"key": value, "status": "ADDED", "source": row["Source_ID"], "source_item_id": row["Source_Item_ID"], "published": row["Published_Date"], "organisation": row["Organisation_Raw"], "title": row["Title"]})
    for value in sorted(set(old) - set(new)):
        row = old[value]
        removed.append({"key": value, "status": "REMOVED", "reason": "UNEXPLAINED", "source": row["Source_ID"], "source_item_id": row["Source_Item_ID"], "published": row["Published_Date"], "organisation": row["Organisation_Raw"], "title": row["Title"]})
    for k in sorted(set(old)&set(new)):
        for field in FIELDS:
            if old[k][field]!=new[k][field]: changes.append({"key":k,"source":old[k]["Source_ID"],"source_item_id":old[k]["Source_Item_ID"],"published":old[k]["Published_Date"],"organisation":old[k]["Organisation_Raw"],"title":old[k]["Title"],"field":field,"before":old[k][field],"after":new[k][field]})
    return changes, added, removed


def run_audit(rows, before_rows=None):
    """Return the complete, order-independent audit payload."""
    result = summary(rows)
    if before_rows is not None:
        changes, added, removed = diff(before_rows, rows)
        result["changes"] = changes
        result["added"] = added
        result["removed"] = removed
        result["added_rows"] = len(added)
        result["removed_rows"] = len(removed)
        result["changed_rows"] = len({tuple(change["key"]) for change in changes})
        for field in FIELDS:
            result[f"changed_{field.lower()}"] = sum(change["field"] == field for change in changes)
    return result


def threat_backfill_candidates(rows):
    """Observe the existing unknown-threat backfill without writing data."""
    candidates = []
    for row in rows:
        if row.get("Threat") != UNKNOWN:
            continue
        direct = classify_threat(row.get("Title", ""), row.get("Threat_Raw", ""))
        candidate = direct
        reason = "classify_threat"
        if candidate == config.THREAT_UNKNOWN:
            markers = [marker for marker in _UNKNOWN_LEAK_MARKERS if marker in searchable(row.get("Title", ""))]
            if markers:
                candidate = config.THREAT_LEAK
                reason = "title_markers=" + ",".join(markers)
        if candidate != config.THREAT_UNKNOWN:
            candidates.append({
                "source_id": row.get("Source_ID", ""),
                "source_item_id": row.get("Source_Item_ID", ""),
                "organisation": row.get("Organisation_Raw", ""),
                "title": row.get("Title", ""),
                "threat_before": row.get("Threat", ""),
                "threat_candidate": candidate,
                "reason": reason,
            })
    return sorted(candidates, key=lambda value: (value["source_id"], value["source_item_id"], value["title"]))


def actor_sentinel_candidates(source_fact_rows):
    """§stabilisation pré-release : lignes de `source_facts.csv` dont
    `Threat_Actor` est un mot générique (jamais un nom d'acteur réel, cf.
    `source_facts._ACTOR_SENTINELS`). Bloquant (--check-regression) :
    contrairement au taux d'Inconnu, c'est une valeur fausse publiable, pas
    un manque de complétude."""
    candidates = []
    for row in source_fact_rows:
        actor = row.get("Threat_Actor", "")
        if actor and searchable(actor) in sf._ACTOR_SENTINELS:
            candidates.append({
                "item_id": row.get("Item_ID", ""),
                "source_id": row.get("Source_ID", ""),
                "threat_actor": actor,
            })
    return sorted(candidates, key=lambda value: (value["source_id"], value["item_id"]))


def duplicate_high_confidence_candidates(items):
    """§stabilisation pré-release : sous-ensemble « haute confiance »
    (concaténation/permutation EXACTES, `duplicate_audit.
    HIGH_CONFIDENCE_REASON_CODES`) des candidats de `cyberwatch.
    duplicate_audit` — jamais l'inclusion de mots, volontairement non
    bloquante (trop de faux positifs institutionnels légitimes)."""
    candidates = duplicate_audit.find_duplicate_candidates(items)
    high_confidence = [
        candidate for candidate in candidates
        if candidate.reason_code in duplicate_audit.HIGH_CONFIDENCE_REASON_CODES
    ]
    return sorted(
        (
            {
                "reason_code": candidate.reason_code,
                "short": candidate.short.Organisation_Raw,
                "long": candidate.long.Organisation_Raw,
                "short_source": candidate.short.Source_ID,
                "long_source": candidate.long.Source_ID,
                "days_apart": candidate.days_apart,
            }
            for candidate in high_confidence
        ),
        key=lambda value: (value["short"], value["long"], value["short_source"], value["long_source"]),
    )


def organisation_identity_registry_problems(rows):
    """§Lot 16 : collision, cycle, alias sans canonical — cf. `org_identity.
    validate_organisation_identity_registry`, seule source de vérité pour
    ces contrôles structurels (pas de logique dupliquée ici)."""
    return org_identity.validate_organisation_identity_registry(rows)


def registry_veto_bypass_candidates(items, registry_rows):
    """§Lot 16 : aucune équivalence du registre ne doit réunir deux items que
    `dedup.decide_merge` rejette encore par un veto fort (récurrence, Event_Date
    conflictuel, Source_Item_ID conflictuel). Ce n'est théoriquement pas
    possible (`dedup_ai.validate_ai_dedup_decision` vérifie déjà ce veto avant
    d'écrire une proposition), donc un candidat ici est un signal de
    régression réelle, pas un simple avertissement."""
    registry_targets = {
        row.get("Canonical_Key", "") for row in registry_rows
        if row.get("Decision") == DECISION_SAME
    }
    if not registry_targets:
        return []

    by_key = defaultdict(list)
    for item in items:
        key = effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
        if key in registry_targets:
            by_key[key].append(item)

    candidates = []
    for key, group in by_key.items():
        if len(group) < 2:
            continue
        for left, right in combinations(sorted(group, key=lambda i: i.Item_ID), 2):
            decision = decide_merge(left, right)
            if decision.reason_code in STRONG_KEEP_REASON_CODES:
                candidates.append({
                    "organisation_key": key,
                    "left_item_id": left.Item_ID,
                    "right_item_id": right.Item_ID,
                    "veto_reason_code": decision.reason_code,
                })
    return sorted(candidates, key=lambda value: (value["organisation_key"], value["left_item_id"], value["right_item_id"]))


def dedup_identity_corpus_benchmark(corpus_path=DEDUP_IDENTITY_CORPUS):
    """§Lot 0/16 : known_duplicate_recall / known_nonduplicate_false_merge_count
    sur le corpus de régression, offline (cf. `duplicate_audit.
    dedup_identity_benchmark`)."""
    path = Path(corpus_path)
    if not path.exists():
        return {"available": False}
    cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
    return {"available": True, **duplicate_audit.dedup_identity_benchmark(cases)}


def main():
    p=argparse.ArgumentParser();p.add_argument('--items');p.add_argument('--before');p.add_argument('--after');p.add_argument('--check',action='store_true');p.add_argument('--metrics', action='store_true');p.add_argument('--quality-baseline', default=str(ROOT / 'data' / 'quality_baseline.json'));p.add_argument('--check-regression', action='store_true');p.add_argument('--source-facts', default=str(ROOT / 'data' / 'source_facts.csv'));p.add_argument('--organisation-identity-registry', default=str(ROOT / 'data' / 'organisation_identity_registry.csv'));p.add_argument('--dedup-identity-corpus', default=str(DEDUP_IDENTITY_CORPUS));a=p.parse_args()
    if bool(a.before) != bool(a.after):
        p.error("--before et --after doivent être fournis ensemble")
    rows=load(a.items or a.after)
    before_rows = load(a.before) if a.before else None
    source_fact_rows = load_optional(a.source_facts)
    registry_rows = load_optional(a.organisation_identity_registry)
    items = [Item.from_row(row) for row in rows]
    result=run_audit(rows, before_rows)
    result["threat_backfill_candidates"] = threat_backfill_candidates(rows)
    result["threat_backfill_candidates_total"] = len(result["threat_backfill_candidates"])
    result["actor_sentinel_candidates"] = actor_sentinel_candidates(source_fact_rows)
    result["actor_sentinel_candidates_total"] = len(result["actor_sentinel_candidates"])
    result["duplicate_high_confidence_candidates"] = duplicate_high_confidence_candidates(items)
    result["duplicate_high_confidence_candidates_total"] = len(result["duplicate_high_confidence_candidates"])
    # §Lot 16 : gates spécifiques au filet de déduplication LLM — registre
    # d'identité (collision/cycle), aucune fusion contournant un veto fort,
    # et le corpus de régression §Lot 0 (offline, 0 faux merge attendu).
    result["organisation_identity_registry_problems"] = organisation_identity_registry_problems(registry_rows)
    result["organisation_identity_registry_problems_total"] = len(result["organisation_identity_registry_problems"])
    result["registry_veto_bypass_candidates"] = registry_veto_bypass_candidates(items, registry_rows)
    result["registry_veto_bypass_candidates_total"] = len(result["registry_veto_bypass_candidates"])
    result["dedup_identity_corpus_benchmark"] = dedup_identity_corpus_benchmark(a.dedup_identity_corpus)
    result["quality_metrics"] = quality_metrics(items)
    blob=canonical(result); digest=hashlib.sha256(blob.encode()).hexdigest(); print(blob); print('audit_hash='+digest)
    if a.metrics:
        for name, value in result["global"].items():
            print(f"{name}={value}")
        for name in ("added_rows", "removed_rows", "changed_rows") + tuple(f"changed_{field.lower()}" for field in FIELDS):
            if name in result:
                print(f"{name}={result[name]}")
    if a.check:
        shuffled=list(rows); random.Random(42).shuffle(shuffled)
        shuffled_facts=list(source_fact_rows); random.Random(43).shuffle(shuffled_facts)
        shuffled_registry=list(registry_rows); random.Random(44).shuffle(shuffled_registry)
        shuffled_items=[Item.from_row(row) for row in shuffled]
        shuffled_result = run_audit(shuffled, before_rows)
        shuffled_result["threat_backfill_candidates"] = threat_backfill_candidates(shuffled)
        shuffled_result["threat_backfill_candidates_total"] = len(shuffled_result["threat_backfill_candidates"])
        shuffled_result["actor_sentinel_candidates"] = actor_sentinel_candidates(shuffled_facts)
        shuffled_result["actor_sentinel_candidates_total"] = len(shuffled_result["actor_sentinel_candidates"])
        shuffled_result["duplicate_high_confidence_candidates"] = duplicate_high_confidence_candidates(shuffled_items)
        shuffled_result["duplicate_high_confidence_candidates_total"] = len(shuffled_result["duplicate_high_confidence_candidates"])
        shuffled_result["organisation_identity_registry_problems"] = organisation_identity_registry_problems(shuffled_registry)
        shuffled_result["organisation_identity_registry_problems_total"] = len(shuffled_result["organisation_identity_registry_problems"])
        shuffled_result["registry_veto_bypass_candidates"] = registry_veto_bypass_candidates(shuffled_items, shuffled_registry)
        shuffled_result["registry_veto_bypass_candidates_total"] = len(shuffled_result["registry_veto_bypass_candidates"])
        shuffled_result["dedup_identity_corpus_benchmark"] = dedup_identity_corpus_benchmark(a.dedup_identity_corpus)
        shuffled_result["quality_metrics"] = quality_metrics(shuffled_items)
        if canonical(shuffled_result)!=canonical(result): raise SystemExit('audit non déterministe')
        print('check=PASS')
    if a.check_regression:
        baseline_path = Path(a.quality_baseline)
        if not baseline_path.exists():
            raise SystemExit('quality baseline missing: ' + str(baseline_path))
        baseline = json.loads(baseline_path.read_text(encoding='utf-8'))
        problems = compare_quality(result['quality_metrics'], baseline['metrics'])
        if result['threat_backfill_candidates_total']:
            problems.append('deterministic threat candidates still unknown')
        if result['actor_sentinel_candidates_total']:
            problems.append('acteurs sentinelles génériques détectés dans source_facts.csv')
        if result['duplicate_high_confidence_candidates_total']:
            problems.append('doublons haute confiance (concaténation/permutation) non résolus')
        if before_rows is not None and any(row['reason'] == 'UNEXPLAINED' for row in result['removed']):
            problems.append('unexplained removed rows')
        # §Lot 16 : gates du filet de déduplication LLM.
        if result['organisation_identity_registry_problems_total']:
            problems.append('registre identité organisation invalide (collision/cycle/alias sans canonical)')
        if result['registry_veto_bypass_candidates_total']:
            problems.append('équivalence de registre contournant un veto fort déterministe')
        benchmark = result['dedup_identity_corpus_benchmark']
        if benchmark.get('available') and benchmark.get('known_nonduplicate_false_merge_count'):
            problems.append('faux merge détecté sur le corpus de régression dedup (tests/fixtures/dedup_identity_cases.json)')
        if problems:
            print('quality=FAIL')
            raise SystemExit('\n'.join(problems))
        print('quality=PASS')
if __name__=='__main__': main()
