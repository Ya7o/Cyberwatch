"""Phase canonique, offline et idempotente de qualification d'un snapshot."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from . import (config, context_sector, enrichment, identity, incremental, qualification_policy,
               sector as sector_policy, sector_registry, sector_registry_safety, source_llm_fallback, store)
from .dedup import build_incidents_with_registry
from .model import Incident, Item
from .qualification_decision import QualificationDecision, decisions_from_provenance, record_mutations, snapshot_fields, summarize_decisions
from .sector_fallback_migration import restore_legacy_sector_fallbacks

_AUTHORITATIVE_NATIVE_THREAT_SOURCES=frozenset({"VEILLE_LLM"})
_AUTHORITATIVE_DEFAULT_THREATS={"RANSOMWARE_LIVE":config.THREAT_RANSOMWARE}
_SOURCE_SCOPE_THREATS={"FRENCHBREACHES":config.THREAT_LEAK,"BONJOURLAFUITE":config.THREAT_LEAK}
_STRONG_SOURCE_SCOPE_OVERRIDES=frozenset({config.THREAT_RANSOMWARE,config.THREAT_DDOS,config.THREAT_MALWARE,config.THREAT_ACCOUNT,config.THREAT_LEAK,config.THREAT_PHISHING,config.THREAT_THIRD_PARTY})
_SECTOR_FALLBACK_AUTO_APPLY=False
PREQUAL_STATE_CSV=store.DATA_DIR/"prequalification_state.csv"

@dataclass(frozen=True)
class QualificationReport:
    items:list[Item]; incidents:list[Incident]; changes:dict[str,int]; provenance:list[dict[str,str]]; decisions:list[QualificationDecision]; decision_summary:list[dict[str,object]]; incident_id_registry:list[dict[str,str]]; items_hash:str; incidents_hash:str

def stabilize_threats(items):
    changed=0
    for item in items:
        before=item.Threat
        if item.Source_ID in _AUTHORITATIVE_NATIVE_THREAT_SOURCES:
            native=(item.Threat_Raw or "").strip()
            if native in config.THREATS:item.Threat=native
        elif item.Source_ID in _AUTHORITATIVE_DEFAULT_THREATS:item.Threat=_AUTHORITATIVE_DEFAULT_THREATS[item.Source_ID]
        elif item.Source_ID in _SOURCE_SCOPE_THREATS:
            scoped=_SOURCE_SCOPE_THREATS[item.Source_ID]
            if item.Threat not in _STRONG_SOURCE_SCOPE_OVERRIDES:item.Threat=scoped
        if item.Threat!=before:changed+=1
    return changed

def backfill_safe_name_sectors(items):
    changed=0
    for item in items:
        if item.Sector!=config.SECTOR_UNKNOWN:continue
        candidate=sector_policy.classify_sector_name(item.Organisation_Raw)
        if candidate==config.SECTOR_UNKNOWN:continue
        item.Sector=candidate;changed+=1
    return changed

def backfill_structured_source_sectors(items,source_fact_rows=None):
    rows=source_fact_rows if source_fact_rows is not None else store.read_csv(store.SOURCE_FACTS_CSV);raw_by_item=defaultdict(set)
    for row in rows:
        if row.get("Source_ID")=="RANSOMWARE_LIVE":
            raw,item_id=(row.get("Source_Sector_Raw") or "").strip(),(row.get("Item_ID") or "").strip()
            if item_id and raw:raw_by_item[item_id].add(raw)
    changed=0
    for item in items:
        if item.Source_ID!="RANSOMWARE_LIVE" or item.Sector!=config.SECTOR_UNKNOWN:continue
        raw_values=raw_by_item.get(item.Item_ID,set())
        if len(raw_values)!=1:continue
        candidate=sector_policy.classify_source_sector(next(iter(raw_values)))
        if candidate!=config.SECTOR_UNKNOWN:item.Sector=candidate;changed+=1
    return changed

def neutralize_sector_fallback(items,changes,provenance):
    if _SECTOR_FALLBACK_AUTO_APPLY:return 0
    by_id={item.Item_ID:item for item in items if item.Item_ID};neutralized=0
    for row in provenance:
        if row.get("Origin")!="LLM_SOURCE_FALLBACK" or row.get("Field")!="Sector" or row.get("Decision")!="APPLIED":continue
        item=by_id.get(row.get("Item_ID",""));applied=row.get("Final_Value","")
        if item is None or not applied or item.Sector!=applied:continue
        item.Sector=row.get("Previous_Value") or config.SECTOR_UNKNOWN;row["Final_Value"],row["Confidence"],row["Decision"]=item.Sector,"","REJECTED_POLICY_DISABLED";neutralized+=1
    if neutralized:
        changes["llm_sector_fallback"]=max(0,changes.get("llm_sector_fallback",0)-neutralized);changes["llm_sector_rejected"]=changes.get("llm_sector_rejected",0)+neutralized
    changes["llm_sector_policy_rejected"]=neutralized;provenance.sort(key=lambda row:(row["Item_ID"],row["Field"],row["Decision"]));return neutralized

def _observe_layer(decisions,ordered,*,origin,confidence,mutate):
    before=snapshot_fields(ordered);result=mutate();decisions.extend(record_mutations(before,ordered,origin=origin,confidence=confidence));return result

def _capture_prequalification_state(ordered,source_facts,org_cache):
    facts_by_item=defaultdict(list)
    for row in source_facts:
        item_id=(row.get("Item_ID") or "").strip()
        if item_id:facts_by_item[item_id].append(row)
    dependency_digest_value=incremental.qualification_dependency_digest(store.ROOT,reference_rows=store.read_csv(store.ENRICHMENT_REFERENCE_CSV),org_cache_rows=org_cache)
    previous=incremental.fingerprints_from_state(store.read_csv(PREQUAL_STATE_CSV),column="Prequalification_Fingerprint")
    dirty_set=incremental.classify_prequalification_items(ordered,previous,facts_by_item=facts_by_item,policy_version=config.METHOD_ID,dependency_digest_value=dependency_digest_value)
    incremental.write_prequalification_observation(dirty_set,policy_version=config.METHOD_ID,dependency_digest_value=dependency_digest_value)

def qualify(items):
    ordered=identity.sort_items(items);source_facts,org_cache=store.read_csv(store.SOURCE_FACTS_CSV),store.load_org_enrichment_cache();_capture_prequalification_state(ordered,source_facts,org_cache)
    previous_provenance=store.load_qualification_provenance();decisions=[]
    restored=restore_legacy_sector_fallbacks(ordered,previous_provenance);registry_restored=sector_registry.restore_registry_applications(ordered,previous_provenance);reference=enrichment.load_reference()
    changes=_observe_layer(decisions,ordered,origin="MANUAL_REFERENCE",confidence="HIGH",mutate=lambda:enrichment.enrich_items(ordered,reference));changes["llm_sector_restored"],changes["sector_registry_restored"]=restored,registry_restored
    changes.update(_observe_layer(decisions,ordered,origin="OFFLINE_BACKFILL",confidence="MEDIUM",mutate=lambda:enrichment.backfill_unknowns(ordered,reference)))
    changes["sector_safe_name_backfill"]=_observe_layer(decisions,ordered,origin="SAFE_NAME_RULE",confidence="HIGH",mutate=lambda:backfill_safe_name_sectors(ordered))
    changes["sector_structured_source_backfill"]=_observe_layer(decisions,ordered,origin="STRUCTURED_SOURCE",confidence="HIGH",mutate=lambda:backfill_structured_source_sectors(ordered,source_facts))
    context_applied,context_provenance,context_conflicts=context_sector.resolve_contextual_sectors(ordered,source_facts,org_cache);decisions.extend(decisions_from_provenance(context_provenance));changes["sector_context_applied"],changes["sector_context_conflicts"]=context_applied,context_conflicts
    changes["threat_stabilized"]=_observe_layer(decisions,ordered,origin="THREAT_STABILIZATION",confidence="HIGH",mutate=lambda:stabilize_threats(ordered))
    registry_rows=sector_registry.build_registry(ordered,reference,source_fact_rows=source_facts,org_cache_rows=org_cache,previous_provenance=previous_provenance);sector_registry_safety.enforce_candidate_conflicts(registry_rows)
    registry_applied,registry_provenance,registry_known_conflicts=sector_registry.apply_registry(ordered,registry_rows);decisions.extend(decisions_from_provenance(registry_provenance));changes["sector_registry_applied"],changes["sector_registry_known_conflicts"]=registry_applied,registry_known_conflicts
    changes["sector_registry_auto_orgs"]=sum(row.get("Decision")==sector_registry.DECISION_AUTO for row in registry_rows);changes["sector_registry_review_orgs"]=sum(row.get("Decision")==sector_registry.DECISION_REVIEW for row in registry_rows);changes["sector_registry_conflict_orgs"]=sum(row.get("Decision")==sector_registry.DECISION_CONFLICT for row in registry_rows)
    llm_changes,llm_provenance=source_llm_fallback.apply_source_llm_fallback(ordered);changes.update(llm_changes);neutralize_sector_fallback(ordered,changes,llm_provenance);decisions.extend(decisions_from_provenance(llm_provenance))
    decisions=qualification_policy.reconcile(ordered,decisions);provenance=[decision.to_row() for decision in decisions]
    incidents,incident_id_registry=build_incidents_with_registry(ordered,store.load_incident_id_registry())
    return QualificationReport(ordered,incidents,changes,provenance,decisions,summarize_decisions(decisions),incident_id_registry,identity.items_hash(ordered),identity.incidents_hash(incidents))
