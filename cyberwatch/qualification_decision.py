"""Instrumentation canonique des décisions de qualification."""
from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass
from .model import Item

QUALIFICATION_FIELDS = ("Sector", "Location", "Threat")
QUALIFICATION_DECISION_COLUMNS = ["Item_ID","Source_ID","Field","Previous_Value","Candidate_Value","Final_Value","Origin","Confidence","Evidence","Match_Strategy","Decision","Rejected_Reason","Winning_Origin","Winning_Value"]
ORIGIN_PRIORITY = {"SOURCE_NATIVE":0,"MANUAL_REFERENCE":10,"STRUCTURED_SOURCE":20,"ORG_CONTEXT_SECTOR":30,"ORG_SECTOR_REGISTRY":40,"SAFE_NAME_RULE":50,"OFFLINE_BACKFILL":60,"THREAT_STABILIZATION":70,"LLM_SOURCE_FALLBACK":90}

@dataclass(frozen=True)
class QualificationDecision:
    item_id: str; source_id: str; field: str; previous_value: str; candidate_value: str; final_value: str; origin: str
    confidence: str = ""; evidence: str = ""; match_strategy: str = ""; decision: str = "APPLIED"
    rejected_reason: str = ""; winning_origin: str = ""; winning_value: str = ""
    @classmethod
    def from_provenance(cls, row):
        return cls(row.get("Item_ID",""),row.get("Source_ID",""),row.get("Field",""),row.get("Previous_Value",""),row.get("Candidate_Value",""),row.get("Final_Value",""),row.get("Origin",""),row.get("Confidence",""),row.get("Evidence",""),row.get("Match_Strategy",""),row.get("Decision",""),row.get("Rejected_Reason",""),row.get("Winning_Origin",""),row.get("Winning_Value",""))
    @classmethod
    def from_row(cls, row): return cls.from_provenance(row)
    def to_row(self):
        return {"Item_ID":self.item_id,"Source_ID":self.source_id,"Field":self.field,"Previous_Value":self.previous_value,"Candidate_Value":self.candidate_value,"Final_Value":self.final_value,"Origin":self.origin,"Confidence":self.confidence,"Evidence":self.evidence,"Match_Strategy":self.match_strategy,"Decision":self.decision,"Rejected_Reason":self.rejected_reason,"Winning_Origin":self.winning_origin,"Winning_Value":self.winning_value}

def snapshot_fields(items):
    return {item.Item_ID:{field:str(getattr(item,field,"") or "") for field in QUALIFICATION_FIELDS} for item in items if item.Item_ID}

def record_mutations(before, items, *, origin, confidence, evidence="", match_strategy=""):
    decisions=[]
    for item in items:
        previous=before.get(item.Item_ID)
        if previous is None: continue
        for field in QUALIFICATION_FIELDS:
            old,new=previous.get(field,""),str(getattr(item,field,"") or "")
            if old != new: decisions.append(QualificationDecision(item.Item_ID,item.Source_ID,field,old,new,new,origin,confidence,evidence,match_strategy,"APPLIED"))
    return sorted(decisions,key=_decision_sort_key)

def decisions_from_provenance(rows): return sorted((QualificationDecision.from_provenance(row) for row in rows),key=_decision_sort_key)
def summarize_decisions(decisions):
    grouped=defaultdict(list)
    for decision in decisions: grouped[(decision.origin,decision.field)].append(decision)
    rows=[]
    for (origin,field),values in sorted(grouped.items()):
        statuses=Counter(value.decision for value in values); confidences=Counter(value.confidence or "UNSPECIFIED" for value in values)
        rows.append({"Origin":origin,"Field":field,"Decisions":len(values),"Applied":statuses.get("APPLIED",0),"Rejected":sum(v for k,v in statuses.items() if k.startswith("REJECTED")),"Protected":statuses.get("PROTECTED",0),"Other":sum(v for k,v in statuses.items() if k not in {"APPLIED","PROTECTED"} and not k.startswith("REJECTED")),"Confidence":dict(sorted(confidences.items()))})
    return rows

def precedence(origin): return ORIGIN_PRIORITY.get(origin,999)
def _decision_sort_key(decision): return (decision.item_id,decision.field,precedence(decision.origin),decision.origin,decision.decision)
