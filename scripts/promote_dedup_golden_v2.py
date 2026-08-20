#!/usr/bin/env python3
"""Build a larger, evidence-backed dedup Golden V2 corpus."""
from __future__ import annotations
import argparse, csv, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from cyberwatch import store
from cyberwatch.dedup_golden_refs import LEFT_STABLE_REF_COLUMNS, RIGHT_STABLE_REF_COLUMNS, enrich_golden_row
GOLDEN_V2="DEDUP-GOLDEN-2"; REVIEWED_AT="2026-08-20"; DEFAULT_TARGET=150
SUPPORTED_SOURCE_PAIRS={frozenset(("BONJOURLAFUITE","CYBERATTAQUE_ORG")),frozenset(("RANSOMWARE_LIVE","CYBERATTAQUE_ORG")),frozenset(("FRENCHBREACHES","CYBERATTAQUE_ORG")),frozenset(("VEILLE_LLM","CYBERATTAQUE_ORG")),frozenset(("BONJOURLAFUITE","FRENCHBREACHES"))}
RECURRENCE_RE=re.compile(r"\b(nouvelle?|nouveau|encore|again|second(?:e)?|[2-9](?:e|eme|ème)|a nouveau|à nouveau|une nouvelle fois|frappe une nouvelle fois|frappé une nouvelle fois)\b",re.I)
MANUAL_POSITIVE_OVERRIDES={frozenset(("ITM-5299e7c10746fa62","ITM-c5d6e68764f9a13e")):"WiziShop / DropIZI : même date, même victime et même fuite de factures décrite par Cyberattaque.org et FrenchBreaches."}
BASE_COLUMNS=["Case_ID","Left_Item_ID","Right_Item_ID",*LEFT_STABLE_REF_COLUMNS,*RIGHT_STABLE_REF_COLUMNS,"Same_Organisation_REF","Same_Incident_REF","Evidence","Reviewed_At","Golden_Version"]
REVIEW_COLUMNS=["Review_ID","Left_Item_ID","Right_Item_ID","Verdict","Evidence_Tier","Evidence","Reviewed_At"]
def _read(path):
    with Path(path).open(encoding="utf-8",newline="") as h:return list(csv.DictReader(h))
def _pair(r):return frozenset((r["Left_Item_ID"],r["Right_Item_ID"]))
def _same_identity(r):
    lk=(r.get("Left_Organisation_Key")or"").strip();rk=(r.get("Right_Organisation_Key")or"").strip()
    if lk and lk==rk:return True
    lc=(r.get("Left_Company_ID")or"").strip();rc=(r.get("Right_Company_ID")or"").strip();return bool(lc and lc==rc)
def _eligible_auto_positive(r):
    if r.get("Risk_Type")!="POSSIBLE_FALSE_MERGE":return False,""
    ls=(r.get("Left_Source_ID")or"").strip();rs=(r.get("Right_Source_ID")or"").strip()
    if not ls or not rs or ls==rs or frozenset((ls,rs)) not in SUPPORTED_SOURCE_PAIRS:return False,""
    try:days=int((r.get("Days_Apart")or"999").strip())
    except ValueError:return False,""
    if days>1 or not _same_identity(r) or RECURRENCE_RE.search(f"{r.get('Left_Title','')} {r.get('Right_Title','')}"):return False,""
    same_url=bool(r.get("Left_URL") and r.get("Left_URL")==r.get("Right_URL"));same_company=bool(r.get("Left_Company_ID") and r.get("Left_Company_ID")==r.get("Right_Company_ID"))
    if same_url:tier="EXACT_SHARED_URL"
    elif "RANSOMWARE_LIVE" in (ls,rs):tier="RANSOMWARE_EDITORIAL_CORROBORATION"
    elif "FRENCHBREACHES" in (ls,rs):tier="BREACH_EDITORIAL_CORROBORATION"
    elif "VEILLE_LLM" in (ls,rs):tier="REGIONAL_EDITORIAL_CORROBORATION"
    elif same_company:tier="COMPANY_ID_CROSS_SOURCE"
    else:tier="CANONICAL_IDENTITY_CROSS_SOURCE"
    return True,tier
def _evidence(r,tier):return f"Revue V2 [{tier}] : {r.get('Left_Source_ID','')}/{r.get('Right_Source_ID','')}, même identité organisationnelle, écart {r.get('Days_Apart','')} jour(s). Titres: {(r.get('Left_Title')or'').strip()} | {(r.get('Right_Title')or'').strip()}"
def _sort(r):
    days=int(r.get("Days_Apart") or 999);same=int(bool(r.get("Left_Company_ID")) and r.get("Left_Company_ID")==r.get("Right_Company_ID"));return(days,-same,r.get("Left_Source_ID",""),r.get("Right_Source_ID",""),min(r.get("Left_Item_ID",""),r.get("Right_Item_ID","")),max(r.get("Left_Item_ID",""),r.get("Right_Item_ID","")))
def build(golden_path,audit_path,review_output,target_cases,refresh=False):
    rows=_read(golden_path)
    if not refresh and len(rows)>=target_cases and rows and all(r.get("Golden_Version")==GOLDEN_V2 for r in rows) and Path(review_output).exists():return len(rows),len(_read(review_output))
    base=[r for r in rows if not r.get("Case_ID","").startswith("V2P")]
    audit=_read(audit_path);existing={_pair(r) for r in base};selected=[];by_pair={_pair(r):r for r in audit}
    for pair,evidence in MANUAL_POSITIVE_OVERRIDES.items():
        if pair in existing:continue
        r=by_pair.get(pair)
        if r is None:raise RuntimeError(f"manual review pair missing: {sorted(pair)}")
        selected.append((r,"MANUAL_MISSED_DUPLICATE_REVIEW",evidence));existing.add(pair)
    eligible=[]
    for r in audit:
        if _pair(r) in existing:continue
        ok,tier=_eligible_auto_positive(r)
        if ok:eligible.append((r,tier))
    eligible.sort(key=lambda x:_sort(x[0]));need=max(0,target_cases-len(base)-len(selected))
    if len(eligible)<need:raise RuntimeError(f"not enough evidence-backed candidates: need={need}, eligible={len(eligible)}")
    selected += [(r,t,_evidence(r,t)) for r,t in eligible[:need]]
    by_id={i.Item_ID:i for i in store.load_items()};out=[]
    for r in base:
        m=dict(r);m["Golden_Version"]=GOLDEN_V2;out.append(enrich_golden_row(m,by_id))
    reviews=[]
    for n,(c,t,e) in enumerate(selected,1):
        r={"Case_ID":f"V2P{n:03d}","Left_Item_ID":c["Left_Item_ID"],"Right_Item_ID":c["Right_Item_ID"],"Same_Organisation_REF":"SAME","Same_Incident_REF":"SAME","Evidence":e,"Reviewed_At":REVIEWED_AT,"Golden_Version":GOLDEN_V2};out.append(enrich_golden_row(r,by_id));reviews.append({"Review_ID":r["Case_ID"],"Left_Item_ID":r["Left_Item_ID"],"Right_Item_ID":r["Right_Item_ID"],"Verdict":"SAME_INCIDENT","Evidence_Tier":t,"Evidence":e,"Reviewed_At":REVIEWED_AT})
    if len(out)<target_cases:raise RuntimeError(f"golden size {len(out)} < {target_cases}")
    with Path(golden_path).open("w",encoding="utf-8",newline="") as h:w=csv.DictWriter(h,fieldnames=BASE_COLUMNS,extrasaction="ignore",lineterminator="\n");w.writeheader();w.writerows(out)
    Path(review_output).parent.mkdir(parents=True,exist_ok=True)
    with Path(review_output).open("w",encoding="utf-8",newline="") as h:w=csv.DictWriter(h,fieldnames=REVIEW_COLUMNS,lineterminator="\n");w.writeheader();w.writerows(reviews)
    return len(out),len(reviews)
def main():
    p=argparse.ArgumentParser();p.add_argument("--golden",default=str(ROOT/"data/golden/dedup_golden.csv"));p.add_argument("--audit",default=str(ROOT/"data/dedup_audit_candidates.csv"));p.add_argument("--review-output",default=str(ROOT/"data/golden/dedup_reviewed_v2.csv"));p.add_argument("--target-cases",type=int,default=DEFAULT_TARGET);p.add_argument("--refresh",action="store_true");a=p.parse_args();total,reviewed=build(Path(a.golden),Path(a.audit),Path(a.review_output),a.target_cases,a.refresh);print(f"DEDUP_GOLDEN_V2 total={total} reviewed_v2={reviewed}");return 0
if __name__=="__main__":raise SystemExit(main())
