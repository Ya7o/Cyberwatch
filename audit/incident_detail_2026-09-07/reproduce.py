"""Audit hors réseau ; écrit uniquement dans ce dossier d'audit."""
from __future__ import annotations
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cyberwatch import fact_resolution as fr, site, store, data_sensitivity

OUT = Path(__file__).resolve().parent
facts = json.loads((ROOT / 'assets/data/facts.json').read_text())
incidents = json.loads((ROOT / 'assets/data/incidents.json').read_text())
raw = site._source_facts_by_incident(store.load_items(), store.load_source_facts())
orgs = {i['id']: i['org'] for i in incidents}
counts = Counter()
examples = {}
for iid, detail in facts.items():
    for field, record in detail.get('fields', {}).items():
        counts['field:' + field] += 1
        counts['scalar_total'] += 1
        if record.get('evidence'): counts['scalar_with_evidence'] += 1
        counts['scalar_status:' + record.get('status', 'missing')] += 1
    for collection in ('affected','data_types','systems','datasets','claims','attack_flow','timeline','vulnerabilities'):
        entries = detail.get(collection, [])
        counts['incidents_with:' + collection] += bool(entries)
        counts['entries:' + collection] += len(entries)
        counts['no_status:' + collection] += sum(e.get('status','unknown') == 'unknown' for e in entries)
        counts['with_evidence:' + collection] += sum(bool(e.get('evidence')) for e in entries)
        counts['negative:' + collection] += sum(e.get('status') in {'denied','negated','hypothesis'} for e in entries)
    if orgs.get(iid) in ('Zéro Logement Vacant','Jouvet SAS','Timetonic','Qare','La Maison Des Travaux'):
        examples[orgs[iid]] = {'incident': next(i for i in incidents if i['id']==iid), 'resolved':detail, 'raw':raw.get(iid)}

def resolve(rows):
    return fr.resolve_incident_facts(rows, organisation='Acme')

cases = {}
cases['scalar_status_inheritance'] = resolve([{
    'source':'CYBERATTAQUE_ORG', 'item_id':'a', 'claim_status':'confirmed',
    'threat_actor':'BlackCat', 'threat_actor_evidence':"L'attribution à BlackCat reste une hypothèse non confirmée.",
    'rich_facts': {'claims':[{'type':'actor','value':'BlackCat','status':'hypothesis','evidence':"L'attribution à BlackCat reste une hypothèse non confirmée."}]},
}])
cases['attack_flow_status_inheritance'] = resolve([{
    'source':'CYBERATTAQUE_ORG', 'item_id':'a', 'claim_status':'confirmed',
    'attack_flow':[{'action':'exfiltration de fichiers','evidence':"Aucune exfiltration de fichiers n'a été constatée.",'status':'denied'}],
}])
cases['conflicting_scalar'] = resolve([
    {'source':'RANSOMWARE_LIVE','item_id':'a','claim_status':'claimed','attack_date':'2026-09-01','attack_date_evidence':"Le groupe revendique une attaque le 1 septembre."},
    {'source':'CYBERATTAQUE_ORG','item_id':'b','claim_status':'confirmed','attack_date':'2026-09-04','attack_date_evidence':"Acme confirme que l'attaque a eu lieu le 4 septembre."},
])
cases['denial_only'] = resolve([{
    'source':'CYBERATTAQUE_ORG','item_id':'a','claim_status':'reported',
    'rich_facts':{'claims':[{'type':'data_type','value':'mots de passe','status':'denied','evidence':"Acme confirme qu'aucun mot de passe n'a été exposé."}]},
}])
cases['negative_vulnerable_exposure'] = data_sensitivity.classify({
    'claims':[{'value':"Aucune donnée d'enfant exposée",'status':'denied','evidence':"Acme confirme qu'aucune donnée d'enfant n'a été exposée."}],
    'data_types':[],
})
real_iid = next(i['id'] for i in incidents if i['org'] == 'Zéro Logement Vacant')
cases['real_vector_negation'] = resolve(raw[real_iid])
jouvet_iid = next(i['id'] for i in incidents if i['org'] == 'Jouvet SAS')
cases['real_group_monthly_count'] = fr.resolve_incident_facts(raw[jouvet_iid], organisation='Jouvet SAS')
recomputed = site._resolved_details(incidents, raw)
disagreements = []
for iid, rows in raw.items():
    for field in fr.SCALAR_FIELDS:
        vals = sorted({str(r[field]) for r in rows if r.get(field)})
        if len(vals)>1:
            disagreements.append({'org':orgs.get(iid), 'field':field,'values':vals,'selected':facts.get(iid,{}).get('fields',{}).get(field)})
result = {
    'scope':'local checkout, offline; examples are not a statistical accuracy benchmark',
    'incidents':len(incidents),'facts':len(facts),'source_rows':sum(map(len,raw.values())),
    'metrics':dict(counts),'sector_statuses':dict(Counter(i.get('sector_status',{}).get('status') for i in incidents)),
    'recomputed_detail_differences':[iid for iid in facts if facts[iid] != recomputed.get(iid)],
    'quality_alerts':dict(Counter(a['code'] for i in incidents for a in i.get('quality_alerts',[]))),
    'cases':cases,'scalar_disagreements':disagreements,'examples':examples,
    'hashes':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ['assets/dashboard-v2.js','assets/data/facts.json','assets/data/incidents.json','cyberwatch/fact_resolution.py','cyberwatch/fact_resolution_counts.py']},
}
(OUT/'evidence.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('examples','hashes','scalar_disagreements')},ensure_ascii=False,indent=2))
print('Scalar disagreements:',len(disagreements))
