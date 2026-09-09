import json
from pathlib import Path
OUT=Path(__file__).resolve().parent
read=lambda name:json.loads((OUT/name).read_text(encoding='utf-8-sig'))
notes=read('review_notes.json'); runs={n:{r['incident']['id']:r for r in read(n+'_evidence.json')} for n in ['run1','run2']}
assert set(notes)==set(runs['run2']), (set(notes)-set(runs['run2']),set(runs['run2'])-set(notes))
render={n:read(n+'_render.json')['rendered'] for n in runs}
technical=read('technical_checks.json')
esc=lambda s:str(s).replace('|',' / ').replace('\n',' ')
out=['# Audit incident par incident — collectes des 7 et 8 septembre 2026','',
 '73 fiches distinctes, présentes dans au moins un des deux snapshots ; 68 fiches au premier run et 73 au second. Toutes ont été jointes aux observations, faits source, décisions sectorielles, traces disponibles et au HTML produit par le véritable renderer. Les avis distinguent erreurs établies et points à instruire ; une absence de champ n’est pas, seule, la preuve d’une mauvaise extraction.', '',
 'R1 = RUN-20260907T183136, R2 = RUN-20260908T154840 (UTC+4). « Pas de trace » signifie absence de nouvel appel source_facts tracé dans ce run, et non échec ni absence de qualification déterministe. Les appels généraux cyberattaque_semantic ont une télémétrie séparée. Les 73 fiches R2 se trouvent dans [run2_evidence.json](run2_evidence.json), avec toutes leurs preuves par Item_ID ; [run1_evidence.json](run1_evidence.json) conserve l’état R1. Les données canoniques et le code métier n’ont pas été modifiés.', '',
 'Les champs affichés sans badge restent identifiés `unknown` dans ce rapport. Les catégories masquées par le renderer sont explicitement listées. Les citations complètes et statuts par valeur se trouvent dans les JSON de preuve, pour éviter de surcharger chaque fiche.', '',
 '| Incident | Priorité | Secteur R2 | Menace R2 | Territoire R2 |', '|---|---|---|---|---|']
for iid,r in runs['run2'].items():
 i=r['incident'];out.append(f"| [{esc(i['org'])}](#{iid.lower()}) | {notes[iid]['priority']} | {i['sector']} | {i['threat']} | {i['location']} |")
ledger=[]
for iid,r in runs['run2'].items():
 i=r['incident'];note=notes[iid]
 out+=['',f'<a id="{iid.lower()}"></a>',f"## {i['org']} — {iid}",'',f"**{note['priority']} — {note['note']}**",'',
 '| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |','|---|---|---|---|---|---|']
 for n,tag in [('run1','R1'),('run2','R2')]:
  if iid not in runs[n]:out.append(f'| {tag} | Non présent | — | — | — | — |');continue
  rr=runs[n][iid];ii=rr['incident'];out.append(f"| {tag} | {ii['date']} | {ii['sector']} / {ii['sector_status']['status']} | {ii['threat']} / {ii['threat_status']['status']} | {ii['location']} | {ii['items']} |")
 out+=['', '**Chaîne de qualification et déduplication**','']
 for n,tag in [('run1','R1'),('run2','R2')]:
  if iid not in runs[n]:continue
  rr=runs[n][iid]
  statuses=' ; '.join(f"{s['Source_ID']} : {s['Status']} / {s['Reason']} → {s['Resolved_Sector']}" for s in rr['sector_log'])
  out.append(f'- {tag}, secteur : {statuses}.')
  traces=rr['traces']
  out.append(f"- {tag}, extraction : {len(traces)} appel(s) source_facts tracé(s), "+('tous success au niveau appel ; les rejets de champs restent distincts.' if traces else 'faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.'))
  for t in traces:
   out.append(f"  - {t['item_id']}, index {t['index']} : accepté(s) {', '.join((t.get('normalized') or {}).keys()) or 'aucun'} ; rejet(s) {esc('; '.join(k+'='+v for k,v in (t.get('rejections') or {}).items())) or 'aucun' }.")
  pairs=rr.get('dedup_log',[])
  if pairs:
   for p in pairs:out.append(f"- {tag}, dédup `{p['left']} / {p['right']}` ({p['left_org']} / {p['right_org']}) : {p['status']}, organisation {p['same_organisation']}, incident {p['same_incident']}, confiance {p['confidence']}.")
  else:out.append(f'- {tag}, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.')
  for p in rr['pending']:out.append(f"- {tag}, reprise `{p['item_id']}` : {p['reason']}, champs {', '.join(p['fields'])}, tentatives différées {p['attempts']}.")
 out+=['', '**Qualifications du volet R2**','',f"Résumé : {i['summary'] or 'absent' }",'',
 '| Champ | Valeur publiée | Statut conservé | Source |','|---|---|---|---|']
 for field,v in r['detail']['fields'].items():out.append(f"| {field} | {esc(v['value'])} | {v.get('status','unknown')} | {v.get('source','')} |")
 if not r['detail']['fields']:out.append('| — | Aucun scalaire supplémentaire | — | — |')
 for arr,title in [('affected','Volumes'),('data_types','Types de données'),('systems','Systèmes'),('datasets','Périmètres'),('vulnerabilities','Vulnérabilités')]:
  vals=r['detail'].get(arr,[])
  out+=['',title+' : '+('; '.join(f"{v.get('raw') or v.get('value')}"+(f" {v.get('unit','')}" if arr=='affected' and not v.get('raw') else '')+f" [{v.get('status','unknown')}]" for v in vals) if vals else 'aucun élément publié')+'.']
 out+=['',f"Déroulé : {len(r['detail'].get('attack_flow',[]))} étape(s) ; chronologie : {len(r['detail'].get('timeline',[]))} entrée(s).",'',
 'Catégories perdues au rendu : '+(', '.join(render['run2'][iid]['dropped_types']) or 'aucune détectée')+'.','',
 'Alertes du produit : '+(', '.join(a['code'] for a in i['quality_alerts']) or 'aucune')+'.','',
 '**Sources de cette fiche**','']
 for it in r['items']:out.append(f"- `{it['Item_ID']}` — {it['Source_ID']} — [{it['Title']}]({it['URL']}).")
 ledger.append({'incident_id':iid,'org':i['org'],**note,'r1_present':iid in runs['run1'],'r2_sector':i['sector'],'r2_threat':i['threat'],'r2_location':i['location'],'dropped_types':render['run2'][iid]['dropped_types']})
(OUT/'INCIDENTS.md').write_text('\n'.join(out)+'\n')
(OUT/'review_ledger.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n')
print('73 incidents reviewed; appendix and ledger written.')
