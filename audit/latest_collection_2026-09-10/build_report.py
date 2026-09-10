"""Freeze audit evidence and render Markdown tables without changing production."""
import csv, hashlib, json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUT=Path(__file__).resolve().parent
RUN='RUN-20260910T072351'
def read(name): return json.loads((ROOT/'data'/f'{name}.json').read_text())
def rows(name): return list(csv.DictReader((ROOT/'data'/f'{name}.csv').open()))
def dump(path,obj): path.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
items=rows('items')
new=[r for r in items if r['Collected_As_Of'].startswith('2026-09-10')]
new_ids={r['Item_ID'] for r in new}
facts={r['Item_ID']:r for r in rows('source_facts')}
probes=json.loads((OUT/'evidence.json').read_text())
snapshot={'snapshot':read('snapshot'),'run':[r for r in rows('run_log') if r['Run_ID']==RUN],
    'source_runs':[r for r in rows('run_sources') if r['Run_ID']==RUN],
    'metrics':[r for r in rows('production_metrics') if r['Run_ID']==RUN],
    'new_items':new,'new_source_facts':[facts[i] for i in sorted(new_ids)],
    'sector_decisions':[r for r in rows('sector_resolution') if r['Item_ID'] in new_ids and r['Run_ID']==RUN],
    'llm_usage':read('llm_usage'),'extraction_usage':read('source_facts_ai_usage'),
    'extraction_trace':read('source_facts_ai_trace'),'dedup':read('dedup_review_latest'),
    'deferred_entries':read('source_facts_retry_queue')}
dump(OUT/'run_snapshot.json',snapshot)
tracked=[ROOT/'data'/n for n in ['snapshot.json','items.csv','incidents.csv','source_facts.csv','source_facts_ai_cache.json','source_facts_ai_trace.json','llm_usage.json','source_facts_ai_usage.json','dedup_review_latest.json','source_facts_retry_queue.json']]
tracked += [ROOT/'assets/data'/n for n in ['incidents.json','facts.json']]
dump(OUT/'input_hashes.json',{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked})

field_map={'summary':'Summary','impact':'Impact','third_party':'Third_Party','evolution':'Evolution','attack_flow':'Attack_Flow_JSON'}
cache_rows=[]
for item in probes['cached_reobserved']:
    fact=facts[item['item_id']]
    for entry in item['cache']:
        for field,record in entry['fields'].items():
            if record['status']!='accepted': continue
            raw=record['value']
            values=raw if isinstance(raw,list) else [raw]
            value=' ; '.join(str(v.get('value',v.get('action',''))) for v in values)
            evidence=' ; '.join(v.get('evidence','') for v in values)
            confidence=' ; '.join(str(v.get('confidence','')) for v in values)
            if field=='affected_datasets':
                canonical=' ; '.join(v.get('value','') for v in json.loads(fact['Source_Metadata_JSON']).get('rich_facts',{}).get('affected_datasets',[]))
            else: canonical=fact.get(field_map.get(field,''),'')
            cache_rows.append({'organisation':item['organisation'],'source':item['source'],'item_id':item['item_id'],'field':field,'effective_model':entry.get('effective_model',''),'status':record['status'],'llm_value':value,'self_confidence':confidence,'evidence':evidence,'canonical_source_facts':canonical})
dump(OUT/'llm_cache_extractions.json',cache_rows)
def cell(s): return str(s or '∅').replace('|','\\|').replace('\n',' ')
cache_table='| Article relu | Champ | Valeur LLM en cache | Confiance déclarée | Valeur actuelle dans SourceFacts |\n|---|---|---|---|---|\n'
for r in cache_rows:
    cache_table+='| '+' | '.join(cell(v) for v in [r['organisation']+' / '+r['source'],r['field'],r['llm_value'],r['self_confidence'],r['canonical_source_facts']])+' |\n'

report='''**Audit de la dernière collecte — RUN-20260910T072351**

Collecte locale du 10 septembre 2026 à 07:23:51 UTC+4, fenêtre du 9 au 10 septembre. Code déclaré : `5d5fda27bf04c5b07fdccd579c1c2b9e80fc5a4d`. Audit de l'état local et des artefacts générés ; déploiement distant non vérifié. Le corpus comportait déjà des changements non commités à l'ouverture de l'audit.

**Verdict : la chaîne ne fonctionne pas correctement de bout en bout sur les nouveautés.** Deux sources décrivent la même cyberattaque contre la mairie du Tampon, mais produisent deux incidents distincts et deux menaces spécifiques non étayées. Un vecteur d'accès hypothétique devient même « confirmé ». Les deux localisations sont correctes. L'extraction et la déduplication LLM sont désactivées (`API_KEY_MISSING`).

Le périmètre principal contient exclusivement les deux nouveaux items. Les quatre articles Citadium/Printemps sont mentionnés uniquement parce que leurs extractions en cache ont été réutilisées dans ce run. Tarnos intervient exclusivement comme candidat de déduplication contre un nouvel item. Aucun audit général de l'historique n'a été réalisé.

**Ce que la collecte a effectivement traité**

| Indicateur du run | Valeur | Interprétation |
|---|---:|---|
| Articles repérés dans la fenêtre | 7 | 3 FrenchBreaches + 4 Cyberattaque.org |
| Observations retenues | 6 | 2 nouvelles + 4 déjà présentes ; 1 article sans victime rejeté |
| Nouveaux incidents enregistrés | 2 | Les deux nouvelles fiches du Tampon |
| Appels LLM / tokens / coût | 0 / 0 / 0 $ | Pas d'extraction nouvelle et pas de décision LLM |
| Événements d'extraction désactivée | 8 | Deux passes pour chacun des 4 articles partiellement ou non couverts par le cache |
| Valeurs acceptées réutilisées depuis le cache | 17 | Sur les 4 articles Citadium/Printemps ; aucune sur les 2 nouveaux items |
| Abstentions réutilisées depuis le cache | 40 | Ne représentent pas 40 faits extraits |
| Candidats de déduplication du run | 2 | 0 examiné par le LLM |
| File de qualification avant → après | 2 → 4 | Les 2 nouveaux articles ont été conservés pour une reprise |

`items_eligible=12` compte les passages d'extraction (6 articles × 2 contrats), pas douze articles distincts. Les compteurs de déduplication et d'inconnus portant sur l'ensemble du corpus ne sont pas des scores de qualité des deux nouveautés. Le run est marqué `OK` et `Published=true` malgré la désactivation ; cela constate une exécution et des artefacts locaux, pas une validation sémantique ni un déploiement distant démontré. VEILLE_LLM est `PARTIAL` pour ancienneté du snapshot (8 jours) et n'apporte aucun item dans cette fenêtre.

**Tableau extraction → décision des deux nouveaux items**

| Étape / champ | FrenchBreaches — Ville du Tampon | Cyberattaque.org — Le Tampon | Verdict |
|---|---|---|---|
| Item | `ITM-0c085da888611a12` | `ITM-f2c9b54af4eae1da` | Deux observations d'un même événement |
| Contenu capturé titre + résumé + corps | 6 526 caractères ; détail HTML HYDRATED | 2 847 caractères ; corps de l'article conservé | Les preuves utiles sont présentes |
| Contrôle d'intégrité | SHA-256 identique à la trace du run | SHA-256 identique à la trace du run | Contextes reconstitués fidèlement depuis la file |
| Extraction LLM nouvelle | Aucune ; 2 passes désactivées, 16 champs différés | Aucune ; 2 passes désactivées, 17 champs différés | Échec d'exécution LLM, aucune réponse à noter |
| Cache LLM de ce nouvel item | Aucune entrée | Aucune entrée | Aucun résultat historique à attribuer au modèle |
| Identité normalisée | `ville du tampon` | `le tampon` | Alias non rapprochés |
| Secteur publié | Inconnu ; `NO_ACTIVITY_EVIDENCE` | Administration / Collectivité ; `ORGANISATION_NAME_RULE` | 1/2 correctement qualifié ; le corps du premier article décrit pourtant la mairie |
| Menace publiée | Fuite de données ; statut unknown, `THREAT_SINGLE_LEGACY_VALUE` | Ransomware ; statut reported, `THREAT_EVIDENCE_RANSOMWARE` | 0/2 menaces spécifiques étayées |
| Localisation publiée | La Réunion | La Réunion | 2/2 correctes ; lieu fin absent |
| Vecteur initial | Vide | `vulnerability_exploitation`, publié confirmed | Erreur grave sur la fiche Cyberattaque.org |
| Impact | Perturbations des services municipaux, avec `**` résiduel | Vide | Fait utile disponible mais extraction hétérogène |
| Résumé | Vide | Reprise du titre | Aucun résumé nouveau issu du LLM |
| Date de l'incident | 09/09/2026, base PUBLICATION | 09/09/2026, base PUBLICATION | Début des perturbations également présent dans les timelines ; date de compromission exacte inconnue |
| Volumes, victimes, CVE, données exposées | Aucune valeur publiée | Aucune valeur publiée | Abstention appropriée ; 82 600 habitants ne devient pas un nombre de victimes |
| Incident final | `INC-AF70EBB0A692` | `INC-F7E0A7E8A73F` | Doublon non fusionné |

L'attendu de l'audit est **une seule fiche « Mairie du Tampon », Administration / Collectivité, La Réunion**, décrivant une cyberattaque avec perturbation des services et **nature technique inconnue**. Ni ransomware, ni fuite, ni exploitation de vulnérabilité ne sont établis par ces textes. Le choix éventuel d'une catégorie générique dans la taxonomie doit conserver cette incertitude. Cette ligne attendue est une conclusion humaine de l'audit, pas une extraction LLM.

**Pourquoi la déduplication échoue**

| Paire proposée | Signal | Décision déterministe reproduite | LLM du run | Décision attendue de l'audit |
|---|---|---|---|---|
| Le Tampon ↔ Ville du Tampon | Similarité 0,7619 ; même jour | `NO_DECISION` : clés d'organisation différentes | DISABLED | Même organisation et même incident : fusion |
| Tarnos ↔ Ville du Tampon | Similarité 0,6923 ; 11 jours d'écart | `NO_DECISION` | DISABLED | Organisations différentes : conserver séparées |

La génération de candidats trouve donc le vrai doublon. L'absence de rapprochement déterministe des noms, puis l'arrêt du filet LLM, expliquent son maintien. Le candidat Tarnos est du bruit de similarité ; aucune fausse fusion n'a été appliquée. Aucun veto de date n'est nécessaire pour expliquer la paire du Tampon : le résolveur s'arrête déjà sur les clés d'organisation différentes.

**Causes vérifiées dans le code et par reproduction hors ligne**

1. `normalize.classify_threat` retourne **Ransomware** pour la phrase « Il serait donc prématuré de parler de ransomware ou de fuite de données. ». Les expressions de négation ne couvrent pas cette incertitude. Ensuite `threat_resolution.resolve_component` considère `item.Threat == Ransomware` comme un signal reported, avec pour preuve un titre qui ne dit pourtant pas ransomware.
2. FrenchBreaches conserve le défaut de flux **Fuite de données**. Le résolveur final n'a ni résumé ni affirmation positive d'exfiltration et reprend `THREAT_SINGLE_LEGACY_VALUE`, sans preuve. L'article dit explicitement qu'aucune fuite n'est confirmée.
3. `_deterministic_initial_access` transforme une phrase pédagogique sur plusieurs vecteurs possibles en **vulnerability_exploitation**, confiance interne **1,0**. L'affirmation « aucun point d'entrée n'a encore été rendu public » ne bloque pas cette variante. La fiche finale hérite ensuite de `confirmed`, alors que la confirmation porte sur la cyberattaque, pas sur ce vecteur.
4. `_safe_institutional_name_sector` reconnaît `ville de` et `ville d`, mais pas `ville du`. Le nom Le Tampon est reconnu par la politique nominative ; Ville du Tampon reste inconnu. La catégorie publique visible dans l'article n'a pas été matérialisée dans `Source_Sector_Raw`.
5. Les deux fiches finales présentent `quality_alerts=[]` et aucun champ rejeté dans les faits publiés, malgré ces erreurs. Les compteurs globaux à zéro sur un corpus de référence ne couvrent pas ce nouveau cas.

Repères de code : `cyberwatch/normalize.py:275`, `cyberwatch/normalize.py:333`, `cyberwatch/threat_resolution.py:150`, `cyberwatch/source_facts_ai.py:473`, `cyberwatch/sector.py:140`, `cyberwatch/dedup.py:138`. Les résultats exacts des fonctions et les objets publiés sont figés dans `evidence.json`.

**Le LLM reçoit-il correctement l'article ?**

Pour ce run, **aucun article n'a été envoyé à l'API**. Il faut distinguer la collecte réussie du transport LLM inexécuté.

La préparation d'extraction assemble titre, résumé et contenu, et le prompt ajoute séparément source, victime et date de publication. Les deux contextes du Tampon ont une empreinte conforme à celle du run. Leur taille reste sous la limite par défaut de 10 000 caractères : avec cette limite, aucune troncature ne serait nécessaire. La journalisation du run désactivé ne fige pas un corps de requête ni les paramètres de troncature effectifs ; ces constats ne constituent donc pas une preuve de requête réseau émise.

Les textes capturés contiennent les négations nécessaires. FrenchBreaches conserve un peu de bruit de bas de page et du Markdown ; Cyberattaque.org contient une section pédagogique qu'il faut distinguer de l'incident. Sur les deux articles nouveaux, le problème prouvé porte surtout sur cette distinction sémantique.

Le **filet LLM de déduplication** utilise une autre entrée, beaucoup plus pauvre : titres, identités, dates, menace déjà classée et quelques SourceFacts. Dans les deux objets reconstruits, `Editorial_Evidence` est vide ; le corps de l'article n'est pas transmis. Les champs Sector et Location ne sont pas inclus directement non plus, et Fine_Location est vide. Réactiver le LLM ne suffit donc pas à lui garantir les preuves géographiques et les réserves présentes dans l'article. Repères : `source_facts_ai_api.py:99`, `source_facts_ai.py:128`, `source_facts_ai.py:943`, `dedup_ai.py:339`.

Pour les seuls articles anciens relus pendant ce run, les contextes FrenchBreaches Citadium et Printemps font 11 624 et 12 043 caractères. Ils incluent un article connexe Shipup. Une nouvelle demande avec la limite par défaut couperait le milieu du texte en gardant le début et la fin. Ce risque est constaté dans les entrées conservées, mais aucun nouvel envoi n'a eu lieu ici.

**Les 17 extractions LLM en cache utilisées dans cette collecte**

Toutes les lignes ci-dessous portent `model=gpt-5-nano` comme modèle demandé/cache et **`effective_model=gpt-4o-mini`** comme modèle ayant produit les valeurs. Elles sont antérieures au run et leur état de cache est `accepted`. La confiance est une déclaration de l'extraction, pas une précision mesurée. `∅` désigne un champ plat vide, pas nécessairement une absence dans tous les faits riches. Les citations justificatives sont conservées intégralement dans `llm_cache_extractions.json`.

'''+cache_table+'''
Une anomalie concrète du cache : l'impact Printemps/Cyberattaque.org dit « des attaques ciblées possibles via des e-mails ou appels frauduleux. », avec 0,7 et statut accepted. C'est un risque futur, interdit par le contrat d'impact. Le SourceFacts actuel a une formulation factuelle après correction éditoriale ; le risque ne figure pas comme impact dans la fiche agrégée. **Le résultat final corrigé ne démontre donc pas que l'extraction LLM brute était correcte.** Les 17 valeurs acceptées restent consultables afin de distinguer ces étages.

**Avis sur la performance du modèle et priorités**

La suffisance du modèle est **non démontrée** sur la dernière collecte : zéro inférence nouvelle, zéro latence LLM mesurée, zéro décision de déduplication. Les valeurs en cache montrent un modèle effectif gpt-4o-mini et au moins une erreur sémantique acceptée ; ce petit échantillon ne permet pas d'estimer sa précision globale ni d'affirmer qu'un autre modèle suffirait.

Le prompt exige déjà des preuves, interdit hypothèses et recommandations, et utilise un JSON Schema strict. Cela sécurise la forme, pas la vérité de chaque valeur : [OpenAI Docs — Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs) documente cette limite. Pour qualifier un modèle, il faut une comparaison sur des entrées et critères métier identiques, avec appréciation humaine des cas limites : [OpenAI Docs — Evaluation best practices](https://developers.openai.com/api/docs/guides/evaluation-best-practices).

Priorités proposées, sans modification de la production dans cet audit :

1. Corriger les menaces non étayées et le vecteur d'accès faussement confirmé, puis rapprocher les deux fiches du Tampon avec preuve et garde-fous.
2. Rétablir l'exécution LLM dans l'environnement de collecte et rendre sa désactivation visible dans le verdict de qualification ; la file de reprise existe déjà.
3. Corriger les règles de négation, le préfixe institutionnel manquant et la propagation du statut confirmed d'un incident vers des champs non confirmés.
4. Donner au dédoublonnage les preuves pertinentes de chaque article, avec localisation et incertitudes ; isoler les articles connexes avant extraction et troncature.
5. Évaluer séparément **réponse brute → validation → SourceFacts → incident publié**, sur les mêmes textes : reconnaissance du secteur et du territoire, abstention sur menace technique et vecteur inconnus, refus du faux nombre de victimes, vraie fusion Tampon et refus de Tarnos. Zéro fausse affirmation critique sur ce cas est un critère local de réception proposé, pas une garantie générale. Une comparaison de modèles reste à exécuter ; aucune supériorité mesurée n'est revendiquée.

**Traçabilité de l'audit**

`run_snapshot.json` fige les traces, métriques et entrées de reprise du run. `evidence.json` contient les reproductions hors ligne, les objets de déduplication reconstruits, le cache pertinent et les deux fiches publiées localement. `llm_cache_extractions.json` contient les 17 valeurs de cache avec citations et décision de matérialisation. Les fichiers `ITM-…-context.txt` conservent les textes exacts reconstitués. `input_hashes.json` identifie les fichiers canoniques inspectés. Les scripts du dossier sont des outils d'audit ; ils ne lancent ni collecte ni appel LLM. Aucun code métier ni donnée canonique n'a été modifié par cet audit.
'''
(OUT/'rapport.md').write_text(report)
assert len(cache_rows)==17
assert len(new)==2
assert all(p['context_hash_matches'] for p in probes['probes'])
assert snapshot['llm_usage']['calls_attempted']==0
print(f'Rapport créé : {len(report)} caractères ; 17 extractions cache ; 2 nouveaux items ; 2 hashes vérifiés.')
