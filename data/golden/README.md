# Golden set de qualification

Ce dossier contient la référence manuelle réutilisable destinée à challenger la qualité de qualification de Cyberwatch. Il ne mesure pas la couverture de collecte : chaque cas doit provenir d'un incident et de sources déjà exploités par Cyberwatch.

## Principe

La référence doit être construite en aveugle à partir de `Incident_ID`, `Date`, `Organisation`, `Organisation_Key`, `Sources` et `Source_URLs`. Les valeurs Cyberwatch `Secteur`, `Menace` et `Localisation` ne doivent pas être consultées pendant la qualification de référence.

Les labels `*_REF` utilisent strictement les listes de `cyberwatch/config.py`. Une valeur connue doit être accompagnée d'une preuve courte et vérifiable. En cas d'ambiguïté réelle, `Inconnu` est préférable à une qualification forcée.

Le golden set est l'arbitre. Les exports LLM expérimentaux ne doivent jamais être recopiés dans `qualification_golden.csv` sans revue indépendante.

## Golden v2 : revue contradictoire et traçabilité

`qualification_golden.csv` reste le snapshot de référence initial. Les corrections issues d'une contre-enquête sont enregistrées de façon append-only dans `qualification_golden_audit.csv`. Les scripts d'évaluation appliquent automatiquement ce journal pour construire la vue effective du golden ; aucune correction du juge n'est donc confondue avec une amélioration de Cyberwatch.

Décisions autorisées :

- `CONFIRMED` : la valeur a été revérifiée et reste inchangée ;
- `CORRECTED` : une valeur est corrigée avec ancienne valeur, nouvelle valeur, preuve et motif ;
- `REVIEW` : le cas reste litigieux et est exclu de la vue effective et des scores tant que l'arbitrage n'est pas clos ;
- `DUPLICATE` : le cas est un doublon d'un autre `Golden_ID` canonique et est retiré de la vue effective.

Une correction `CORRECTED` fait passer uniquement le cas concerné à `Golden_Version >= 2`. Une ligne non revue reste en v1 : le taux de revue est donc mesurable et ne peut pas être artificiellement déclaré à 100 %.

### Règles d'arbitrage

**Menace.** La référence applique la même priorité sémantique que la taxonomie canonique : une classe spécifique bat un marqueur générique. `Ransomware` reste prioritaire ; une compromission de compte explicitement établie bat une intrusion générique ; une fuite/exfiltration avérée bat une simple mention de piratage ou d'accès non autorisé. Une revendication non corroborée doit être signalée dans la confiance plutôt que transformée en fait certain.

**Secteur.** Le secteur décrit l'activité principale réelle de la victime, pas son statut juridique et pas le domaine évoqué dans l'incident. Une entité publique de santé peut donc être `Santé`, un organisme de formation aux métiers du bâtiment est `Éducation / Formation`. La politique Cyberwatch `Immobilier -> Construction / BTP` reste applicable faute de catégorie immobilière dédiée.

**Localisation.** La localisation décrit l'implantation de la victime concernée par l'incident. Elle ne doit pas être déduite de la localisation d'un prestataire, d'un groupe parent ou de l'attaquant.

**Identité de l'incident.** Deux lignes avec la même organisation et des dates très proches doivent être revues comme doublon potentiel. Une republication ou une nouvelle source sur le même événement ne doit pas créer une deuxième vérité de référence.

### Hiérarchie des preuves

Pour trancher un désaccord, privilégier dans cet ordre :

1. communication officielle de la victime ;
2. administration, régulateur ou source institutionnelle ;
3. source Cyberwatch d'origine ;
4. média fiable ;
5. revendication d'attaquant ou agrégateur.

Une revendication d'attaquant prouve qu'une revendication existe ; elle ne prouve pas à elle seule que tous ses détails sont vrais.

### Confiance

- `HIGH` : preuve explicite et rejouable ; une URL de source exploitable est attendue ;
- `MEDIUM` : conclusion fortement étayée mais reposant en partie sur une inférence ou une revendication ;
- `LOW` : ambiguïté réelle ; ne pas forcer un label si `Inconnu` est plus fidèle.

## Auditer le golden lui-même

```bash
python scripts/audit_golden.py
```

Le script produit :

- `bench/results/golden_quality_findings.csv` : anomalies et cas à revoir ;
- `bench/results/golden_quality_summary.json` : couverture des URLs, distribution des confiances, taux de revue, corrections et doublons ;
- des alertes déterministes pour `HIGH` sans URL, preuves génériques, doublons proches et incohérences de priorité de menace.

Pour matérialiser la vue corrigée sans toucher au snapshot v1 :

```bash
python scripts/audit_golden.py --materialized bench/results/qualification_golden_v2.csv
```

## Construire les candidats

```bash
python scripts/build_golden_candidates.py --limit 150
```

Le résultat est écrit dans `bench/results/golden_candidates.csv`. Le script équilibre de façon déterministe l'échantillon entre les sources afin d'éviter qu'une source dominante écrase le benchmark.

## Alimenter le golden set

Ajouter les cas validés à `qualification_golden.csv` avec des identifiants stables `GOLD-0001`, `GOLD-0002`, etc. `Incident_ID_Snapshot` conserve l'identifiant observé au moment de la revue, mais il n'est pas l'identité primaire du cas.

`Golden_Version` commence à `1`. `Taxonomy_Version` doit correspondre à `config.METHOD_ID` au moment de la revue. Une évolution de méthode force ainsi une revue explicite plutôt qu'un benchmark silencieusement obsolète.

Une référence existante ne doit plus être retouchée silencieusement : toute correction postérieure au v1 passe par `qualification_golden_audit.csv`.

## Évaluer Cyberwatch seul

```bash
python scripts/evaluate_golden.py
```

Par défaut, le journal `qualification_golden_audit.csv` est appliqué avant l'évaluation. Passer `--audit ''` permet exceptionnellement de rejouer le snapshot v1 brut et de mesurer l'effet exact des corrections du juge.

Le matching utilise, dans l'ordre : l'`Incident_ID_Snapshot` s'il désigne encore le même cas, puis l'organisation avec une URL source commune, puis source + proximité de date, puis organisation + date très proche. Un résultat ambigu n'est jamais choisi arbitrairement.

Le rapport sépare notamment :

- `accuracy_pct` : correspondance exacte avec la référence ;
- `coverage_pct` : part des cas pour lesquels Cyberwatch ne répond pas `Inconnu` ;
- `precision_when_qualified_pct` : précision lorsque Cyberwatch tranche ;
- `resolvable_unknown` : `Inconnu` Cyberwatch alors que le golden set connaît la réponse ;
- `wrong_classification` : Cyberwatch tranche mais avec un mauvais label.

Les détails sont écrits dans `bench/results/golden_evaluation.csv`. Ces résultats sont des artefacts de benchmark et ne doivent pas être mélangés au golden set lui-même.

## Comparer la DB aux exports LLM

La commande permanente lit maintenant directement les trois JSON versionnés :

- `sources/veillellm/frenchbreaches_2026.json` ;
- `sources/veillellm/cyberattaque_org_2026.json` ;
- `sources/veillellm/cyberattaques_reunion_mayotte_2026.json`.

```bash
python scripts/evaluate_golden_challengers.py
```

Le benchmark applique d'abord le journal de revue du golden puis compare séparément `CYBERWATCH_DB`, `FRENCHBREACHES_LLM_JSON`, `CYBERATTAQUE_ORG_LLM_JSON` et `REUNION_MAYOTTE_LLM_JSON`. Il ne modifie ni n'enrichit les exports avant mesure ; une liste JSON `sources` est seulement convertie en URLs de provenance pour le matching.

Pour chaque champ (`Secteur`, `Menace`, `Localisation`), il affiche les mêmes métriques que le benchmark DB, puis un delta sur les cas retrouvés par les deux méthodes :

- `gains` : la DB est fausse et le challenger est correct ;
- `regressions` : la DB est correcte et le challenger est faux ;
- `delta_accuracy_pp` : écart d'accuracy en points sur les mêmes cas ;
- `common_matched_cases` : taille réelle de la comparaison directe.

Les détails sont écrits dans `bench/results/golden_challenger_comparison.csv` et le résumé dans `bench/results/golden_challenger_summary.json`.

### Matching des challengers

L'URL source commune est prioritaire et peut reconnaître le même incident même si l'ordre des mots du nom change (`Motoculture Cravero` / `Cravero Motoculture`). Sans URL commune, le matching exige une organisation normalisée identique et une date proche. Aucun rapprochement flou ou LLM n'est utilisé par le benchmark.

Si un cas légitime ne peut pas être rapproché automatiquement, `challenger_matches.csv` permet une correspondance manuelle minimale :

```text
Golden_ID,Challenger,Source_URL,Notes
GOLD-0042,FRENCHBREACHES_LLM_JSON,https://source.example/cas,alias de nom vérifié
```

Ce fichier ne contient aucune qualification et ne peut donc pas influencer le verdict du benchmark.
