# Golden set de qualification

Ce dossier contient la référence manuelle réutilisable destinée à challenger la qualité de qualification de Cyberwatch. Il ne mesure pas la couverture de collecte : chaque cas doit provenir d'un incident et de sources déjà exploités par Cyberwatch.

## Principe

La référence doit être construite en aveugle à partir de `Incident_ID`, `Date`, `Organisation`, `Organisation_Key`, `Sources` et `Source_URLs`. Les valeurs Cyberwatch `Secteur`, `Menace` et `Localisation` ne doivent pas être consultées pendant la qualification de référence.

Les labels `*_REF` utilisent strictement les listes de `cyberwatch/config.py`. Une valeur connue doit être accompagnée d'une preuve courte et vérifiable. En cas d'ambiguïté réelle, `Inconnu` est préférable à une qualification forcée.

Le golden set est l'arbitre. Les exports LLM expérimentaux ne doivent jamais être recopiés dans `qualification_golden.csv` sans revue indépendante.

## Construire les candidats

```bash
python scripts/build_golden_candidates.py --limit 150
```

Le résultat est écrit dans `bench/results/golden_candidates.csv`. Le script équilibre de façon déterministe l'échantillon entre les sources afin d'éviter qu'une source dominante écrase le benchmark.

## Alimenter le golden set

Ajouter les cas validés à `qualification_golden.csv` avec des identifiants stables `GOLD-0001`, `GOLD-0002`, etc. `Incident_ID_Snapshot` conserve l'identifiant observé au moment de la revue, mais il n'est pas l'identité primaire du cas.

`Golden_Version` commence à `1`. `Taxonomy_Version` doit correspondre à `config.METHOD_ID` au moment de la revue. Une évolution de méthode force ainsi une revue explicite plutôt qu'un benchmark silencieusement obsolète.

Le fichier est append-only autant que possible. Une référence existante ne change que si une preuve meilleure apparaît, si la référence était erronée ou si la nomenclature évolue.

## Évaluer Cyberwatch seul

```bash
python scripts/evaluate_golden.py
```

Le matching utilise, dans l'ordre : l'`Incident_ID_Snapshot` s'il désigne encore le même cas, puis l'organisation avec une URL source commune, puis source + proximité de date, puis organisation + date très proche. Un résultat ambigu n'est jamais choisi arbitrairement.

Le rapport sépare notamment :

- `accuracy_pct` : correspondance exacte avec la référence ;
- `coverage_pct` : part des cas pour lesquels Cyberwatch ne répond pas `Inconnu` ;
- `precision_when_qualified_pct` : précision lorsque Cyberwatch tranche ;
- `resolvable_unknown` : `Inconnu` Cyberwatch alors que le golden set connaît la réponse ;
- `wrong_classification` : Cyberwatch tranche mais avec un mauvais label.

Les détails sont écrits dans `bench/results/golden_evaluation.csv`. Ces résultats sont des artefacts de benchmark et ne doivent pas être mélangés au golden set lui-même.

## Comparer la DB aux exports LLM FrenchBreaches / Cyberattaque.org

Les exports expérimentaux actuellement attendus sont :

- `sources/veillellm/frenchbreaches_2026.csv` ;
- `sources/veillellm/cyberattaque_org_2026.csv`.

Ils sont lus tels quels : le benchmark ne les enrichit pas et ne les corrige pas avant mesure. Le champ `territoire` est simplement ramené à la nomenclature de localisation Cyberwatch (`France` devient `France métropolitaine`, un territoire hors périmètre devient `Inconnu`).

Exécuter :

```bash
python scripts/evaluate_golden_challengers.py
```

Le rapport compare séparément :

- `CYBERWATCH_DB` ;
- `FRENCHBREACHES_LLM` ;
- `CYBERATTAQUE_ORG_LLM`.

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
GOLD-0042,FRENCHBREACHES_LLM,https://source.example/cas,alias de nom vérifié
```

Ce fichier ne contient aucune qualification et ne peut donc pas influencer le verdict du benchmark.
