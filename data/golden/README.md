# Golden set de qualification

Ce dossier contient la référence manuelle réutilisable destinée à challenger la qualité de qualification de Cyberwatch. Il ne mesure pas la couverture de collecte : chaque cas doit provenir d'un incident et de sources déjà exploités par Cyberwatch.

## Principe

La référence doit être construite en aveugle à partir de `Incident_ID`, `Date`, `Organisation`, `Organisation_Key`, `Sources` et `Source_URLs`. Les valeurs Cyberwatch `Secteur`, `Menace` et `Localisation` ne doivent pas être consultées pendant la qualification de référence.

Les labels `*_REF` utilisent strictement les listes de `cyberwatch/config.py`. Une valeur connue doit être accompagnée d'une preuve courte et vérifiable. En cas d'ambiguïté réelle, `Inconnu` est préférable à une qualification forcée.

## Construire les candidats

```bash
python scripts/build_golden_candidates.py --limit 150
```

Le résultat est écrit dans `bench/results/golden_candidates.csv`. Le script équilibre de façon déterministe l'échantillon entre les sources afin d'éviter qu'une source dominante écrase le benchmark.

## Alimenter le golden set

Ajouter les cas validés à `qualification_golden.csv` avec des identifiants stables `GOLD-0001`, `GOLD-0002`, etc. `Incident_ID_Snapshot` conserve l'identifiant observé au moment de la revue, mais il n'est pas l'identité primaire du cas.

`Golden_Version` commence à `1`. `Taxonomy_Version` doit correspondre à `config.METHOD_ID` au moment de la revue. Une évolution de méthode force ainsi une revue explicite plutôt qu'un benchmark silencieusement obsolète.

Le fichier est append-only autant que possible. Une référence existante ne change que si une preuve meilleure apparaît, si la référence était erronée ou si la nomenclature évolue.

## Évaluer Cyberwatch

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
