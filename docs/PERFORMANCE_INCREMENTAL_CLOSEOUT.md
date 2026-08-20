# Performance / incrémental — contrat de clôture

## Architecture retenue

- Les `SourceFacts` inchangés sont réutilisés avec preuve `Item_ID + source + version + content hash`.
- Le dirty-set **pré-qualification** classe chaque item en `NEW`, `DIRTY` ou `UNCHANGED` à partir des entrées métier, SourceFacts, version de politique et dépendances.
- `CYBERWATCH_INCREMENTAL_QUALIFICATION=1` autorise le fast-path uniquement lorsque le dirty-set ne contient aucun travail.
- Dès qu'un item est `NEW` ou `DIRTY`, `qualify()` complet reste la référence canonique.
- Même sur fast-path, les incidents sont toujours reconstruits par la déduplication courante. Une évolution de règle peut donc faire merge/split sans données nouvelles.
- Le cache détail FrenchBreaches reste opt-in (`CYBERWATCH_FRENCHBREACHES_DETAIL_CACHE=1`) tant qu'un historique réel ne justifie pas son activation par défaut.

## Pourquoi il n'existe pas de `qualify_partial()` en production

La qualification comporte des dépendances globales par organisation et par registre (contexte, consensus, conflits, restauration de provenance). Requalifier seulement un item NEW/DIRTY sans recalculer correctement ses dépendances peut produire un résultat différent du canonique. Le coût de complexité et de preuve est supérieur au gain démontré à ce stade.

Le contrat retenu est donc : **zéro changement => presque zéro travail de qualification ; changement => canonique complet**. C'est le point d'optimisation à fort rendement et faible risque observé dans les logs.

## Gates

Les métriques Performance enregistrent le mode `full/delta`, le dirty-set préqual, les appels SourceFacts LLM et un verdict `performance_gate`.

Un run est invalide si :

- `qualification_mode=delta` avec `prequal_new > 0` ou `prequal_dirty > 0` ;
- le fast-path delta déclenche un appel SourceFacts LLM ;
- le shadow de qualification détecte une divergence.

Aucun gate ne repose sur un temps absolu, car la latence réseau/CI est variable.

## Verdict de clôture réelle

`scripts/performance_closeout_report.py` retourne :

- `BLOCKED` si un invariant est violé ;
- `NOT_READY` tant qu'aucun run réel n'a emprunté le fast-path ;
- `READY` dès qu'un run réel delta existe et que les invariants récents sont verts.

Ainsi le code du chantier peut être fusionné sans prétendre avoir mesuré un run qui n'a pas été exécuté.
