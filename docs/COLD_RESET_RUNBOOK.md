# Cold reset de développement

Le reset total Cyberwatch sert désormais à valider qu'une base propre peut être reconstruite depuis zéro avec le code actuel. La conservation de l'historique publié n'est pas un critère bloquant pendant cette phase de développement.

## Invariants

- les alias, référentiels Sector, golden datasets et baselines qualité restent protégés ;
- `incident_id_registry.csv` est réinitialisé dans le staging afin de tester aussi la génération des identités depuis zéro ;
- le reset travaille dans `/tmp/cyberwatch-cold-reset` et la base canonique n'est remplacée qu'après certification ;
- les différences d'`Item_ID` et d'`Incident_ID` avant/après sont conservées comme diagnostics mais ne bloquent plus la promotion ;
- les enrichissements sont exécutés par couches avec budgets indépendants et checkpoints de cache entre passes ;
- une archive complète de la DB actuelle est conservée pour comparaison et rollback.

## Avant lancement

Exécuter :

```bash
python -m cyberwatch.cold_reset preflight
python -m cyberwatch.cold_reset manifest --output /tmp/cold-reset-before.json
```

Le préflight doit retourner `GO`. Le manifeste contient les hashes des actifs présents, des caches et sorties dérivées, ainsi qu'une estimation de durée/coût basée sur la télémétrie disponible.

## Séquence du workflow

1. tests complets et préflight offline ;
2. archive restaurable du snapshot courant ;
3. staging isolé et purge des sorties, caches froids, états incrémentaux et registre d'incidents ;
4. reconstruction déterministe sans LLM ni enrichissement réseau ;
5. diff historique informatif ;
6. qualification bornée ;
7. extraction sémantique par passes de 250 appels maximum ;
8. SourceFacts par passes de 250 appels maximum ;
9. enrichissement organisation sans LLM ;
10. golden tests, qualité, répétabilité, contrôles structurels et gate DB non vide ;
11. diff final avant/après à des fins d'audit ;
12. export des diagnostics ;
13. promotion atomique si `publish=true`.

`publish` vaut `true` par défaut pour le reset de développement : la reconstruction est donc publiée automatiquement si et seulement si tous les gates techniques passent.

## Gates bloquants

La promotion reste bloquée sur les échecs techniques : tests, golden dedup, golden qualification, qualité des données, `cyberwatch check`, `test-repeat`, build du site ou DB vide/invalide.

La perte d'anciens `Item_ID` ou `Incident_ID` n'est plus bloquante en phase de développement. Elle reste visible dans les artifacts pour le ré-audit après reset.

## Rollback et ré-audit

Chaque run exporte `cyberwatch-before-reset.tgz`, les manifests avant/après, les diffs d'identités et les rapports LLM. En cas d'échec avant promotion, la base canonique reste intacte. Après une promotion, l'archive permet de restaurer ou simplement de comparer l'ancienne DB avec la nouvelle lors du ré-audit complet.
