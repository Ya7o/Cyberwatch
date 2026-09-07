# Statut d'architecture Cyberwatch

Date de simplification : 2026-09-01

## Architecture de production

```text
sources -> collecte -> identité -> enrichissement -> déduplication -> publication
```

Une seule branche de production : `main`. Chaque MAJ ne collecte qu'aujourd'hui
et hier, sans reconstruction historique. `collect.yml` est le seul workflow
qui écrit les données ; `ci.yml` valide le produit et `monitor.yml` surveille
la production sans la modifier.

## Règles

- `data/` est canonique ; `assets/data/` est dérivé ;
- une preuve insuffisante peut produire `Inconnu` ;
- une source en échec reste visible dans le journal du run ;
- les tendances 30 jours restent neutralisées avant 60 jours continus de
  couverture ; le dashboard avertit après 30 heures et déclare le snapshot
  périmé à 36 heures ;
- un filet LLM final vérifie les nouveaux doublons contre la base ;
- la publication est annulée si `origin/main` diffère du commit au départ du
  run ; le push non fast-forward couvre aussi la dernière fenêtre de course ;
- les métriques quotidiennes de production sont historisées dans
  `data/production_metrics.csv` et affichées dans la vue Analyse ;
- le corpus métier versionné dans `validation/business_corpus.json` complète
  le corpus de déduplication et s'exécute en CI sans réseau ;
- la priorité est la rapidité et la lisibilité du prototype.

Il n'existe ni branche de production parallèle, ni script de backfill dans le
chemin quotidien. La preuve de sept collectes planifiées ne peut être acquise
que par sept événements GitHub `schedule` réellement réussis.
