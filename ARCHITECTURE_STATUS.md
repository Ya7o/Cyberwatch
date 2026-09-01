# Statut d'architecture Cyberwatch

Date de simplification : 2026-09-01

## Architecture de production

```text
sources -> collecte -> identité -> enrichissement -> déduplication -> publication
```

Une seule branche de production : `main`. Chaque MAJ ne collecte qu'aujourd'hui
et hier, sans reconstruction historique. Deux workflows : `ci.yml` et
`collect.yml`.

## Règles

- `data/` est canonique ; `assets/data/` est dérivé ;
- une preuve insuffisante peut produire `Inconnu` ;
- une source en échec reste visible dans le journal du run ;
- un filet LLM final vérifie les nouveaux doublons contre la base ;
- aucun nouveau workflow ou chemin de publication parallèle sans besoin
  produit démontré ;
- la priorité est la rapidité et la lisibilité du prototype.

Il n'existe plus de golden set, benchmark, campagne de qualification, script de
backfill ou registre de revue secteur dans le projet.
