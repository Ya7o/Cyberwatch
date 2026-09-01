# Statut d'architecture Cyberwatch

Date de simplification : 2026-08-31

## Architecture de production

```text
sources -> collecte -> identité -> enrichissement -> déduplication -> publication
```

Une seule branche de production : `main`. Le corpus commence le 28 août 2026,
puis chaque MAJ ne collecte qu'aujourd'hui et hier. Deux workflows : `ci.yml`
et `collect.yml`.

## Règles

- `data/` est canonique ; `assets/data/` est dérivé ;
- une preuve insuffisante peut produire `Inconnu` ;
- une source en échec reste visible dans le journal du run ;
- un filet LLM final vérifie les nouveaux doublons contre la base ;
- aucun nouveau workflow ou chemin de publication parallèle sans besoin
  produit démontré ;
- la priorité est la rapidité et la lisibilité du prototype.

Les anciens golden sets, benchmarks de certification et promotions ne font pas
partie du projet.
