# Statut d'architecture Cyberwatch

Date de simplification : 2026-08-31

## Architecture de production

```text
sources -> collecte -> enrichissement -> déduplication -> publication
```

Une seule branche de production : `main`. Une seule période de données : à
partir du 28 août 2026. Deux workflows : `ci.yml` et `collect.yml`.

## Règles

- `data/` est canonique ; `assets/data/` est dérivé ;
- une preuve insuffisante produit `Inconnu`, jamais une valeur inventée ;
- une source en échec reste visible dans le journal du run ;
- les identifiants et la déduplication restent déterministes ;
- aucun nouveau workflow ou chemin de publication parallèle sans besoin
  produit démontré ;
- les optimisations visent d'abord la collecte, la qualité des données et le
  temps d'exécution mesuré.

Les tests et benchmarks existants sont conservés lorsqu'ils protègent ces
invariants. Les anciens artefacts de clôture, resets et promotions ne font pas
partie de l'exploitation.
