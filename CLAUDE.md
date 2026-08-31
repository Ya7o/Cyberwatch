# Cyberwatch — garde-fous de développement

La chaîne canonique est unique :

```text
collecte -> enrichissement -> déduplication -> publication sur main
```

## Invariants

- Le corpus publié commence le `2026-08-28`.
- `data/` est canonique et `assets/data/` est généré.
- Une absence de preuve reste `Inconnu`.
- Une panne de source est journalisée et n'est pas masquée.
- `Item_ID`, `Organisation_Key` et `Incident_ID` sont reproductibles.
- Le LLM ne contourne pas les règles déterministes d'identité ou de fusion.
- `replay`, `diagnose` et `probe` ne doivent engager aucun coût LLM.

## Surface opérationnelle

- `.github/workflows/ci.yml` : tests ;
- `.github/workflows/collect.yml` : collecte quotidienne ou manuelle et
  publication directe sur `main`.

Ne pas ajouter de branche `prod`, de workflow de promotion, de reset parallèle
ou de nouvelle couche sans problème réel et mesuré.

## Validation

```bash
python -m pytest tests/ -q
node --check assets/dashboard-v2.js
node --check assets/dashboard-integrity.js
python -m cyberwatch check --allow-uninitialized
```

Une collecte réelle n'est pas un test générique : elle accède au réseau,
modifie les données et peut appeler l'API si une clé est disponible.

La méthode métier détaillée reste définie dans `METHODOLOGY.md`.
