# Cyberwatch — garde-fous de développement

La chaîne canonique est unique :

```text
collecte -> identité -> enrichissement -> déduplication -> publication
```

## Invariants

- Une MAJ lit seulement aujourd'hui et hier et conserve le corpus existant.
- `MAJ` / `maj` lance `python -m cyberwatch maj`, y compris après une purge.
- `PURGE` / `purge` lance `python -m cyberwatch purge` : vider le corpus,
  les caches et files de reprise, puis générer un dashboard vide, sans collecte.
- `data/` est canonique et `assets/data/` est généré.
- Une absence de preuve reste `Inconnu`.
- Une panne de source est journalisée et n'est pas masquée.
- `Item_ID`, `Organisation_Key` et `Incident_ID` sont reproductibles.
- Le LLM ne contourne pas les règles déterministes d'identité ou de fusion.
- Une réponse LLM invalide conserve le résultat déterministe.

## Surface opérationnelle

- `.github/workflows/ci.yml` : smoke tests ;
- `.github/workflows/collect.yml` : collecte quotidienne ou manuelle et
  publication directe sur `main`, avec choix manuel MAJ ou PURGE.

GitHub est la base. `MAJ` et `PURGE` s'exécutent **à distance**, via
`collect.yml`, jamais en local : la clé API vit dans le secret GitHub
`CYBERWATCHAPI`, et seul le workflow publie `data/` et `assets/data/` sur
`main`. Un run local n'a pas la clé, produit un corpus dégradé et un état qui
diverge de `main`.

```bash
gh workflow run collect.yml --ref main -f operation=MAJ
gh workflow run collect.yml --ref main -f operation=PURGE
gh run watch <run-id> --exit-status   # puis git pull pour récupérer le corpus
```

Après une purge, enchaîner une MAJ : la purge ne collecte rien.

Ne pas ajouter de branche `prod`, golden, campagne de qualification, workflow
de promotion, reset parallèle ou nouvelle couche sans besoin produit réel.

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
