# Cyberwatch — instructions agent

## Production
- `main` est la source canonique.
- Pour **MAJ** ou **PURGE** en production, utiliser `.github/workflows/collect.yml` ; ne pas lancer une collecte locale.
- `PURGE` vide les données et génère un dashboard vide. Ne pas lancer `MAJ` automatiquement après : attendre une demande explicite ou la collecte planifiée.
- `data/` est canonique ; `assets/data/` est généré.

```bash
gh workflow run collect.yml --ref main -f operation=MAJ
gh workflow run collect.yml --ref main -f operation=PURGE
```

## Validation
```bash
python -m pytest tests/ -q
node --check assets/dashboard-v2.js
node --check assets/dashboard-integrity.js
python -m cyberwatch check --allow-uninitialized
```

Une collecte réelle n'est pas un test générique.

Pour les règles métier, lire `METHODOLOGY.md` uniquement si la tâche le nécessite. Pour la résolution sectorielle, lire `docs/SECTOR_IMPLEMENTATION_2026-09-05.md` uniquement si nécessaire.
