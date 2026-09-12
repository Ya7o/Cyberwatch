# Cyberwatch

Cyberwatch collecte des incidents cyber publiquement documentés, les enrichit, les déduplique puis publie un dashboard statique.

**Production : https://ya7o.github.io/Cyberwatch/**

## Architecture

```text
collecte -> identité -> enrichissement -> déduplication -> publication
```

- `data/items.csv` contient les observations ;
- `data/incidents.csv` contient les incidents dédupliqués ;
- `assets/data/` est généré pour le dashboard ;
- `main` contient le code, les données et la production GitHub Pages.

Une `MAJ` collecte uniquement aujourd'hui et hier à La Réunion (UTC+4) et conserve le corpus existant. `PURGE` vide le corpus et le dashboard sans lancer de collecte.

## Sources actives

| Source | Accès |
|---|---|
| `FRENCHBREACHES` | RSS |
| `BONJOURLAFUITE` | HTML |
| `CYBERATTAQUE_ORG` | contenu paginé |
| `RANSOMWARE_LIVE` | API JSON |
| `VEILLE_LLM` | snapshot versionné La Réunion / Mayotte |

## Production

La collecte canonique passe par `.github/workflows/collect.yml`. Le secret GitHub `Cyberwatchapi` est injecté dans `OPENAI_API_KEY` et ne doit jamais être écrit dans le dépôt ou les journaux.

```bash
gh workflow run collect.yml --ref main -f operation=MAJ
gh workflow run collect.yml --ref main -f operation=PURGE
```

`collect.yml` est le seul workflow qui écrit les données. `ci.yml` valide le produit et `monitor.yml` surveille la fraîcheur sans modifier le corpus.

## Développement

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
python -m cyberwatch check
python -m cyberwatch validate-business
node --check assets/dashboard-v2.js
node --check assets/dashboard-integrity.js
```

Une collecte locale peut accéder au réseau et à l'API si `OPENAI_API_KEY` est présente ; elle n'est pas le chemin de publication de production.

Cyberwatch est un outil de veille fondé sur des publications publiques : une fiche n'est ni une attribution ni une confirmation globale de tous les faits, et l'absence de fiche ne prouve pas l'absence d'incident. Pour signaler une correction, ouvrir une issue GitHub avec une source publique vérifiable.

Licence : MIT.
