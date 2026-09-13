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

## Qualification sectorielle

Un secteur n'est publié que s'il repose sur une activité métier prouvée. L'ordre est : référentiel validé, nom institutionnel sûr, rubrique structurée de la source, activité citée dans l'article. À défaut, le secteur reste `Inconnu` avec un motif explicite — une abstention vaut mieux qu'une attribution non justifiée.

Pour BonjourLaFuite, qui ne publie qu'un nom et des types de données, deux niveaux comblent le vide. Le niveau 1 réutilise une activité déjà prouvée pour la même identité canonique. Le niveau 2 va chercher la preuve dehors : URL déjà connue de Cyberwatch, puis registre public `recherche-entreprises.api.gouv.fr`. Aucun moteur de recherche généraliste n'est implémenté ni simulé.

Un provider ne rend que des URL candidates ; il n'a aucun pouvoir de décision. La preuve n'existe qu'après téléchargement et vérification : citation littéralement présente dans le contenu, nom propre exactement celui de la victime, ni récit d'incident, ni activité d'un tiers ou d'une maison mère. Une fiche de registre n'est jamais retenue sur la seule concordance de nom — il faut une corroboration indépendante à l'échelle de la commune ou d'un département d'outre-mer. Le secteur est ensuite établi par la chaîne existante, déterministe d'abord, mapper taxonomique ensuite.

Zéro appel de modèle sur tout chemin déterministe ; au plus un appel pour désigner une citation et un pour la taxonomie, la citation désignée repassant par toutes les portes déterministes. `data/organisation_activity_evidence.csv` mémorise une preuve par organisation et la re-vérifie à chaque lecture, si bien qu'un durcissement de politique est rétroactif.

```bash
python scripts/evaluate_external_activity.py   # benchmark d'activation, hors ligne
```

Le niveau 2 n'est activé en production qu'après ce benchmark : dix portes bloquantes, dont zéro faux positif, zéro erreur d'identité et zéro secteur sans activité prouvée. Résultat courant dans `validation/external_activity_20/report.md`.

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
