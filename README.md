# Cyberwatch

Cyberwatch collecte des incidents cyber publiquement documentés, les enrichit,
les déduplique puis publie un dashboard statique.

**Production : https://ya7o.github.io/Cyberwatch/**

Le corpus de production commence le **28 août 2026**. Un événement antérieur
n'est pas conservé, même s'il est découvert plus tard.

## Chaîne unique

```text
collecte -> enrichissement -> déduplication -> publication
```

- `data/items.csv` contient les observations issues des sources ;
- `data/incidents.csv` contient les incidents dédupliqués ;
- `assets/data/` est généré pour le dashboard ;
- `main` contient le code, les données et la production GitHub Pages.

Il n'existe ni branche `prod`, ni promotion entre environnements, ni workflow
de reset parallèle.

## Sources actives

| Source | Accès |
|---|---|
| `FRENCHBREACHES` | RSS |
| `BONJOURLAFUITE` | HTML |
| `CYBERATTAQUE_ORG` | contenu paginé |
| `RANSOMWARE_LIVE` | API JSON |
| `VEILLE_LLM` | snapshot versionné La Réunion / Mayotte |

`VEILLE_LLM` conserve les signaux non confirmés comme `CANDIDATE`, mais seuls
les enregistrements `ACCEPTED` entrent dans le corpus. Deux événements d'une
même organisation et d'un même jour restent distincts lorsque leur
localisation diffère.

## Commandes

```bash
pip install -r requirements.txt

# mise à jour ou reconstruction, toujours depuis le 28 août
python -m cyberwatch maj --layers all --start 2026-08-28
python -m cyberwatch create --layers all --start 2026-08-28

# contrôles et dashboard
python -m cyberwatch check
python -m cyberwatch build-site
python -m cyberwatch report
```

`create` remplace la base ; `maj` la met à jour. Les deux peuvent accéder au
réseau et utiliser l'API OpenAI si `OPENAI_API_KEY` est présente. Sans clé, la
collecte continue et les valeurs insuffisamment prouvées restent `Inconnu`.

Pour un diagnostic sans publication :

```bash
python -m cyberwatch diagnose
python -m cyberwatch probe SOURCE_ID
python -m cyberwatch replay
```

## GitHub Actions

Deux workflows seulement :

- `ci.yml` teste le code sur `main` et les pull requests ;
- `collect.yml` lance une collecte quotidienne à 11 h à La Réunion et publie
  directement les données sur `main`.

Le lancement manuel de `collect.yml` propose uniquement `maj` ou `create`.
Le budget LLM est plafonné par run ; les usages sont consignés dans
`data/ai_usage.csv` et `data/dedup_ai_daily_usage.csv`.

## Validation locale

```bash
python -m pytest tests/ -q
node --check assets/dashboard-v2.js
node --check assets/dashboard-integrity.js
python -m cyberwatch check --allow-uninitialized
```

Les règles détaillées de qualification et de déduplication restent décrites
dans `METHODOLOGY.md`. Les changements doivent corriger un problème observé ;
ils ne doivent pas ajouter une seconde chaîne parallèle.
