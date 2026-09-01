# Cyberwatch

Cyberwatch collecte des incidents cyber publiquement documentés, les enrichit,
les déduplique puis publie un dashboard statique.

**Production : https://ya7o.github.io/Cyberwatch/**

Le corpus initial commence le **28 août 2026**. Ensuite, chaque mise à jour ne
cherche que les publications d'aujourd'hui et d'hier.

## Chaîne unique

```text
collecte -> identité -> enrichissement -> déduplication -> publication
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

# quotidien : aujourd'hui + hier uniquement
python -m cyberwatch maj

# reconstruction exceptionnelle du corpus initial
python -m cyberwatch create

# contrôles et dashboard
python -m cyberwatch check
python -m cyberwatch build-site
python -m cyberwatch report
```

`create` remplace la base depuis le 28 août ; `maj` ajoute les dernières
24 heures calendaires. Les deux peuvent accéder au
réseau et utiliser l'API OpenAI si `OPENAI_API_KEY` est présente. Sans clé, la
collecte continue et les valeurs insuffisamment prouvées restent `Inconnu`.

## GitHub Actions

Deux workflows seulement :

- `ci.yml` exécute seulement quelques smoke tests et la syntaxe JavaScript ;
- `collect.yml` lance une collecte quotidienne à 11 h à La Réunion et publie
  directement les données sur `main`.

Le lancement manuel de `collect.yml` propose uniquement `maj` ou `create`.
Les plafonds logiciels visent environ 0,10 $ par run entre qualification,
faits structurés, secteur et déduplication ; les usages sont consignés dans
`data/ai_usage.csv` et `data/dedup_ai_daily_usage.csv`.

## Vérification rapide

```bash
python -m pytest -q tests/test_normalize.py tests/test_collector_registry.py tests/test_dedup.py tests/test_site.py
node --check assets/dashboard-v2.js
node --check assets/dashboard-integrity.js
```
