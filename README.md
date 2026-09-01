# Cyberwatch

Cyberwatch collecte des incidents cyber publiquement documentés, les enrichit,
les déduplique puis publie un dashboard statique.

**Production : https://ya7o.github.io/Cyberwatch/**

Chaque mise à jour cherche seulement les publications d'aujourd'hui et d'hier.
Le corpus déjà publié est conservé tel quel et n'est jamais reconstruit par le
workflow quotidien.

## Chaîne unique

```text
collecte -> identité -> enrichissement -> déduplication -> publication
```

- `data/items.csv` contient les observations issues des sources ;
- `data/incidents.csv` contient les incidents dédupliqués ;
- `assets/data/` est généré pour le dashboard ;
- `main` contient le code, les données et la production GitHub Pages.

Il n'existe ni branche `prod`, ni promotion, ni workflow de reset parallèle.

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

# contrôles et dashboard
python -m cyberwatch check
python -m cyberwatch build-site
python -m cyberwatch report
```

`maj` ajoute les dernières publications calendaires. Elle peut accéder au
réseau et utiliser l'API OpenAI si `OPENAI_API_KEY` est présente. Sans clé, la
collecte continue et les valeurs non résolues restent `Inconnu`.

## GitHub Actions

Deux workflows seulement :

- `ci.yml` exécute seulement quelques smoke tests et la syntaxe JavaScript ;
- `collect.yml` lance une collecte quotidienne à 11 h à La Réunion et publie
  directement les données sur `main`.

Le lancement manuel de `collect.yml` exécute la même `maj`. Un plafond global
de 0,03 $ couvre l'extraction de faits et le filet final de déduplication. Les
usages détaillés sont consignés dans `data/llm_usage.json`.

## Vérification rapide

```bash
python -m pytest -q tests/test_normalize.py tests/test_collector_registry.py tests/test_dedup.py tests/test_site.py
node --check assets/dashboard-v2.js
node --check assets/dashboard-integrity.js
```
