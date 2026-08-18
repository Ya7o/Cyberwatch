# Cyberwatch

Cyberwatch est un observatoire reproductible d'incidents cyber **publiquement documentés** en France et dans l'Océan Indien.

Le projet collecte plusieurs sources, normalise les événements, qualifie les champs utiles, déduplique les observations en incidents, contrôle la cohérence du snapshot puis publie un dashboard statique.

**Dashboard : https://ya7o.github.io/Cyberwatch/**

Version du package : `1.0.0`.

> Cyberwatch documente ce qui est publiquement observable. Il ne prétend pas recenser toutes les cyberattaques réelles.

## 1. Vue d'ensemble

Le flux nominal est :

```text
Sources
  ↓
Collecte
  ↓
Normalisation / identification de l'organisation
  ↓
Qualification Threat / Sector / Location
  ↓
Registres et enrichissements contrôlés
  ↓
Déduplication en incidents
  ↓
Contrôles + hashes déterministes
  ↓
CSV canoniques
  ↓
JSON du dashboard / GitHub Pages
```

Trois documents ont des rôles distincts :

- `README.md` : comprendre et exploiter le projet ;
- `METHODOLOGY.md` : méthode normative détaillée et choix de conception ;
- `CLAUDE.md` : garde-fous techniques pour modifier le dépôt sans casser ses invariants.

## 2. Principes de conception

Cyberwatch privilégie la **traçabilité et la reproductibilité** à la recherche d'une couverture artificiellement parfaite.

- mêmes entrées → mêmes identifiants et mêmes hashes ;
- une source défaillante est journalisée, pas transformée en faux succès ;
- une donnée insuffisamment prouvée reste `Inconnu` ;
- l'IA ne décide jamais l'identité d'un item ou d'un incident ;
- les CSV de `data/` sont canoniques, les fichiers de `assets/data/` sont dérivés ;
- les rapprochements d'organisations restent prudents : mieux vaut un doublon à examiner qu'une fusion irréversible mal fondée.

## 3. Périmètre et sources

Le périmètre méthodologique couvre la France métropolitaine et plusieurs territoires de l'Océan Indien : La Réunion, Mayotte, Maurice, Madagascar, Seychelles et Comores.

Le pipeline publié repose actuellement sur cinq sources actives :

| Source | Rôle | Accès |
|---|---|---|
| `FRENCHBREACHES` | fuites de données en France | flux RSS |
| `BONJOURLAFUITE` | chronologie de fuites | parseur HTML dédié |
| `CYBERATTAQUE_ORG` | incidents/cyberattaques publiés | source paginée avec contenu |
| `RANSOMWARE_LIVE` | ransomware, groupe, pays et parfois secteur | API JSON |
| `VEILLE_LLM` | couverture analytique La Réunion + Mayotte | snapshot JSON versionné |

`VEILLE_LLM` est relu intégralement à chaque run. Son `score_cyberattaque` est une information, jamais un seuil d'exclusion. Lorsqu'un incident existe aussi dans une source directe, cette source analytique ne gonfle pas artificiellement le nombre de corroborations éditoriales.

D'autres sources et couches existent dans `cyberwatch/sources.py` mais restent volontairement inactives lorsqu'elles ne permettent pas une collecte suffisamment fiable ou vérifiable. Leur protocole et leur motif de désactivation sont conservés dans le référentiel plutôt que masqués.

## 4. Architecture du code

L'orchestration principale est portée par `cyberwatch/runner.py` et la phase canonique offline par `cyberwatch/qualification.py`.

Les principaux blocs sont :

- `cyberwatch/collectors/` : adaptateurs de collecte (`feed`, WordPress, JSON-LD, HTML dédié, API ransomware, Veille LLM, veille média…) ;
- `cyberwatch/sources.py` : référentiel exécutable des sources, protocoles et critères de succès ;
- `cyberwatch/normalize.py` : normalisation des noms, dates, localisation et menace ;
- `cyberwatch/sector.py` : politique déterministe de classification Sector ;
- `cyberwatch/enrichment.py` : référentiel manuel et enrichissements sûrs ;
- `cyberwatch/org_enrichment.py`, `company_evidence.py`, `company_subject_evidence.py` : preuves entreprise/activité ;
- `cyberwatch/sector_registry.py` : registre organisation → secteur et file de qualification ;
- `cyberwatch/source_facts.py` / `source_facts_ai.py` : faits structurés extraits des sources ;
- `cyberwatch/ai.py` : filet de rattrapage LLM sur les champs encore inconnus pendant une vraie collecte réseau ;
- `cyberwatch/dedup.py` et `incident_identity.py` : regroupement des items et stabilité des incidents ;
- `cyberwatch/store.py` : lecture/écriture atomique des données ;
- `cyberwatch/site.py` : génération des données consommées par le dashboard ;
- `cyberwatch/quality.py`, `qualification.py` et les scripts d'audit : contrôles de qualité et non-régression.

Le modèle des colonnes canoniques est défini dans `cyberwatch/model.py`.

## 5. Qualification des données

### Menace et localisation

Les valeurs structurées fournies par une source sont privilégiées. Les règles déterministes complètent ensuite les valeurs manquantes. Un filet LLM peut intervenir pendant `create`/`maj` uniquement lorsqu'un champ reste inconnu et qu'une clé OpenAI est disponible.

Une valeur déjà connue n'est pas écrasée arbitrairement par le filet IA, et l'identité (`Item_ID`, `Organisation_Key`, `Incident_ID`) reste hors de son périmètre.

### Secteur

La qualification Sector est volontairement conservatrice. `Inconnu` signifie **preuve insuffisante selon la politique active**, pas nécessairement « secteur introuvable ».

Les preuves utiles comprennent notamment :

1. secteur structuré explicitement fourni par une source et mappé dans la taxonomie ;
2. référentiel manuel `data/enrichment_reference.csv` ;
3. règles nominatives considérées suffisamment sûres ;
4. description d'activité explicitement extraite ;
5. preuves entreprise : activité officielle, code NAF précis, site officiel ;
6. consensus entre observations d'une même organisation ;
7. candidat LLM conservé comme preuve lorsque le canal n'est pas autorisé à écrire automatiquement.

Le registre `cyberwatch/sector_registry.py` agrège ces preuves par organisation et produit trois décisions :

- `AUTO` : preuve issue d'un canal autorisé par la politique ;
- `REVIEW` : candidat cohérent mais canal non autorisé en écriture automatique ;
- `CONFLICT` : plusieurs secteurs incompatibles ou preuve contradictoire.

La politique d'activation se trouve dans `data/sector_auto_policy.json`. Elle permet d'améliorer progressivement la couverture **sans transformer chaque nouvelle intuition en règle globale**.

Audit Sector :

```bash
python scripts/audit_sector_coverage.py --output ""
python scripts/evaluate_sector_registry.py --json /tmp/sector-registry.json
python scripts/check_sector_registry_policy.py --json /tmp/sector-registry.json
```

Sorties principales :

- `data/sector_quality.json` : métriques de couverture ;
- `data/organisation_sector_registry.csv` : preuves et décision par organisation ;
- `data/sector_enrichment_queue.csv` : organisations restant à traiter.

## 6. Déduplication et identité

`data/items.csv` conserve les observations source par source. `data/incidents.csv` contient la vue dédupliquée utilisée par le dashboard.

La logique reste déterministe : normalisation de l'organisation, regroupement temporel, choix d'une ancre stable et registre d'identifiants d'incident. Les rapprochements flous ne sont pas appliqués silencieusement.

Pour rechercher des doublons potentiels sans modifier les données :

```bash
python -m cyberwatch audit-duplicates
```

## 7. Données

### Données canoniques

Les fichiers principaux de `data/` sont :

- `items.csv` : une ligne par item collecté ;
- `incidents.csv` : incidents dédupliqués ;
- `sources.csv` : référentiel des sources et protocoles ;
- `run_sources.csv` : résultat détaillé de chaque source pendant chaque run ;
- `run_log.csv` : synthèse des runs ;
- `entity_watch.csv` : état de la veille nominative ;
- `snapshot.json` : provenance et hashes du snapshot courant ;
- `baseline.json` : baseline locale facultative ;
- `source_facts.csv` : faits auxiliaires extraits des sources ;
- `enrichment_reference.csv` : enrichissements manuels explicites ;
- `ai_qualifications.csv` / `ai_usage.csv` : cache, provenance et consommation du filet IA ;
- `organisation_sector_registry.csv` / `sector_enrichment_queue.csv` : registre et file Sector ;
- `qualification_provenance.csv` : décisions de qualification réversibles et traçables.

Le schéma exact des tables métier est défini dans `cyberwatch/model.py`.

### Données dérivées

`assets/data/` est généré depuis les données canoniques pour le dashboard. Il ne doit pas être édité à la main.

```bash
python -m cyberwatch build-site
```

## 8. Commandes

Installation :

```bash
pip install -r requirements.txt
```

Commandes principales :

| Commande | Usage |
|---|---|
| `python -m cyberwatch create` | construire une base depuis zéro |
| `python -m cyberwatch maj` | mettre à jour une base existante |
| `python -m cyberwatch replay` | reconstruire offline depuis les données locales |
| `python -m cyberwatch check` | contrôler la cohérence du snapshot |
| `python -m cyberwatch test-repeat` | vérifier la répétabilité déterministe |
| `python -m cyberwatch build-site` | régénérer les données du dashboard |
| `python -m cyberwatch report` | afficher le résumé Markdown du dernier run |
| `python -m cyberwatch diagnose` | sonder les sources sans publier de snapshot |
| `python -m cyberwatch probe SOURCE_ID` | diagnostiquer une source précise |
| `python -m cyberwatch probe-media` | comparer les accès disponibles pour les médias |
| `python -m cyberwatch backfill-unknowns` | rejouer la requalification offline des champs prévus |
| `python -m cyberwatch audit-duplicates` | signaler des rapprochements possibles sans fusion |
| `python -m cyberwatch repair-identities` | réparer les identités déterministes existantes |
| `python -m cyberwatch repair-integrity` | réparer IDs et doublons de clé exacte |
| `python -m cyberwatch baseline` | enregistrer la baseline du snapshot validé |

`maj` travaille avec un chevauchement temporel afin de récupérer les publications tardives ; `VEILLE_LLM` est, lui, relu en totalité.

Les commandes réseau acceptent notamment `--as-of`, `--start`, `--layers` et `--transient` selon le mode. Utiliser `--transient` pour une exécution qui ne doit pas écrire le snapshot ni les historiques.

## 9. IA et coûts

Le projet peut utiliser `OPENAI_API_KEY` pendant une vraie collecte pour compléter certains champs encore inconnus. Sans clé, le pipeline continue sans ce filet.

```bash
export OPENAI_API_KEY=sk-...
python -m cyberwatch maj
```

Points importants :

- `replay`, `diagnose`, `probe` et `probe-media` ne doivent pas appeler le filet IA de collecte ;
- `VEILLE_LLM` n'est pas envoyé dans une seconde qualification LLM ;
- les appels et coûts estimés sont journalisés ;
- une erreur IA ne doit pas faire échouer toute la collecte ;
- l'identité des items et incidents reste entièrement déterministe.

En GitHub Actions, le secret est injecté dans le workflow de collecte réelle, pas dans la CI de tests.

## 10. GitHub Actions

### CI

`.github/workflows/ci.yml` s'exécute sur les pull requests et sur `main`. Elle vérifie notamment :

- tests `pytest` ;
- golden de déduplication ;
- audits de couverture Sector avant/après requalification offline ;
- golden de qualification et garde de précision ;
- benchmark/politique du registre Sector ;
- syntaxe JavaScript du dashboard ;
- répétabilité ;
- contrôles structurels du snapshot.

La CI n'utilise pas le secret OpenAI de collecte.

### Collecte

`.github/workflows/collect.yml` exécute une `maj` quotidienne planifiée à `04:00 UTC` et permet aussi des lancements manuels (`maj`, `create`, `diagnose`, `replay`, `probe`, `probe-media`).

Pour les modes qui écrivent : collecte → rapport → audits qualité → contrôles → génération du dashboard → commit des changements `data/` et `assets/data/`.

Les workflows d'enrichissement et d'audit spécialisés présents dans `.github/workflows/` sont des outils ciblés ; ils ne remplacent pas la chaîne canonique de `collect.yml` et `ci.yml`.

## 11. Validation locale

Avant une modification de code ou de données :

```bash
python -m pytest tests/ -q
node --check assets/app.js
python -m cyberwatch test-repeat
python -m cyberwatch check --allow-uninitialized
```

Pour une modification touchant la qualification Sector :

```bash
python scripts/audit_sector_coverage.py --output ""
python scripts/evaluate_golden.py --details /tmp/golden.csv --json /tmp/golden.json
python scripts/evaluate_sector_registry.py --json /tmp/sector-registry.json
python scripts/check_sector_registry_policy.py --json /tmp/sector-registry.json
```

Ne pas lancer une collecte réelle simplement pour tester du code : `create` et `maj` accèdent au réseau, peuvent modifier les données canoniques et peuvent engager des appels IA si une clé est présente.

## 12. Dashboard

Le dashboard est statique :

- `index.html` : structure de la page ;
- `assets/app.js` : logique de chargement, filtres et rendu ;
- `assets/data/` : JSON générés depuis la base canonique.

Le filtre **Local** expose les informations spécifiques à Veille LLM : score cyberattaque, synthèse analytique et références documentaires. Ces informations restent masquées dans la vue générale pour conserver une lecture compacte.

## 13. Où modifier quoi ?

| Besoin | Fichier / zone |
|---|---|
| ajouter ou désactiver une source | `cyberwatch/sources.py` + collecteur si nécessaire |
| changer une taxonomie/règle | `cyberwatch/config.py`, `normalize.py`, `sector.py` |
| ajouter une preuve Sector | modules d'enrichissement / `sector_registry.py` |
| changer la déduplication | `dedup.py`, `incident_identity.py` + golden dédié |
| changer les colonnes canoniques | `model.py` + stockage/tests/migrations nécessaires |
| modifier le dashboard | `index.html`, `assets/app.js`, `assets/styles.css` |
| modifier la méthode | `METHODOLOGY.md` et, si nécessaire, `METHOD_ID` |
| modifier la CI / collecte | `.github/workflows/ci.yml`, `collect.yml` |

La règle générale est de **faire évoluer les mécanismes existants avant d'ajouter une nouvelle couche parallèle**. Le projet possède déjà des registres, files de revue, golden tests et audits pour absorber la plupart des améliorations sans créer une architecture supplémentaire.
