# Cyberwatch

Cyberwatch est un observatoire reproductible d'incidents cyber **publiquement documentés** en France et dans l'Océan Indien.

Le projet collecte plusieurs sources, normalise les événements, qualifie les champs utiles, déduplique les observations en incidents, contrôle la cohérence du snapshot puis publie un dashboard statique.

**Dashboard : https://ya7o.github.io/Cyberwatch/**

Version du package : `1.0.0`.

> Cyberwatch documente ce qui est publiquement observable. Il ne prétend pas recenser toutes les cyberattaques réelles.

## 1. Flux nominal

```text
Sources
  ↓
Collecte
  ↓
Normalisation / identification de l'organisation
  ↓
Qualification Threat / Sector / Location
  ↓
Déduplication en incidents
  ↓
Contrôles + hashes déterministes
  ↓
CSV canoniques
  ↓
JSON du dashboard / GitHub Pages
```

Documents de référence :

- `README.md` : comprendre et exploiter le projet ;
- `METHODOLOGY.md` : méthode normative et choix de conception ;
- `CLAUDE.md` : garde-fous techniques de modification ;
- `ARCHITECTURE_STATUS.md` : domaines actifs, domaines gelés et règle anti-complexité.

## 2. Principes de conception

Cyberwatch privilégie la **traçabilité et la reproductibilité** à la recherche d'une couverture artificiellement parfaite.

- mêmes entrées → mêmes identifiants et mêmes hashes ;
- une source défaillante est journalisée, pas transformée en faux succès ;
- une donnée insuffisamment prouvée reste `Inconnu` ;
- l'identité publiée reste reproductible et déterministe : le LLM peut challenger des candidats de rapprochement lors d'une collecte réelle, mais une décision LLM n'est appliquée qu'après validation par une policy déterministe et ne devient reproductible qu'une fois persistée dans le registre d'identité versionné (§5) ; `REPLAY` ne consulte jamais le LLM ;
- les CSV de `data/` sont canoniques, `assets/data/` est dérivé ;
- un rapprochement incertain reste à examiner plutôt que d'être fusionné silencieusement.

Le moteur technique est désormais considéré mature pour les enjeux actuels. Les nouveaux développements doivent prioriser la qualité des données, les sources et la valeur du dashboard. Voir `ARCHITECTURE_STATUS.md`.

## 3. Périmètre et sources actives

Le périmètre méthodologique couvre la France métropolitaine et plusieurs territoires de l'Océan Indien : La Réunion, Mayotte, Maurice, Madagascar, Seychelles et Comores.

Le pipeline publié repose actuellement sur cinq sources actives :

| Source | Rôle | Accès |
|---|---|---|
| `FRENCHBREACHES` | fuites de données en France | flux RSS |
| `BONJOURLAFUITE` | chronologie de fuites | parseur HTML dédié |
| `CYBERATTAQUE_ORG` | incidents/cyberattaques publiés | source paginée avec contenu |
| `RANSOMWARE_LIVE` | ransomware, groupe, pays et parfois secteur | API JSON |
| `VEILLE_LLM` | couverture analytique La Réunion + Mayotte | snapshot JSON versionné |

`VEILLE_LLM` est relu intégralement à chaque run. Son `score_cyberattaque` est
une information, jamais un seuil d'exclusion. La routine conserve les signaux
non démontrés comme `CANDIDATE`, mais seuls les dossiers `ACCEPTED` par preuve
cyber explicite entrent dans la base. Lorsqu'un incident existe aussi dans une
source directe, cette source analytique ne gonfle pas artificiellement le
nombre de corroborations éditoriales. Les anciennes tables ChatGPT globales de
FrenchBreaches et Cyberattaque.org sont archivées comme benchmarks et ne sont
plus lues en production.

D'autres sources peuvent rester présentes dans le référentiel lorsqu'elles sont volontairement inactives. Leur protocole et leur motif de désactivation sont conservés plutôt que masqués.

## 4. Architecture

L'orchestration principale est portée par `cyberwatch/runner.py` et la qualification canonique par `cyberwatch/qualification.py`.

Blocs principaux :

- `cyberwatch/collectors/` : adaptateurs de collecte ;
- `cyberwatch/sources.py` : référentiel exécutable des sources ;
- `cyberwatch/normalize.py` : normalisation ;
- `cyberwatch/qualification*.py`, `sector*.py` : qualification et provenance ;
- `cyberwatch/source_facts*.py` : faits structurés extraits des sources ;
- `cyberwatch/ai.py`, `llm_runtime.py` : filet LLM borné et télémétrie ;
- `cyberwatch/dedup.py`, `incident_identity.py` : regroupement et stabilité des incidents ;
- `cyberwatch/dedup_ai.py`, `duplicate_audit.py`, `org_identity.py` : filet LLM de déduplication (candidats, batch quotidien, registre d'identité, §5) ;
- `cyberwatch/store.py` : stockage atomique ;
- `cyberwatch/site.py` : données du dashboard ;
- `cyberwatch/quality.py` : contrôles de cohérence.

Les domaines Qualification, Identity, Dedup, LLM runtime, Incremental, Quality framework et Cold Reset sont **gelés fonctionnellement** : bug, régression, sécurité, coût réel ou besoin produit bloquant uniquement. Ils ne doivent plus recevoir de sophistication préventive.

## 5. Qualification et identité

Les valeurs structurées fournies par une source sont privilégiées. Les règles déterministes puis les référentiels complètent les valeurs manquantes. Un filet LLM peut intervenir pendant une vraie collecte lorsque les canaux autorisés le permettent.

Une valeur déjà connue n'est pas écrasée arbitrairement par le filet IA de qualification (§8), et l'identité (`Item_ID`, `Organisation_Key`, `Incident_ID`) reste hors de son périmètre. Le filet LLM de déduplication (ci-dessous) est un mécanisme distinct, avec ses propres garde-fous.

La qualification Sector est volontairement conservatrice : `Inconnu` signifie **preuve insuffisante selon la politique active**.

`data/items.csv` conserve les observations source par source. `data/incidents.csv` contient la vue dédupliquée utilisée par le dashboard. Les rapprochements flous ne sont pas appliqués silencieusement.

### Identité organisationnelle ≠ identité d'incident

Deux questions distinctes, jamais mélangées : « ces deux libellés désignent-ils la même
organisation victime ? » (identité **organisationnelle**) et « ces deux items décrivent-ils
le même événement ? » (identité **d'incident**). Une même organisation peut légitimement
porter plusieurs incidents distincts et non concomitants.

Le moteur déterministe (`normalize.organisation_key`, `organisation_aliases.csv`,
`org_identity.effective_organisation_key`) reste la première ligne et l'autorité pour
les deux. Un filet LLM optionnel (`cyberwatch/dedup_ai.py`) challenge, lors d'une MAJ
réelle, un petit nombre de candidats plausibles issus des items nouveaux ou rafraîchis
du jour contre le corpus historique — jamais toute la base contre elle-même, jamais plus
d'un appel LLM par MAJ. Il ne répond jamais qu'à la question organisationnelle de façon
actionnable : `same_organisation=SAME` avec confiance ≥ 0.95 et sans conflit avec un veto
déterministe fort peut proposer une équivalence, persistée dans
`data/organisation_identity_registry.csv` (registre dynamique, distinct de
`organisation_aliases.csv` qui reste le référentiel statique curé à la main). La question
d'incident (`same_incident`) est mesurée mais n'est **jamais** appliquée directement : la
fusion d'incident reste exclusivement décidée par `dedup.group_components`, y compris une
fois l'identité organisationnelle unifiée. Détails complets : `METHODOLOGY.md` §14.5.

## 6. Données

Données canoniques principales :

- `data/items.csv` : observations collectées ;
- `data/incidents.csv` : incidents dédupliqués ;
- `data/sources.csv` : référentiel des sources ;
- `data/run_sources.csv`, `data/run_log.csv` : historique des runs ;
- `data/snapshot.json` : provenance et hashes ;
- `data/source_facts.csv` : faits auxiliaires ;
- `data/ai_qualifications.csv`, `data/ai_usage.csv` : cache/provenance/coût LLM ;
- `data/organisation_sector_registry.csv`, `data/sector_enrichment_queue.csv` : registre Sector ;
- `data/organisation_sector_evidence.csv`, `data/organisation_sector_decisions.csv` : preuves par étape et décision finale Sector ;
- `data/qualification_provenance.csv` : décisions de qualification ;
- `data/organisation_identity_registry.csv` : équivalences d'identité organisationnelle validées (LLM ou manuelles), consultées par `effective_organisation_key` (§5) ;
- `data/dedup_ai_daily_usage.csv` : télémétrie du filet LLM de déduplication (candidats, décisions, coût, durée).

`assets/data/` est généré depuis les données canoniques pour le dashboard et ne doit pas être édité à la main.

```bash
python -m cyberwatch build-site
```

## 7. Commandes

Installation :

```bash
pip install -r requirements.txt
```

### Usage courant

| Commande | Usage |
|---|---|
| `python -m cyberwatch maj` | mettre à jour la base existante |
| `python -m cyberwatch create` | construire une base depuis zéro |
| `python -m cyberwatch replay` | reconstruire offline depuis les données locales |
| `python -m cyberwatch check` | contrôler la cohérence du snapshot |
| `python -m cyberwatch build-site` | régénérer les données du dashboard |
| `python -m cyberwatch report` | afficher le résumé Markdown du dernier run |

### Diagnostic

| Commande | Usage |
|---|---|
| `python -m cyberwatch diagnose` | sonder les sources sans publier |
| `python -m cyberwatch probe SOURCE_ID` | diagnostiquer une source précise |
| `python -m cyberwatch probe-media` | comparer les accès média disponibles |
| `python -m cyberwatch test-repeat` | vérifier le déterminisme |

Les autres commandes sont des outils de maintenance ou d'audit exceptionnels. Elles ne constituent pas la surface opérationnelle quotidienne.

`maj` utilise un chevauchement temporel pour récupérer les publications tardives ; `VEILLE_LLM` est relu en totalité.

## 8. IA et coûts

Le projet peut utiliser `OPENAI_API_KEY` pendant une vraie collecte pour compléter certains champs encore inconnus. Sans clé, le pipeline continue sans ce filet.

```bash
export OPENAI_API_KEY=sk-...
python -m cyberwatch maj
```

Invariants :

- `replay`, `diagnose`, `probe` et `probe-media` n'appellent pas le filet IA de collecte, dédup compris ;
- `VEILLE_LLM` n'est pas envoyé dans une seconde qualification LLM ;
- appels et coûts estimés sont journalisés ;
- une erreur IA ne fait pas échouer toute la collecte ;
- l'identité reste entièrement déterministe et reproductible — le LLM ne fait que proposer, une policy déterministe valide, seule la persistance rend une décision reproductible (§5).

Le secret OpenAI est injecté dans les workflows de collecte réelle, jamais dans la CI de développement.

Le filet LLM de déduplication (§5) suit les mêmes garanties, avec une contrainte
supplémentaire propre à `maj` : au plus un appel LLM par run, activé via
`DEDUP_AI_DAILY_ENABLED=1` (mis par `collect.yml` uniquement pour `maj`, jamais pour
`create`/`replay`/`diagnose`/`probe`/`probe-media`). Un rattrapage manuel de
l'historique déjà publié existe séparément : `python scripts/backfill_dedup_identity.py`
(plusieurs appels autorisés, jamais lancé automatiquement).

## 9. GitHub Actions

La surface opérationnelle est volontairement limitée à **trois workflows**.

### `ci.yml` — développement

Déclenché sur pull request et `main`. Il exécute :

- `python -m pytest tests/ -q` ;
- `node --check assets/app.js` ;
- `python -m cyberwatch check --allow-uninitialized`.

La CI n'utilise aucun secret de collecte.

### `collect.yml` — exploitation courante

Exécute automatiquement une `maj` quotidienne et permet manuellement : `maj`, `create`, `diagnose`, `replay`, `probe`, `probe-media`.

Pour les modes qui écrivent : collecte → contrôles → génération du dashboard → commit de `data/` et `assets/data/`.

`collect.yml` est le **seul workflow planifié qui écrit les données**.

### `cold-reset.yml` — opération exceptionnelle

Workflow exclusivement manuel de reconstruction complète. Il travaille dans un staging isolé, archive l'état précédent, exécute les différentes passes bornées, vérifie le résultat puis publie seulement si l'option `publish` est activée.

Le cold reset est gelé fonctionnellement : maintenance corrective uniquement.

Il n'existe plus de workflow de « reset rapide » parallèle. Les variantes de reconstruction doivent utiliser le chemin canonique plutôt que recréer une seconde orchestration.

## 10. Validation locale

Avant une modification de code :

```bash
python -m pytest tests/ -q
node --check assets/app.js
python -m cyberwatch check --allow-uninitialized
```

`python -m cyberwatch test-repeat` reste disponible lorsqu'une modification touche explicitement l'identité, la déduplication ou le déterminisme.

Les audits spécialisés sont lancés manuellement lorsqu'un chantier touche leur domaine. Ils ne sont pas des gates de développement génériques.

Ne pas lancer une collecte réelle simplement pour tester du code : `create` et `maj` accèdent au réseau, peuvent modifier les données canoniques et peuvent engager des appels IA si une clé est présente.

## 11. Dashboard

Le dashboard reste statique :

- `index.html` : structure ;
- `assets/app.js` : chargement, filtres et rendu ;
- `assets/data/` : JSON dérivés.

Le développement actif doit désormais privilégier la valeur utilisateur : lisibilité, recherche, navigation, compréhension des incidents et analyses exploitables.

## 12. Où modifier quoi ?

| Besoin | Fichier / zone |
|---|---|
| ajouter ou désactiver une source | `cyberwatch/sources.py` + collecteur si nécessaire |
| changer une taxonomie/règle | `cyberwatch/config.py`, `normalize.py`, `sector.py` |
| changer la déduplication | `dedup.py`, `incident_identity.py` + tests dédiés |
| changer le filet LLM de déduplication | `dedup_ai.py`, `duplicate_audit.py`, `org_identity.py` + `tests/fixtures/dedup_identity_cases.json` |
| changer les colonnes canoniques | `model.py` + stockage/tests/migration nécessaire |
| modifier le dashboard | `index.html`, `assets/app.js`, `assets/styles.css` |
| modifier la méthode | `METHODOLOGY.md` et, si nécessaire, `METHOD_ID` |
| modifier la CI / collecte | `.github/workflows/ci.yml`, `collect.yml`, exceptionnellement `cold-reset.yml` |

La règle générale est de **faire évoluer les mécanismes existants avant d'ajouter une nouvelle couche parallèle**. Une nouvelle abstraction transversale doit résoudre un problème observé et mesurable ; préparer une évolution hypothétique n'est plus une justification suffisante.
