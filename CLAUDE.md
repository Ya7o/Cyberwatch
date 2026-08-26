# Cyberwatch — garde-fous de développement

Cyberwatch est un observatoire déterministe d'incidents cyber publiquement documentés :

```text
collecte -> normalisation -> qualification -> déduplication -> contrôles -> snapshot -> dashboard
```

`METHODOLOGY.md` est la référence normative. `ARCHITECTURE_STATUS.md` définit les domaines actifs et gelés.

## Principes non négociables

- **Déterminisme** : mêmes entrées -> mêmes `Item_ID`, `Organisation_Key`, `Incident_ID` et hashes.
- **Transparence** : une source en échec ou partielle ne doit jamais être transformée en faux succès.
- **Pas de donnée inventée** : absence de preuve, panne réseau, budget ou clé manquante -> `Inconnu` ou statut explicite.
  - **Exception documentée (Sector)** : à la différence des autres champs, lorsque l'activité de l'organisation victime est connue mais qu'aucun secteur de la taxonomie ne lui correspond exactement (association, culte, syndicat, parti politique...), le moteur choisit le secteur le plus proche plutôt que `Inconnu` (décision explicite du 2026-08-26). Cette exception est portée par les 3 canaux LLM Secteur (`source_facts_ai.py`, `domain_page_sector_llm.py`, `organisation_sector_llm.py`) et par l'arbitrage de `organisation_sector.py`, qui applique désormais toute proposition, même faible/LLM seule, comme `Item.Sector`. Elle ne s'applique qu'à `Sector` : `Threat`, `Location`, l'identité et la déduplication restent strictement soumis au principe général ci-dessus.
- **Isolation des sources** : une source défaillante ne doit pas faire tomber silencieusement les autres.
- **Identité hors LLM** : aucun LLM ne décide l'identité d'un item, d'une organisation ou d'un incident.
- **Données canoniques** : `data/` est canonique ; `assets/data/` est dérivé et doit être régénéré.

## Gouvernance anti-complexité

Le moteur est considéré mature pour les enjeux actuels. Les domaines Qualification, Identity, Dedup, LLM runtime, Incremental, Quality framework et Cold Reset sont **FROZEN**.

Un domaine gelé ne doit être rouvert que pour :

- bug reproductible ;
- régression mesurée ;
- perte de déterminisme, de traçabilité ou de sécurité ;
- coût opérationnel significatif constaté ;
- changement externe imposé ;
- fonctionnalité produit prioritaire réellement bloquée.

Une amélioration de propreté, d'élégance, de généricité, de préparation future ou d'observabilité ne suffit plus.

Avant d'ajouter un module transversal, une `policy`, un `runtime`, un `contract`, une `baseline`, un nouveau cache ou une couche d'observabilité, vérifier :

1. quel problème réel et observé est résolu ;
2. quelle métrique, panne, régression ou fonctionnalité le démontre ;
3. pourquoi le mécanisme existant ne peut pas absorber le changement ;
4. quel coût de maintenance supplémentaire est créé.

**Faire évoluer les mécanismes existants avant d'ajouter une couche parallèle.**

## Surface GitHub Actions

La surface canonique est volontairement limitée à trois workflows :

- `.github/workflows/ci.yml` : développement ;
- `.github/workflows/collect.yml` : collecte et opérations courantes ;
- `.github/workflows/cold-reset.yml` : reset total exceptionnel.

`collect.yml` est le seul workflow planifié de données. `cold-reset.yml` est exclusivement manuel.

Ne pas créer un quatrième workflow sans besoin opérationnel distinct impossible à couvrir par ces trois chemins.

## Collecte et LLM

`create` et `maj` peuvent accéder au réseau, modifier les données canoniques et engager des appels LLM si une clé est disponible.

**Ne jamais déclencher une collecte réelle avec coût LLM simplement pour tester ou investiguer.**

Pour le diagnostic utiliser en priorité :

- `python -m cyberwatch diagnose` ;
- `python -m cyberwatch probe SOURCE_ID` ;
- `python -m cyberwatch probe-media` ;
- `python -m cyberwatch replay` pour une reconstruction offline.

`replay`, `diagnose`, `probe` et `probe-media` ne doivent pas appeler le filet LLM de collecte.

Le LLM complète uniquement les champs métier autorisés restant inconnus. Il ne doit pas écraser arbitrairement une preuve plus forte ni participer au calcul d'identité.

Les budgets et erreurs LLM doivent rester bornés et traçables ; une erreur LLM ne doit pas faire échouer toute la collecte.

## Qualification

La qualification est conservatrice. `Inconnu`, `REVIEW` ou `CONFLICT` sont des résultats valides lorsqu'une preuve suffisante n'existe pas.

Les changements de qualification doivent préserver :

- la précédence explicite des preuves ;
- l'arbitrage déterministe ;
- la provenance ;
- l'indépendance vis-à-vis de l'ordre des candidats ;
- la parité entre chemin canonique et chemin incrémental lorsqu'il est utilisé.

Ne pas rouvrir le chantier Qualification pour une simple hausse marginale de couverture ou une nouvelle abstraction.

## Déduplication et identité

La déduplication reste prudente. Une fusion incertaine vaut moins qu'un doublon à examiner.

Toute modification touchant l'identité ou la déduplication doit démontrer un cas métier réel ou une régression et doit exécuter les tests dédiés, notamment le contrôle de répétabilité lorsque pertinent.

## Données

Principaux fichiers canoniques :

- `data/items.csv` ;
- `data/incidents.csv` ;
- `data/sources.csv` ;
- `data/run_sources.csv` ;
- `data/run_log.csv` ;
- `data/snapshot.json` ;
- `data/source_facts.csv` ;
- `data/ai_qualifications.csv` / `data/ai_usage.csv` ;
- `data/organisation_sector_registry.csv` ;
- `data/qualification_provenance.csv`.

Ne jamais éditer manuellement `assets/data/` pour corriger une donnée : corriger la source canonique ou le générateur puis exécuter `python -m cyberwatch build-site`.

## Validation de développement

Validation générique :

```bash
python -m pytest tests/ -q
node --check assets/app.js
python -m cyberwatch check --allow-uninitialized
```

Les audits spécialisés restent manuels et ne doivent être lancés que lorsqu'un changement touche réellement leur domaine.

`python -m cyberwatch test-repeat` est requis lorsqu'une modification peut affecter identité, déduplication ou déterminisme.

Ne pas lancer `create` ou `maj` comme test générique.

## Priorités de développement

Ordre par défaut :

1. fiabilité et couverture des sources ;
2. qualité réelle des données ;
3. valeur et lisibilité du dashboard ;
4. analyses utiles ;
5. maintenance corrective du moteur.

La sophistication interne n'est plus une finalité de développement.
