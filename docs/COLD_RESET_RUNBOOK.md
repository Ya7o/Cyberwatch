# Reset total Cyberwatch

Le workflow `cold-reset.yml` porte deux intentions distinctes :

- `rebuild` : reconstruction à froid avec purge des caches/sorties dérivées prévues par le protocole historique ;
- `zero` : archive complète puis destruction de tout état métier actif avant reconstruction fraîche.

Le mode `zero` est le mode radical. Il sert à vérifier que le code actuel sait reconstruire Cyberwatch sans dépendre silencieusement des registres, caches, historiques, golden datasets ou données publiées de l'ancienne base.

## Invariants du mode `zero`

- `confirm_zero` doit valoir exactement `RESET` ;
- une archive complète `data/` + `assets/data/` est créée et relue avant toute purge ;
- l'inventaire et le SHA-256 de l'archive sont exportés ;
- `incident_id_registry.csv`, registres de qualification, caches LLM, historiques de runs, baselines, golden datasets, états incrémentaux et données dashboard sont supprimés du staging ;
- les alias d'organisation nécessaires au bootstrap Python sont conservés comme référentiel statique, sans préserver les registres d'identité calculés ;
- seuls les référentiels statiques explicitement allowlistés par `cyberwatch.zero_reset` survivent à la purge ;
- `python -m cyberwatch.zero_reset verify` doit retourner `ZERO` avant toute reconstruction ;
- la reconstruction ne lit jamais l'archive ; celle-ci est uniquement un mécanisme de rollback/audit ;
- `publish=false` est la valeur par défaut ; aucune donnée canonique n'est remplacée pendant un dry-run ;
- lors d'un `zero` publié, un tag Git `archive/pre-zero-<run>-<attempt>` fige le commit exact précédant la remise à zéro ;
- la première reconstruction fraîche produit la nouvelle `post_reset_baseline.json`.

## Référentiels conservés

La conservation est une allowlist, pas une blacklist. Actuellement seuls :

- `data/organisation_aliases.csv` ;
- `data/sector_auto_policy.json` ;
- `data/territorial_identities.csv`.

Ces fichiers décrivent des règles/référentiels statiques nécessaires au domaine ou au bootstrap du programme ; ils ne constituent pas l'état d'une collecte. Ajouter un nouveau survivant exige une modification explicite de l'allowlist et des tests.

## Séquence recommandée

### 1. Dry-run radical

Déclencher `RESET TOTAL` avec :

- `reset_mode=zero` ;
- `confirm_zero=RESET` ;
- fenêtre `start` souhaitée ;
- `publish=false`.

Le workflow exécute :

1. préflight offline ;
2. baseline et manifeste avant ;
3. inventaire complet ;
4. archive certifiée ;
5. copie du dépôt vers staging isolé ;
6. purge radicale du staging ;
7. certification `ZERO` ;
8. reconstruction déterministe ;
9. qualification ;
10. passes sémantiques ;
11. SourceFacts ;
12. enrichissement organisations ;
13. suite de tests, syntaxe des runtimes frontend et `cyberwatch check` ;
14. audit avant/après ;
15. génération de la nouvelle baseline ;
16. export de l'archive et de tous les diagnostics.

### 2. Go / No-Go

Le run est publiable uniquement si :

- la purge a été certifiée `ZERO` ;
- la reconstruction aboutit ;
- les tests passent ;
- le dashboard est générable ;
- `cyberwatch check` passe ;
- l'audit post-reset ne contient pas d'anomalie bloquante.

Les écarts de volumes/IDs par rapport à l'ancienne base sont des informations à examiner, pas une raison automatique de restaurer l'ancien état : l'objectif du mode `zero` est précisément de tester la reconstruction fraîche.

### 3. Publication

Relancer avec les mêmes paramètres et `publish=true`.

Avant le remplacement des données, le workflow crée le tag Git d'archive pré-zero. Ensuite seulement, `data/` et `assets/data/` sont remplacés par le staging certifié et commités.

## Rollback

Deux mécanismes indépendants sont disponibles :

1. le tag Git `archive/pre-zero-*`, qui pointe vers le commit complet antérieur ;
2. l'artifact `cyberwatch-before-reset.tgz`, conservé 30 jours et accompagné de son SHA-256, inventaire et manifeste.

L'archive ne doit jamais être réinjectée automatiquement dans une reconstruction `zero`.

## Commandes locales de certification

```bash
python -m cyberwatch.zero_reset inventory --output /tmp/zero-before.json
python -m cyberwatch.zero_reset archive --output /tmp/cyberwatch-before-reset.tgz --report /tmp/archive.json
python -m cyberwatch.zero_reset purge --root /tmp/cyberwatch-reset --output /tmp/purge.json
python -m cyberwatch.zero_reset verify --root /tmp/cyberwatch-reset --output /tmp/zero-state.json
```

`verify` retourne un code non nul dès qu'un fichier d'état non allowlisté survit.
