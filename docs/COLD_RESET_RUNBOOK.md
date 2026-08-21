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
- seuls les référentiels statiques explicitement allowlistés par `cyberwatch.zero_reset` survivent à la purge ; aucun registre d'identité calculé n'est préservé ;
- `python -m cyberwatch.zero_reset verify` doit retourner `ZERO` : rien d'historique n'a survécu ;
- `python -m cyberwatch.zero_reset validate-bootstrap` doit retourner `READY` : le nécessaire est là. Cette garde s'exécute **avant** la reconstruction, pour qu'un référentiel manquant coûte une seconde et non une reconstruction complète avec son budget LLM ;
- la reconstruction ne lit jamais l'archive ; celle-ci est uniquement un mécanisme de rollback/audit ;
- `publish=false` est la valeur par défaut ; aucune donnée canonique n'est remplacée pendant un dry-run ;
- lors d'un `zero` publié, un tag Git `archive/pre-zero-<run>-<attempt>` fige le commit exact précédant la remise à zéro ;
- la première reconstruction fraîche produit la nouvelle `post_reset_baseline.json`.

## Référentiels conservés

La conservation est une allowlist, pas une blacklist. Un fichier n'y entre que s'il réunit trois conditions : aucun writer dans le dépôt (le code ne sait pas le recréer), aucune identité ni historique de collecte à l'intérieur, et une dépendance réelle et démontrée du bootstrap ou d'une règle métier.

| Fichier | Pourquoi il survit |
|---|---|
| `data/organisation_aliases.csv` | lu à l'import de `cyberwatch.normalize` (`ORGANISATION_ALIASES`) : sans lui, aucun module ne s'importe |
| `data/territorial_identities.csv` | lu à l'import de `cyberwatch.org_identity` (`TERRITORIAL_IDENTITIES`) : même contrainte |
| `data/sector_auto_policy.json` | politique d'activation des canaux Sector. Absent, `sector_registry` retombe sur `DEFAULT_POLICY`, **plus permissif** que la politique voulue : une purge changerait silencieusement la règle métier |
| `data/enrichment_reference.csv` | référentiel manuel `Organisation_Key -> Secteur/Localisation/Périmètre`. Aucun writer, aucun identifiant d'item ou d'incident, et seul canal Sector activé par la politique ci-dessus : purgé, la qualification Sector perd sa source de vérité sans moyen de la reconstruire |

Ajouter un survivant exige une modification explicite de l'allowlist, sa justification ici, et des tests. `tests/test_zero_bootstrap.py` verrouille l'équivalence entre ce qui survit, ce qui est requis (`REQUIRED_BOOTSTRAP_PATHS`) et ce que `cold_reset` considère comme référentiel de bootstrap.

## Gates de qualité et génération zéro

Une base reconstruite depuis zéro est une **nouvelle génération** : elle ne conserve pas les `Item_ID` ni les `Incident_ID` antérieurs, et les corpus de revue manuelle (`data/golden/`) sont détruits avec le reste de l'état.

Les gates sont donc répartis en deux familles.

Obligatoires en mode `zero`, sans exception :

- intégrité structurelle et schémas (`cyberwatch check`) ;
- base non vide (`items > 0`, `incidents > 0`) ;
- absence d'`Item_ID` / `Incident_ID` dupliqués ;
- dernier run `OK`, aucune source en `FAIL` ;
- qualification et déduplication cohérentes ;
- dashboard générable (`build-site` puis `check`).

Inertes lorsque leur sujet n'existe pas dans la génération courante, intégralement appliqués dès qu'il existe :

- contrats du corpus golden (`tests/test_dedup_golden_*`, `tests/test_golden_*`) : ils vérifient un corpus de revue manuelle, qui se reconstitue par revue et non par reconstruction ;
- régressions dedup ancrées sur des items historiques (`tests/test_dedup_golden_v2_regressions.py`) : FrenchBreaches n'expose qu'environ 28 jours, une reconstruction ne retrouve donc pas nécessairement l'article d'ancrage.

Aucun test n'est désactivé : chacun porte une condition explicite et redevient bloquant sur la base canonique, donc en CI sur `main`.

Diagnostics, jamais bloquants : comparaison des volumes et de la couverture à l'ancienne base, churn d'identifiants. `cyberwatch.reset_baseline` les publie en `warnings` et `deltas`, jamais en `blockers`.

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
8. validation des référentiels de bootstrap (`READY`) ;
9. reconstruction déterministe ;
10. qualification ;
11. passes sémantiques ;
12. SourceFacts ;
13. enrichissement organisations ;
14. suite de tests, syntaxe des runtimes frontend et `cyberwatch check` ;
15. audit avant/après ;
16. génération de la nouvelle baseline ;
17. export de l'archive et de tous les diagnostics.

### 2. Go / No-Go

Le run est publiable uniquement si :

- la purge a été certifiée `ZERO` ;
- le bootstrap a été certifié `READY` ;
- la reconstruction aboutit ;
- les tests passent ;
- le dashboard est générable ;
- `cyberwatch check` passe ;
- l'audit post-reset ne contient pas d'anomalie bloquante.

Les écarts de volumes/IDs par rapport à l'ancienne base sont des informations à examiner, pas une raison automatique de restaurer l'ancien état : l'objectif du mode `zero` est précisément de tester la reconstruction fraîche.

### 3. Publication

Relancer avec les mêmes paramètres et `publish=true`.

Avant le remplacement des données, le workflow crée le tag Git d'archive pré-zero. Ensuite seulement, `data/` et `assets/data/` sont remplacés par le staging certifié et commités.

## Historique des resets publiés

| Date | Run | Mode | Résultat |
|---|---|---|---|
| 2026-08-21 | [32516336880](https://github.com/Ya7o/Cyberwatch/actions/runs/32516336880) | `zero` publié | génération 1 : 1051 items, 871 incidents, 5 sources OK, audit `GO`, tag `archive/pre-zero-32516336880-1` |

Deux bugs n'ont pu être découverts qu'à l'exécution réelle et sont corrigés :

- le manifeste final exigeait un état d'identité que le mode `zero` purge à
  dessein, ce qui faisait échouer le run **après** toute la reconstruction ;
- `git tag -a` échouait en « Committer identity unknown », l'identité git n'étant
  posée que dans l'étape de publication, qui s'exécute après le figeage.

Le second est instructif : l'étape n'existe que sous `publish=true`, donc aucun
dry-run ne pouvait l'exercer. **Un dry-run vert ne couvre pas le chemin de
publication.** Le garde-fou a néanmoins joué son rôle — le tag précédant l'écriture
des données, son échec a bloqué la publication et `main` est resté intact.

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
