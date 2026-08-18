# Cyberwatch

Observatoire déterministe d'incidents cyber publiquement documentés en France
et dans l'Océan Indien : **collecte → normalisation → qualification offline
(+ filet de rattrapage LLM optionnel) → déduplication → hashes →
snapshot/dashboard**. Dashboard : https://ya7o.github.io/Cyberwatch/

Le projet liste des incidents publiquement documentés ; il ne prétend pas
recenser toutes les cyberattaques réelles. `METHODOLOGY.md` est la référence
normative (numérotée §1…) — ce fichier n'en est qu'un résumé opérationnel.

## Principes à ne jamais violer

- **Déterminisme** : mêmes entrées → mêmes `Item_ID`/`Incident_ID`/hashes,
  quel que soit l'ordre de traitement (`identity.py`, testé par
  `test-repeat`). Aucune horloge, aucun aléatoire, aucun ordre de dict non
  trié dans un calcul d'identité ou de hash.
- **Transparence > faux zéro/faux OK** : un statut `OK` avec 0 item doit être
  un zéro *vérifié* (`zero_is_trusted`), jamais une couverture ratée
  déguisée. Une source qui ne peut pas atteindre la borne de fenêtre
  demandée est `PARTIAL`, jamais forcée à `OK` — sauf exception documentée et
  vérifiée (voir `status_override` plus bas).
- **Aucune source ne peut faire échouer tout un run** : toute exception
  d'un collecteur est convertie en statut `FAIL` documenté ; les autres
  sources continuent.
- **Jamais de panne silencieuse qui fabrique une donnée** : absence de clé,
  erreur réseau, budget épuisé → le champ concerné reste `Inconnu`, jamais
  une valeur inventée.
- **L'IA ne décide jamais l'identité** : `Item_ID`/`Organisation_Key`/
  `Incident_ID` ne dépendent jamais de Threat/Sector/Location, IA ou pas.

## Architecture (`cyberwatch/`)

Pipeline dans l'ordre d'exécution, orchestré par `runner.py::execute()` :

1. **Collecte** — `collectors/` : un module par famille de source, interface
   commune dans `collectors/base.py` (`Collector.collect(client, spec,
   window) -> CollectResult`). `SourceSpec` (déclaré dans `sources.py`)
   pointe vers un `collector` par nom (registre dans `collectors/__init__.py`).
   - `feed.py` : RSS/Atom, une seule page, pas de pagination native.
   - `wordpress.py` : API REST `/wp-json/wp/v2/posts`, pagination réelle,
     couverture mesurée (pas estimée) — chemin le plus fiable du projet.
   - `jsonld.py` : JSON-LD puis repli balises `<time>` puis dates en texte
     brut à proximité d'un lien.
   - `bonjourlafuite.py` : parseur HTML dédié, protocole `status_override`
     propre (OK/FAIL, pas de notion de borne — cf. plus bas).
   - `ransomware_live.py`, `veillellm.py`, `mediawatch.py`, `newsrss.py`,
     `cyberattaque_org.py`, `autodetect.py` (choisit wordpress → jsonld →
     feed selon ce qui répond).
2. **Normalisation** — `normalize.py` (dates, organisation, classification
   Threat/Sector/Location déterministe par mots-clés/règles).
3. **Backfill** — `enrichment.py` : référentiel `data/enrichment_reference.csv`
   appliqué avant toute classification par défaut.
4. **Filet de rattrapage LLM (optionnel)** — `ai.py` (voir section dédiée).
5. **Déduplication** — `dedup.py`/`identity.py` : regroupe les items en
   incidents par composantes connexes sur `Organisation_Key` + fenêtre
   temporelle.
6. **Export** — `store.py` (CSV canoniques dans `data/`), `site.py` (JSON
   pour le dashboard dans `assets/data/`).

Autres modules notables :
- `status.py` : modèle `Status/Coverage/Reason` (jamais un mot-valise unique)
  + `SourceOutcome` (une ligne `RUN_SOURCES` par source et par run).
- `qualification.py` : contrôles qualité offline post-collecte.
- `watchlists.py` : entités/organisations connues, territoires.
- `http.py` : client HTTP avec budget (`MAX_REQUESTS_PER_RUN=800`,
  `MAX_SECONDS_PER_RUN=45min`, par source `MAX_REQUESTS_PER_SOURCE=60`,
  `MAX_PAGES_PER_SOURCE=50`), respect robots.txt.
- `config.py` : taxonomies fermées (`THREATS`, `SECTORS`, `LOCATIONS`),
  sentinelles `Inconnu` (`THREAT_UNKNOWN`, `SECTOR_UNKNOWN`, `LOC_INCONNU`),
  couches (`LAYER_CORE`, `LAYER_LOCAL_MEDIA`, `LAYER_ENTITY_WATCH`,
  `LAYER_REGIONAL_WATCH`), `METHOD_ID` (bump obligatoire si la méthode
  produisant le snapshot change réellement).

## Données (`data/`, canonique) et sorties (`assets/data/`, dérivées)

CSV canoniques, colonnes figées dans `model.py` (`*_COLUMNS`), écriture
atomique (`store.write_csv` : fichier temp + `os.replace`) :

- `items.csv` : items collectés bruts (jamais dédupliqués).
- `incidents.csv` : incidents dédupliqués — alimente le dashboard.
- `sources.csv` : référentiel des sources (régénéré à chaque run).
- `run_sources.csv` / `run_log.csv` : journal de collecte, append-only.
- `entity_watch.csv` : état de veille par entité surveillée.
- `snapshot.json` : provenance + hashes du snapshot courant.
- `baseline.json` : référence locale facultative (`cmd baseline`).
- `quality_baseline.json` : plancher de qualité, régénéré manuellement
  (`scripts/audit_data_quality.py`), jamais un gate CI obligatoire.
- `ai_qualifications.csv` / `ai_usage.csv` : cache/provenance et usage du
  filet de rattrapage LLM (voir plus bas).

`assets/data/incidents.json` / `assets/data/status.json` sont **dérivés**,
régénérés par `python -m cyberwatch build-site` — ne jamais les éditer à la
main, toujours régénérer depuis les CSV canoniques.

## Filet de rattrapage LLM (`cyberwatch/ai.py`)

Complète **uniquement** Threat/Sector/Location encore `Inconnu` après tout le
déterministe (règles + backfill) — jamais une valeur déjà connue, jamais
l'identité. Détail complet : `METHODOLOGY.md` §11.

- Secret GitHub `Cyberwatchapi` → mappé sur la variable d'env standard
  `OPENAI_API_KEY` **uniquement** dans les workflows (`collect.yml`,
  `initialize.yml`, étape de collecte réelle seulement). Le code Python ne
  lit **jamais** `Cyberwatchapi`, seulement `os.getenv("OPENAI_API_KEY")`.
  `ci.yml` ne reçoit jamais ce secret.
- Modèle : alias flottant `gpt-5-nano` (voir commentaire daté dans `ai.py` —
  un snapshot daté deviné avait été rejeté par l'API réelle : HTTP 400
  `model_not_found`). `reasoning: {"effort": "minimal"}` est **obligatoire**
  dans la requête Responses API — sans ça, un modèle de raisonnement peut
  consommer tout `max_output_tokens` en jetons de raisonnement internes et
  renvoyer un 200 sans aucun message (`status: "incomplete"`), bug réel déjà
  rencontré et corrigé (commit `41837b4`).
- `REPLAY`/`diagnose`/`probe`/`probe-media` **n'appellent jamais** l'API,
  même si `OPENAI_API_KEY` est présente — structurel : `ai_state` n'est créé
  que dans la branche réseau de `runner.execute()`.
- Budget par défaut : `AI_MAX_CALLS_PER_RUN=2000`,
  `AI_MAX_ESTIMATED_COST_USD_PER_RUN=1.00` — un plafond atteint arrête les
  nouveaux appels sans casser le run (`Status=BUDGET_STOP`).
- Panne réseau/format/clé absente → jamais de crash, champs laissés
  `Inconnu`, `Status` journalisé (`DISABLED`/`API_ERROR`/`DEGRADED`/
  `BUDGET_STOP`/`OK`) dans `ai_usage.csv`.

**⚠️ Ne jamais déclencher `collect.yml` (mode `create`/`maj`) ou
`initialize.yml` sans un feu vert explicite de l'utilisateur** — ces deux
workflows injectent le vrai secret OpenAI et incurrent un coût réel. Pour
investiguer une source sans dépenser d'appel LLM, utiliser `mode=diagnose`,
`mode=probe` ou `mode=probe-media` (confirmé structurellement sans appel
IA) ou `mode=replay` — jamais `create`/`maj`.

## Sources actives (5, volontairement réduit)

FrenchBreaches (RSS, plafonné à 100 entrées sans pagination — voir
`feed_has_no_pagination` ci-dessous), BonjourLaFuite (HTML dédié),
Cyberattaque.org (WordPress, `include_content`), Ransomware.live (API,
Threat/Location déjà structurés — jamais requalifiés par l'IA), Veille LLM
(snapshot JSON versionné `sources/veillellm/…json`, relu en entier à chaque
run, tous les dossiers valides importés quel que soit leur score — le score
est affichable, jamais un filtre d'exclusion). Affiché comme
**veillellmReYt** au dashboard (ID interne `VEILLE_LLM` inchangé), et exclu
d'une seconde passe LLM (`skip_ai_qualification`) car déjà structuré par
un LLM en amont.

Les anciens collecteurs presse Mayotte (Kwezi, Mayotte Hebdo, Journal de
Mayotte, Mayotte FM) ont été retirés : trop de faux positifs.

### `status_override` / `feed_has_no_pagination` — sources structurellement bornées

Deux échappatoires existent pour des sources dont la fenêtre demandée est
structurellement hors de portée (jamais un contournement générique) :

- **BonjourLaFuite** (`collectors/bonjourlafuite.py`) : protocole OK/FAIL
  propre, sans notion de borne/couverture.
- **`feed_has_no_pagination`** (param de `SourceSpec`, posé uniquement sur
  FrenchBreaches) : le flux RSS ne pagine pas et sa profondeur recule avec
  le temps (atteignait `2026-01-01` le 14/08, seulement `2026-07-18` le
  15/08) — vérifié par `probe` (pas d'API REST, pas de pagination `?page=`/
  `?paged=`, pas de JSON-LD). La source est `OK` dès que toutes les entrées
  offertes par le flux sont captées.
  **Ne jamais poser ce flag sans avoir vérifié via `probe` qu'aucun autre
  chemin d'accès n'existe** — sinon on masque une vraie régression de
  couverture.

## Commandes CLI (`python -m cyberwatch <commande>`)

| Commande | Écrit des données ? | Réseau ? | Appelle l'IA ? |
|---|---|---|---|
| `create [--start] [--layers]` | ✅ | ✅ | ✅ si clé présente |
| `maj [--layers]` | ✅ | ✅ | ✅ si clé présente |
| `replay` | snapshot local | ❌ | **jamais** |
| `diagnose [--start] [--layers]` | ❌ | ✅ | **jamais** |
| `probe <SOURCE_ID> [--start]` | ❌ | ✅ | **jamais** |
| `probe-media [--only]` | ❌ | ✅ | **jamais** |
| `check [--allow-uninitialized]` | ❌ | ❌ | — |
| `test-repeat` | ❌ | ❌ | — |
| `baseline` | `data/baseline.json` | ❌ | — |
| `build-site` | `assets/data/*.json` | ❌ | — |
| `report` | ❌ (stdout Markdown) | ❌ | — |

`maj` utilise une fenêtre glissante de 21 jours (chevauchement pour
rattraper les ajouts tardifs) et relit toujours le snapshot Veille LLM
complet. `create` sans `--start` démarre au 1er janvier de l'année de
`--as-of`.

**Politique de publication (`runner._persist`)** : `data/items.csv`/
`incidents.csv`/`snapshot.json` ne sont mis à jour que si
`report.overall == OK` (toutes les sources actives OK) — sinon le run
retourne l'exit code 1 et rien n'est publié, même les sources qui ont
réussi. `run_log.csv`/`run_sources.csv` eux sont toujours écrits en
mémoire mais ne sont commit/push que si l'étape CI/CD suivante ("Publier")
s'exécute — ce qui n'arrive pas si la commande a retourné 1.

## Tests et validation

```bash
pip install -r requirements.txt
python -m pytest tests/ -q          # offline, mocké, ~430 tests
node --check assets/app.js          # runtime JS unique du dashboard
python -m cyberwatch check --allow-uninitialized
python -m cyberwatch test-repeat    # déterminisme, ordre A vs ordre aléatoire
```

CI (`ci.yml`, sur push/PR vers `main`) reste volontairement légère : pytest +
syntaxe JS + `test-repeat` + `check --allow-uninitialized`. Aucun secret n'y
est injecté. Les audits spécialisés (`scripts/audit_data_quality.py --check-regression`)
restent manuels, jamais un gate obligatoire.

**Ne jamais lancer `python -m cyberwatch create`/`maj`/`replay` en local sans
isoler `store.*_CSV`** (monkeypatch vers `tmp_path`, cf. les fixtures
`_isolate_store`/`_isolate_ai_csvs` dans `tests/`) — une exécution locale
sans isolation écrase la provenance réelle de `data/snapshot.json` avec des
métadonnées locales factices. Si ça arrive : `git checkout -- data/ assets/data/`
pour revenir à l'état publié, jamais un commit par-dessus.

## Dashboard (`index.html`, `assets/`)

- `assets/app.js` est le **seul runtime** du dashboard : un chargement de
  `incidents.json`/`status.json`, un état, un pipeline filtre → rendu. Il n'y
  a plus de couche legacy, de `document.write` ni de `MutationObserver` pour
  compléter les lignes après rendu.
- Filtres : recherche organisation accent/casse insensitive, Océan Indien,
  Réunion / Mayotte, source et réinitialisation. Aucun filtre métier ne
  repose sur une whitelist d'organisations codée en dur.
- Les lignes d'incident restent compactes. Le bouton **Détails** ouvre une
  seconde ligne pleine largeur avec synthèse, faits par source, vecteur,
  déroulé, volumes, vulnérabilités, données exposées groupées, impact,
  évolution et références disponibles. La criticité des données est calculée
  déterministement pendant ce rendu.
- Section **État des sources** (`#fiabilite`) : vue globale compacte
  (`#sources-list`, nom + LED de statut seulement, aucune métrique) +
  détail accessible dessous (`<details class="sources-detail">`,
  `#sources-detail-table`), mêmes 6 champs pour toute source sans
  traitement spécial (Source, Statut, Dernier item, Organisation, Items
  vus, Items dans la fenêtre).
- `latest_item_org`/`latest_item` (dans `status.json`, calculés par
  `runner.py::run_source`) : dérivés des items réellement collectés, tri
  déterministe `(Published_Date, Item_ID)` en cas d'égalité — jamais un
  cas spécial par source.

## Workflows GitHub Actions (`.github/workflows/`)

- `ci.yml` : push/PR sur `main`, tests offline uniquement, aucun secret.
- `collect.yml` : `workflow_dispatch` (+ cron quotidien 08h La Réunion),
  mode au choix (`maj` par défaut, `create`, `diagnose`, `replay`, `probe`,
  `probe-media`). Secret `OPENAI_API_KEY` injecté sur l'étape "Collecter"
  uniquement.
- `initialize.yml` : `workflow_dispatch`, rebuild complet (`create` +
  `check` + `test-repeat` + `baseline` + `build-site` + `check` final),
  même secret sur l'étape "CREATE contrôlé".

Déclenchement via l'outil `mcp__github__actions_run_trigger`
(`method: run_workflow`, `workflow_id: "collect.yml"` ou
`"initialize.yml"`, `ref: "main"`, `inputs: {...}`).

## Style / conventions du dépôt

- Commentaires et docstrings en français, exclusivement sur le *pourquoi*
  (contrainte cachée, invariant, bug réel déjà rencontré) — jamais sur le
  quoi.
- Pas de branches/PR : tout se pousse directement sur `main` (convention du
  dépôt, pas une règle Claude Code générique).
- Dépendances volontairement minimales (`requests`, `feedparser`, `pytest`)
  — pas de SDK pour l'API OpenAI, appel direct via `requests`.
- Toute nouvelle colonne CSV s'ajoute en fin de liste dans `model.py`
  (`*_COLUMNS`) pour rester rétro-compatible : `store.read_csv` tolère les
  anciennes lignes sans la nouvelle colonne (`row.get(col, "")`).
