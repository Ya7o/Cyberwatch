# Méthodologie exécutable OBS-FR-OI

**`Method_ID : OBS-FR-OI-SIMPLE-SOURCING-4`**
**Périmètre :** France métropolitaine, La Réunion, Mayotte, Maurice, Madagascar, Seychelles, Comores.

## Pipeline canonique de qualification

Chaque snapshot, CREATE, MAJ, REPLAY ou réparation locale, passe par le même
traitement offline : intégrité des items, enrichissement déterministe,
reconstruction des incidents, contrôles pré-export, hashes et persistance
atomique. Les workflows GitHub n'ajoutent aucune transformation métier.

Une étape supplémentaire existe désormais **avant** ce tronc commun offline,
uniquement pendant une collecte réseau réelle (`create`/`maj`, jamais
`replay`) : un filet de rattrapage LLM peut compléter Threat/Sector/Location
encore `Inconnu` après les règles déterministes. Voir §11.

`data/quality_baseline.json` versionne les métriques de qualité, comparées par
`python scripts/audit_data_quality.py --check-regression` : hausse d'inconnus,
candidat de menace résoluble conservé inconnu, suppression inexpliquée. Cet
audit est un outil d'investigation manuelle, pas un gate obligatoire de CI ;
toute mise à jour de la référence reste visible dans Git.

## Couverture locale Réunion / Mayotte

La couverture locale est fournie par le snapshot versionné **Veille LLM**
(`sources/veillellm/cyberattaques_reunion_mayotte_2026.json`). Il est relu en
totalité à chaque run afin qu'une découverte historique tardive soit intégrée
sans dépendre de la fenêtre réseau de MAJ. Tous les dossiers valides sont
matérialisés dans `ITEMS`, quel que soit leur `score_cyberattaque` : le score
reste une information affichée au dashboard, jamais un critère d'exclusion.

Veille LLM est une source analytique : ses références documentaires sont exposées
au dashboard mais ne gonflent jamais le compteur de corroboration éditoriale.
Lorsqu'un incident est déjà couvert par une source directe, `Sources` reste fondé
sur les sources directes. Lorsqu'il n'existe que dans Veille LLM, celle-ci reste
la source unique afin qu'aucun incident ne soit dépourvu de provenance.

Les collecteurs presse Mayotte du Lot 1 ont été retirés après observation de faux
positifs d'extraction de victime dans des articles généralistes. La précision du
corpus prime sur une couverture technique plus large mais bruitée.

## Initialisation et référence

Un **snapshot** est le dernier corpus techniquement valide : ITEMS, INCIDENTS
et provenance cohérente. Une **baseline** est ce même snapshot, revalidé par
`check` et `test-repeat`, puis enregistré comme référence locale
(`data/baseline.json`). Aucune collecte réseau supplémentaire n'est requise
pour créer une baseline — le projet n'est pas critique, une collecte
contrôlée et vérifiée offline suffit. Une MAJ actualise le snapshot mais ne
réécrit pas la baseline.

Ce document décrit la méthode telle qu'elle est **réellement exécutée par le code**.
Il reprend la méthodologie d'origine (`SIMPLE-SOURCING-1`) et consigne, sans les
masquer, les écarts introduits par le passage à l'exécution automatique.

> **Ce que cette base est.** La liste la plus large possible des incidents cyber
> *publiquement listés* par plusieurs sources, avec une couverture mesurable et un
> protocole de récupération reproductible.
> **Ce qu'elle n'est pas.** Elle ne prétend pas représenter toutes les cyberattaques
> réelles.

---

## 1. Ce qui change par rapport à la version 1

### 1.1 Le modèle de statuts est refondu

La version 1 utilisait cinq statuts (`OK`, `EMPTY`, `PARTIAL`, `FAIL`, `NOT_RUN`) et
un statut global insuffisamment explicite. Ce vocabulaire mélangeait deux
questions distinctes et rendait `PARTIAL` ininterprétable.

La version 2 sépare **trois informations orthogonales** :

| Champ | Question à laquelle il répond | Valeurs |
|---|---|---|
| `Status` | Le protocole a-t-il abouti ? | `OK` · `PARTIAL` · `FAIL` · `SKIPPED` |
| `Coverage` | Quelle part du protocole a tourné ? | entier 0 à 100 |
| `Reason_Code` + `Reason` | Pourquoi ? | code machine + phrase française |

**Correspondance avec l'ancien vocabulaire :**

| Version 1 | Version 2 | Pourquoi |
|---|---|---|
| `EMPTY` | `OK` avec `Items_collected = 0` | Un zéro obtenu au bout d'un protocole complet est un **zéro vérifié**, c'est-à-dire un succès — pas une anomalie. |
| `NOT_RUN` | `SKIPPED` | Distingue « hors périmètre de ce run » (normal) de « aurait dû tourner » (anormal, qui devient `FAIL`). |
| `PARTIAL` | `PARTIAL` + `Coverage` | On lit désormais `PARTIAL 68 % (120/176 requêtes)` au lieu d'un « partiel » non interprétable. |

**Règle du zéro fiable.** Un `Items_collected = 0` ne signifie « aucun incident »
que si `Status = OK`. Partout ailleurs il signifie « information indisponible », et
le dashboard l'affiche grisé. C'est la règle « transparence des trous de couverture
> faux zéro » rendue visuelle.

**Statut global du run**, binaire et sans score :

| Niveau | Règle | Lecture |
|---|---|---|
| `OK` | Toutes les sources actives sont `OK`. | Snapshot publiable |
| `BROKEN` | Au moins une source active n'est pas `OK`. | Ne pas publier de snapshot |

Les compteurs `Sources_OK` et `Sources_FAIL` rendent ce statut vérifiable. Il
n'existe pas de score composite métier.

### 1.2 `RANSOMWARE_LIVE` est activée

La version 1 la classait `CANDIDATE_DISABLED` faute d'accès opérationnel en
conversation. En code il s'agit d'une API JSON publique et gratuite fournissant
organisation, date, groupe et pays. La méthode la désignait elle-même comme
prioritaire, les sources françaises étant fortement orientées « fuite de données ».
`HACKMAGEDDON` reste désactivée.

### 1.3 Les couches de veille interrogent directement les flux des médias

La version 1 prévoyait des requêtes de moteur de recherche, exécutables à la main
mais pas en script. Google News RSS a d'abord été retenu comme substitut, puis
**abandonné après vérification** : le `robots.txt` de Google interdit
`/rss/search`. Le pipeline respecte les robots.txt, cette voie est donc fermée.

Les couches de veille lisent désormais **le flux propre de chaque média** du
territoire, puis reconnaissent nominativement les entités surveillées dans les
articles. Ce remplacement est meilleur sur trois plans :

- **conformité** : on consomme les flux que les médias publient pour être lus ;
- **fidélité à la méthode** : le §31 pose « source directe > recherche moteur » ;
- **volumétrie** : une requête par média au lieu de deux par entité, soit
  **36 unités au lieu de 266** pour un balayage complet.

Un article n'entre dans la base que s'il relève du cyber : la seule mention d'une
commune ne suffit pas, celle-ci pouvant être citée pour tout autre motif.

**Limite assumée** : un flux ne porte que ses dernières publications. Cette
couche surveille donc le présent et ne reconstitue pas l'historique. Sa
couverture est calculée sur la part de fenêtre réellement observée, et elle
ressort `PARTIAL` plutôt que de revendiquer une énumération complète.

### 1.4 Le XLSX est remplacé par des CSV

Les cinq feuilles de la version 1 deviennent cinq fichiers CSV versionnés dans git.
L'architecture de la base est inchangée ; seul le contenant l'est. Bénéfices :
diffs lisibles à chaque run, empreintes calculables sans ambiguïté, lecture directe
par le dashboard. Un sixième jeu, `entity_watch.csv`, est ajouté (voir §1.6).

### 1.5 Les `Incident_ID` restent purement déterministes

La version 1 demandait de « préserver un `Incident_ID` existant lorsqu'il
correspond encore à la même composante ». Or l'identifiant dérive de
`Component_Start_Date` : si une MAJ fait apparaître un item plus ancien, la date de
début change et l'identifiant change mécaniquement.

Préserver l'identifiant exigerait un registre persistant, qui **casserait la
reproductibilité pure du `REPLAY`** — or celle-ci est la garantie centrale de la
méthode : à `ITEMS` identique, `Incidents_Hash` identique.

**Le déterminisme pur est retenu.** La continuité historique dont le dashboard a
besoin est portée par `First_seen` et `Last_seen`, déjà présents au schéma.

### 1.6 Ajout du jeu `ENTITY_WATCH`

Une ligne par entité surveillée : territoire, type (commune / critique), date de
dernière interrogation, statut de veille, dernier incident connu. Ce jeu rend la
couverture des couches `ENTITY_WATCH` **vérifiable nominativement** — la couverture
n'est plus un pourcentage abstrait mais s'adosse à la liste des entités réellement
interrogées — et alimente le focus Réunion / Mayotte du dashboard.

---

## 2. Architecture de la base

Six fichiers CSV dans `data/` :

| Fichier | Contenu | Une ligne = |
|---|---|---|
| `items.csv` | Snapshot de collecte, sans déduplication | un item brut réellement lu |
| `incidents.csv` | Base dédupliquée, alimente le dashboard | un incident |
| `sources.csv` | Référentiel des sources et protocoles | une source |
| `run_sources.csv` | Journal par source et par run | une exécution de source |
| `run_log.csv` | Journal de synthèse | un run |
| `entity_watch.csv` | État de veille nominatif | une entité surveillée |

Colonnes exactes : voir `cyberwatch/model.py`, qui fait foi.

---

## 3. Identifiants déterministes

```
Organisation_Key = NFKD → sans accents → minuscules → sans ponctuation
                   → espaces normalisés → retrait des formes juridiques isolées
                     (SAS, SARL, SA, EURL)

Item_ID     = "ITM-" + SHA256(Source_ID|Source_Item_ID)[:16]
              lorsque la source fournit un identifiant natif stable ; sinon
              SHA256(Source_ID|Published_Date|Organisation_Key|URL)[:16].
Incident_ID = "INC-" + SHA256(Organisation_Key|Anchor_Item_ID)[:12].upper()
```

Aucun rapprochement flou, aucune fusion assistée par IA. Deux libellés qui ne se
normalisent pas à l'identique restent deux organisations distinctes :
**un faux doublon est préférable à une fusion non reproductible.**

---

## 4. Déduplication et datation

1. Grouper par `Organisation_Key`.
2. Trier par date, `Source_ID`, `URL`, `Item_ID`; l'ancre du composant est
   l'item canonique retenu par le moteur, pas seulement sa date.
3. Regrouper les items successifs dont l'écart est **inférieur ou égal à 14 jours**.
4. Un écart supérieur ouvre un nouvel incident.

**Date du dashboard** : si au moins un `Event_Date` est connu, `Date` vaut la
première `Event_Date` et `Date_Basis = EVENT` ; sinon la première `Published_Date`
et `Date_Basis = PUBLICATION`.

**Menace d'un incident** : lorsque deux sources qualifient différemment un même
incident, la taxonomie tranche par priorité — un ransomware qui exfiltre reste un
ransomware. Ce choix est déterministe, contrairement à un « premier arrivé ».

Un item sans organisation identifiable reste dans `ITEMS` mais **ne crée pas
d'incident** : un incident sans victime nommée n'est pas un incident.

---

## 5. Volumétrie et plafonds

La collecte est incrémentale : une MAJ ne rejoue que la fenêtre de 14 jours, donc
le coût quotidien reste constant dans le temps.

| Run | Requêtes | Durée |
|---|---|---|
| Quotidien (sources directes) | ~40 | 1–2 min |
| Hebdomadaire (balayage complet) | ~90 | 2–4 min |
| `CREATE` initial (année en cours) | ~90 | 2–5 min |

Mesures relevées en exécution réelle, pas des estimations.

**Plafonds durs**, appliqués dans `cyberwatch/config.py` :

| Plafond | Valeur |
|---|---|
| Timeout par requête | 20 s (2 reprises) |
| Requêtes / pages / durée par source | 60 · 50 · 180 s |
| Budget total du run | 800 requêtes · 45 min |
| Politesse | 1 requête/seconde par domaine, `robots.txt` respecté |

Un dépassement **ne fait jamais échouer le run ni perdre de données** : il arrête
proprement la source, conserve ce qui a été collecté et inscrit la couverture
réelle. C'est précisément le rôle du modèle de statuts.

---

## 6. Chaîne d'accès aux sources

Les structures HTML des sites changent avec le temps. Plutôt que d'écrire un
parser sur mesure par site — fragile et invérifiable — chaque source essaie trois
formats **standardisés**, dans l'ordre, et le pipeline **enregistre celui qui a
fonctionné** dans `RUN_SOURCES` :

1. **API REST WordPress** (`/wp-json/wp/v2/posts`) — dates structurées, filtrage par
   date côté serveur, nombre de pages exact via `X-WP-TotalPages`, donc couverture
   mesurée et non estimée.
2. **Flux RSS / Atom** — autodécouverte puis chemins conventionnels.
3. **JSON-LD schema.org** (`NewsArticle`) — présent sur la quasi-totalité des sites
   de presse, donc générique.
4. **Dates en texte brut** associées au lien le plus proche — dernier repli, utile
   pour les sites institutionnels en HTML statique sans données structurées.

Si aucun ne fonctionne : `FAIL` avec `Reason_Code = NO_FEED_FOUND`, jamais un zéro
silencieux.

**Test de succès commun** : une source n'est `OK` que si la **borne de date a été
atteinte**, c'est-à-dire si la collecte est remontée jusqu'au début de la fenêtre.
Un HTTP 200 ne suffit pas.

---

## 7. Commandes

| Commande | Effet |
|---|---|
| `create` | Construit la base depuis zéro. Sans période, démarre au 1er janvier de l'année en cours. |
| `maj` | Rejoue la fenêtre glissante de 14 jours et fusionne par `Item_ID`. Ne supprime jamais un ancien item. |
| `replay` | Reconstruit `INCIDENTS` depuis `ITEMS`, **sans aucun accès Web**. |
| `test-repeat` | Test de répétabilité : deux constructions, quatre égalités. |
| `diagnose` | Sonde les sources et mesure le coût réel, sans rien écrire. |
| `check` | Rejoue les contrôles avant export. |
| `build-site` | Régénère les données du dashboard. |
| `report` | Résumé Markdown du dernier run. |

---

## 8. Contrôles avant export

Vérifiés à chaque run, et publiés dans `RUN_LOG.Notes` s'ils échouent :

- aucun `Item_ID` ni `Incident_ID` dupliqué ;
- chaque incident possède au moins une source ;
- chaque source active possède une ligne `RUN_SOURCES` ;
- aucun statut `OK` sans couverture complète.

---

## 9. Règles de qualité du sourcing

```
source directe            >  recherche moteur
item réellement énuméré   >  compteur annoncé
protocole terminé         >  site accessible
couverture multi-source   >  dépendance à un seul agrégateur
transparence des trous    >  faux zéro
```


---

## 10. Ce que l'exécution réelle a appris

Ces constats proviennent de runs en conditions réelles, pas d'hypothèses.

| Constat | Conséquence retenue |
|---|---|
| `robots.txt` de Google interdit `/rss/search` | Couches de veille rebasculées sur les flux directs des médias (§1.3) |
| Trois médias répondent `403` à tout agent non-navigateur, alors que leur `robots.txt` autorise le chemin | Une seule nouvelle tentative avec un agent accepté par ces pare-feux, l'identification du projet étant conservée |
| CIRT-MG est une coquille JavaScript de 1,5 Ko, CERT-SC ne sert plus de liste d'alertes, deux médias réunionnais répondent 403 même sous agent de repli | Ces quatre sources passent `Active = NO` avec motif daté et critère de réactivation, comme le prévoit le §21. Elles restent visibles sur le dashboard en `SKIPPED` avec leur raison — désactiver n'est pas masquer. Réserver `BROKEN` aux régressions réelles évite qu'un échec permanent ne rende le signal inutile. |
| La couverture d'une couche de veille mesurée contre une fenêtre historique donnait un « 3 % » permanent | La couverture mesure ce que le protocole contrôle — le nombre de médias lus. La profondeur d'un flux, qui est une propriété du média, est rapportée en clair dans le commentaire. |
| Un marqueur de vocabulaire trop court (« si ») laissait entrer tout texte français | Vocabulaire scindé en racines de mots et expressions exactes, testé sur limites de mots |
| Une liste de fuites nomme ses entrées d'après l'organisation, sans vocabulaire cyber | Le garde-fou d'ingestion ne s'applique pas aux sources déclarant une menace par défaut |

Le principe commun : **chaque limite rencontrée est inscrite dans le statut de la
source plutôt que contournée ou masquée.**

---

## 11. Qualification LLM des champs Inconnu (filet de rattrapage)

`cyberwatch/ai.py` complète, en dernier recours seulement, les champs
`Threat`/`Sector`/`Location` d'un item encore `Inconnu` **après** les règles
déterministes (`normalize.py`) et le backfill (`enrichment.py`). Il ne
touche jamais `Item_ID`, `Organisation_Key`, `Incident_ID` ni une valeur déjà
connue — le §3 (« aucun rapprochement flou, aucune fusion assistée par IA »)
reste entier : l'identité et la déduplication restent purement
déterministes, seule la qualification d'un champ décrivant l'incident peut
recourir au LLM, et seulement s'il est encore inconnu.

**Ordre d'exécution**, par item, dans `runner.entry_to_item`/`run_source` :

```
entrée brute (RawEntry)
→ règles déterministes (normalize.py)
→ backfill (enrichment.py)
→ Item construit, Item_ID figé
→ si Threat/Sector/Location encore Inconnu : filet de rattrapage LLM
→ sinon aucun appel API
→ validation stricte (taxonomie fermée, confiance, preuve)
→ cache (data/ai_qualifications.csv)
→ ITEMS → dédup déterministe existante → INCIDENTS
```

**Modèle** : `gpt-5-nano-2026-03-17` (défaut, overridable par `OPENAI_MODEL`),
appelé via l'API Responses d'OpenAI avec Structured Outputs, en HTTPS direct
(`requests`, pas de SDK). Snapshot et tarifs retenus par recherche web le
2026-08-15 — la documentation officielle était inaccessible depuis
l'environnement d'exécution au moment de l'implémentation ; à corriger si un
usage réel les contredit.

**Politique stricte** : Structured Outputs avec schéma fermé sur les
taxonomies de `config.py` (`Inconnu` est une réponse valide), seuils de
confiance par champ (Location plus stricte), et pour Location une preuve
(`evidence`) qui doit apparaître dans le contexte transmis — jamais une
déduction de connaissance générale sur l'organisation. Toute réponse
invalide, insuffisamment confiante ou mal formée est ignorée : le champ reste
`Inconnu`, l'échec est journalisé, rien n'est inventé.

**Cache** : `data/ai_qualifications.csv`, clé `(Item_ID, Input_Hash)`. Le
`Input_Hash` intègre le contexte transmis, les champs demandés, le modèle,
la version de prompt et de schéma — tout changement de l'un d'eux invalide
naturellement les décisions concernées sans purge manuelle.

**Usage et coût** : `data/ai_usage.csv` porte une ligne de synthèse par run
(candidats, cache hits, appels, tokens, coût estimé, statut), résumée dans
`python -m cyberwatch report`. Garde-fous par variables d'environnement
(`AI_MAX_CALLS_PER_RUN`, `AI_MAX_ESTIMATED_COST_USD_PER_RUN`,
`AI_MAX_CONTEXT_CHARS`, `AI_MAX_OUTPUT_TOKENS`) : un plafond atteint arrête
les nouveaux appels sans casser la collecte, les champs restants demeurant
`Inconnu`.

**Panne non bloquante** : l'absence de `OPENAI_API_KEY`, une panne réseau
définitive ou un modèle qui refuse le format ne font jamais échouer une
collecte — la qualification est simplement désactivée ou dégradée pour ce
run (`ai_usage.Status = DISABLED/API_ERROR/DEGRADED`), journalisé, et le
run continue. La qualification LLM est facultative ; la collecte reste la
fonction critique.

**`REPLAY` reste strictement offline** : il ne traverse jamais
`run_source`/`entry_to_item` (il ne fait que relire `ITEMS` et reconstruire
`INCIDENTS`), donc n'appelle jamais l'API — même si `OPENAI_API_KEY` est
présente. `test-repeat` reste lui aussi entièrement offline et déterministe.

**Sources exclues** : une source déjà issue d'une analyse LLM structurée
(ex. Veille LLM, §Couverture locale Réunion / Mayotte) porte
`params={"skip_ai_qualification": True}` : elle n'est jamais reproposée à un
second LLM. `RANSOMWARE_LIVE` fournit déjà Threat/Location de façon
structurée ; seul Sector peut légitimement rester Inconnu et devenir
éligible.

**Secret GitHub** : `secrets.Cyberwatchapi` est mappé, uniquement dans les
étapes de collecte réelle (`collect.yml` : « Collecter » ; `initialize.yml` :
« CREATE contrôlé »), vers la variable d'environnement standard
`OPENAI_API_KEY` — c'est la seule chose que lit le code Python. `ci.yml` ne
reçoit jamais ce secret ; ses tests mockent systématiquement l'appel réseau.

## 12. Pipeline Secteur : preuve stricte et enrichissement gratuit

Un benchmark réel (120 items frais, hors Veille LLM) a montré que le filet
de rattrapage §11, appliqué sans discernement à `Sector`, devine trop
souvent à partir du seul nom de l'organisation ou du vocabulaire de
l'incident (rançongiciel, fuite de données, groupe cybercriminel) faute de
description métier explicite dans le contexte source — précision mesurée de
62,5 % sur les valeurs injectées. Ce chantier resserre `Sector`
spécifiquement, sans toucher `Threat`/`Location`/la déduplication/la
priorité Veille LLM/les défauts France métropolitaine.

**Aucune recherche Web OpenAI n'est utilisée. L'API OpenAI ne sert qu'à de
la classification textuelle classique** (`POST /v1/responses`, même modèle,
même mécanisme que le §11) — jamais un outil de recherche, jamais un agent.
Toute information externe est récupérée directement par Cyberwatch, en HTTP
simple, vers une API publique gratuite.

**Pipeline**, déclenché uniquement quand `Sector` est encore `Inconnu` après
les règles déterministes et le backfill (§11 inchangé) :

```
Sector Inconnu après déterministe + référentiel ?
  → non : arrêt, coût nul
  → oui → tentative LLM sur le contexte source (§11), preuve stricte :
       l'evidence doit décrire l'activité de l'organisation, être ancrée
       dans le contexte transmis, jamais réduite au nom de l'organisation,
       jamais issue du vocabulaire de l'incident
  → Sector toujours Inconnu (réponse Inconnu ou preuve rejetée) →
       cache d'enrichissement (data/org_enrichment_cache.csv, clé
       Organisation_Key) déjà validé ? → oui : appliqué, coût nul
       → non → requête gratuite recherche-entreprises.api.gouv.fr,
         correspondance UNIQUEMENT sur égalité exacte de nom normalisé
         (`normalize.organisation_key`) ; plusieurs entités légales
         distinctes partageant ce nom (ex. franchises) → AMBIGUOUS, Sector
         reste Inconnu, jamais de choix arbitraire
  → titre de section NAF obtenu (cache ou HTTP frais, cf. note API) →
       mapping déterministe via `org_enrichment.NAF_SECTIONS` (21 entrées
       fixes, coût nul, aucun appel LLM — la table couvre les 21 valeurs
       possibles de façon exhaustive, y compris vers Inconnu)
  → aucune activité fiable obtenue, ou section sans correspondance claire →
       Inconnu reste Inconnu, jamais deviné
```

**Note API (corrigée après le premier run réel du 2026-08-15)** : le plan
initial prévoyait un libellé d'activité détaillé par code NAF, classifié en
dernier recours par un second appel OpenAI scopé. La réponse réelle de
`recherche-entreprises.api.gouv.fr` (vérifiée via le job `probe-org-schema`
de `bench-qualification.yml`, seule voie réseau capable d'atteindre ce
domaine) ne fournit **aucun libellé d'activité détaillé** : `activite_principale`
est un code NAF nu (ex. `"63.11Z"`), jamais un objet `{code, libelle}`. Le
seul texte officiel disponible est le titre de la section NAF à une lettre
(`section_activite_principale`, A à U), exploité via `NAF_SECTION_LABELS`.
Comme cette section ne peut prendre que 21 valeurs, `NAF_SECTIONS` les
tranche toutes explicitement et **aucun second appel LLM n'a lieu** —
l'appeler aurait payé pour reclassifier une valeur déjà connue de façon
déterministe, contraire au §11 (« jamais de LLM pour confirmer une valeur
fiable »). Le même run a aussi révélé que `nom_complet` compose souvent
« Nom commercial (Raison sociale) » : le matching utilise `nom_raison_sociale`
en priorité pour éviter qu'une parenthèse ne casse une correspondance
évidente.

**Preuve stricte côté LLM (`ai.py::_validate`/`_sector_evidence_reason`)** :
chaque champ demandé est désormais validé indépendamment (un rejet sur
`Sector` n'invalide plus `Threat`/`Location` décidés dans le même appel).
Pour `Sector`, une evidence est rejetée si elle est absente du contexte
transmis, si elle se réduit au nom de l'organisation (`organisation_key`
identique), ou si elle relève du vocabulaire d'incident (préfixes/phrases
cyber, groupes de rançongiciel, motifs de `THREAT_RULES`) — même ancrée
dans le contexte. `RANSOMWARE_LIVE` (contexte quasi exclusivement composé de
ce vocabulaire) en bénéficie automatiquement, sans cas spécial par source.

**Enrichissement gratuit (`cyberwatch/org_enrichment.py`)** : appel HTTP
direct (`requests`, indépendant de `http.py`/`HttpClient` — la dimension de
budget ici est un nombre d'appels par run, pas du respect de robots.txt) vers
`recherche-entreprises.api.gouv.fr` (API publique française, sans clé). Un
candidat n'est retenu que si son nom normalisé est **exactement** égal à
celui recherché — jamais de correspondance floue, jamais le premier
résultat. Panne réseau/HTTP/JSON → `ERROR`, jamais mise en cache (retentée
au run suivant), `Sector` reste `Inconnu` — une panne d'enrichissement ne
fait jamais échouer la collecte.

**Cache d'enrichissement** : `data/org_enrichment_cache.csv`, clé
`Organisation_Key`, sans TTL — cohérent avec `ai_qualifications.csv` et
`enrichment_reference.csv`. `MATCHED`/`AMBIGUOUS`/`NOT_FOUND` sont
permanents (jamais retentés) ; `ERROR` ne l'est jamais (retenté à chaque
run). `Validated_Sector`/`Validated_Via` (`deterministic` ou
`no_deterministic_match`) évitent toute nouvelle requête HTTP une fois un
secteur validé ou une section NAF déjà classée sans correspondance.

**Politique Immobilier → Construction / BTP** : la taxonomie Cyberwatch n'a
pas de secteur « Immobilier » dédié. La section NAF L (« Activités
immobilières ») est explicitement mappée vers « Construction / BTP » dans
`org_enrichment.NAF_SECTIONS` — politique documentée ici, pas laissée à la
discrétion d'un LLM.

**Budget** : le mapping NAF_SECTIONS étant déterministe et sans appel LLM,
le pipeline Secteur ne consomme le budget OpenAI (mêmes compteurs
`calls_attempted`/`estimated_cost_usd` que le §11) que pour la tentative sur
le contexte source. L'enrichissement HTTP a son propre plafond
(`ORG_ENRICHMENT_MAX_CALLS_PER_RUN`, défaut 200), indépendant du budget
OpenAI.

**Nouvelles métriques** (`data/ai_usage.csv`, additives en fin de colonnes) :
`Sector_Initial_Unknown`, `Sector_Resolved_Reference`,
`Sector_Resolved_Deterministic`, `Sector_Resolved_Source_LLM`,
`Sector_Evidence_Rejected`, `Sector_Enrichment_Cache_Hit`,
`Sector_Enrichment_Http_Attempted/Matched/Ambiguous/Not_Found/Error`,
`Sector_Resolved_Enriched_Deterministic`, `Sector_Resolved_Enriched_LLM`
(toujours 0, conservée pour la forme — cf. note API ci-dessus),
`Sector_Remaining_Unknown`, `Org_Enrichment_Calls`,
`Org_Enrichment_Duration_s`, `Org_Enrichment_Cache_Hit_Rate`.

**Panne non bloquante et REPLAY** : mêmes garanties que le §11 —
`ORG_ENRICHMENT_ENABLED=0` ou absence de résultat exploitable laisse
`Sector` à `Inconnu` sans jamais faire échouer la collecte ; `REPLAY` ne
traverse jamais `run_source`/`entry_to_item`, donc n'appelle jamais
l'enrichissement, même si les clés/variables d'environnement sont
présentes.
