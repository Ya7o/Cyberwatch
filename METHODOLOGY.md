# Méthodologie exécutable OBS-FR-OI

**`Method_ID : OBS-FR-OI-SIMPLE-SOURCING-10`**
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
sans dépendre de la fenêtre réseau de MAJ. Le snapshot conserve deux états :
`ACCEPTED` lorsqu'une preuve publique démontre le caractère cyber et
`CANDIDATE` lorsque le signal reste une panne, un incident informatique, un
sabotage physique ou une rumeur sans origine cyber démontrée. Seuls les
`ACCEPTED` sont matérialisés dans `ITEMS`. Le score reste une information
analytique et ne décide jamais l'admission.

Le contrat `cyberwatch-veille-v2` impose les compteurs, l'admission, sa raison,
les territoires et au moins une URL documentaire. Un `ACCEPTED` ne peut pas
porter `type_menace=Inconnu` : lorsque le caractère cyber est établi mais pas
sa nature précise, la valeur canonique est `Autre cyber`. Un snapshot âgé de
plus de deux jours est exposé `PARTIAL` mais ne bloque pas les autres sources.

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

Un septième fichier, **`source_facts.csv`, est auxiliaire** (§13) : il ne fait
pas partie de la base canonique ci-dessus, n'entre dans aucun hash
(`Items_Hash`/`Incidents_Hash`), et `REPLAY` ne le lit ni ne l'écrit jamais.

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

`organisation_key` seul ne pratique aucun rapprochement flou : deux libellés qui
ne se normalisent pas à l'identique restent deux organisations distinctes
tant qu'aucun alias ni aucune décision validée ne les unifie explicitement —
**un faux doublon est préférable à une fusion non reproductible.**

L'identité publiée reste entièrement reproductible et déterministe : à
`ITEMS` et registres identiques, `Organisation_Key` effective, `Item_ID` et
`Incident_ID` sont toujours les mêmes, quel que soit l'ordre d'arrivée des
données. Un LLM peut challenger des candidats de rapprochement lors d'une
collecte réelle (§14.5), mais il ne décide jamais seul : une décision LLM
n'est appliquée qu'après validation par une policy déterministe
(`dedup_ai.validate_ai_dedup_decision`), et ne devient reproductible qu'une
fois persistée dans le registre d'identité organisationnelle versionné
(`data/organisation_identity_registry.csv`, §14.5). `REPLAY` ne consulte
jamais le LLM — il lit uniquement ce registre déjà persisté.

L'identité **organisationnelle** (« ces deux libellés désignent-ils la même
victime ? ») et l'identité **d'incident** (« ces deux items décrivent-ils le
même événement ? ») sont deux questions strictement indépendantes : une même
organisation peut légitimement porter plusieurs incidents distincts (§14.5).

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

**Pipeline** (révisé — §Sector fiabilité, voir note de révision en fin de
section) : l'enrichissement organisation est déclenché quand `Sector` **ou**
`Location` est encore `Inconnu` après les règles déterministes et le backfill.
Un unique match exact peut alimenter les deux champs : section NAF pour Sector,
département du siège pour Location. L'enrichissement gratuit et déterministe
passe **avant** tout appel LLM — un LLM ne doit être qu'un dernier recours :

```
Sector Inconnu après déterministe + référentiel ?
  → non : arrêt, coût nul
  → oui → Phase 1 : cache d'enrichissement (data/org_enrichment_cache.csv,
       clé Organisation_Key) déjà validé ? → oui : appliqué, coût nul
       → non → requête gratuite recherche-entreprises.api.gouv.fr,
         correspondance UNIQUEMENT sur égalité exacte de nom normalisé
         (`normalize.organisation_key`) ; plusieurs entités légales
         distinctes partageant ce nom (ex. franchises) → AMBIGUOUS, Sector
         reste Inconnu, jamais de choix arbitraire
       → titre de section NAF obtenu (cache ou HTTP frais, cf. note API) →
         mapping déterministe via `org_enrichment.NAF_SECTIONS` (21 entrées
         fixes, coût nul) → Sector résolu, arrêt
  → Sector toujours Inconnu → Phase 2 : LLM sur le contexte source (§11),
       tenté seulement si le contexte dépasse le seul nom de l'organisation
       (§9 routage — BonjourLaFuite ne l'atteint jamais, contenu
       structurellement pauvre, cf. plus bas) ; preuve stricte : l'evidence
       doit décrire l'activité de l'organisation, être ancrée dans le
       contexte transmis, jamais réduite au nom de l'organisation, jamais
       issue du vocabulaire de l'incident
  → Sector toujours Inconnu, mais un libellé de section NAF a été obtenu en
       Phase 1 sans correspondance déterministe claire → Phase 3, dernier
       recours : un appel LLM minimal, borné au seul libellé officiel
       (jamais le récit de l'incident) — voir note de révision
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
tranche presque toutes explicitement, sans appel LLM — payer un appel pour
reclassifier une valeur déjà connue de façon déterministe violerait le §11
(« jamais de LLM pour confirmer une valeur fiable »). **Révision (§Sector
fiabilité)** : pour les libellés que `NAF_SECTIONS` renvoie à `Inconnu`
faute de correspondance claire (ex. « Autres activités de services »), un
dernier recours borné (`ai.py::_escalate_sector_llm`) tente désormais un
appel LLM minimal dont la seule preuve possible est ce libellé officiel
lui-même — jamais le récit de l'incident. Décision explicite : ce chemin
avait été volontairement écarté au run du 2026-08-15 (paragraphe
initialement écrit ici), mais reste borné aux mêmes garde-fous que le §11
(taxonomie fermée, evidence ancrée, `Inconnu` si confiance insuffisante) et
au même budget OpenAI. Le résultat (`llm` ou `llm_declined`, jamais
retenté) est mis en cache au même titre que la voie déterministe
(`Validated_Via`). Le même run a aussi révélé que `nom_complet` compose souvent
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
`Organisation_Key`. `ERROR` n'est jamais mis en cache (retenté à chaque
run). `MATCHED`/`AMBIGUOUS`/`NOT_FOUND` sont durables par défaut, mais
**versionnés** (§Sector fiabilité) plutôt que strictement permanents :
`Cache_Version` (colonne additive, `org_enrichment.ORG_ENRICHMENT_CACHE_VERSION`,
bump si `_match`/`NAF_SECTIONS` change matériellement) est comparée au
chargement du cache (`start_state()`). Un `NOT_FOUND`/`AMBIGUOUS` dont la
version diffère est ignoré (nouvelle requête HTTP au prochain `resolve()`) —
un résultat négatif ancien ne doit jamais bloquer définitivement une
meilleure résolution après un changement de logique. Un `MATCHED` reste
chargé quelle que soit sa version (données d'entreprise durables, jamais
retenté par HTTP), mais `Validated_Sector`/`Validated_Via` sont
réinitialisés si la version diffère, pour laisser une nouvelle chance au
mapping NAF/à l'escalade LLM. `Validated_Via` prend désormais quatre
valeurs : `""` (jamais tenté), `"deterministic"`, `"llm"`, `"llm_declined"`
(déjà tenté par le LLM minimal, jamais concluant — jamais retenté à
version de cache inchangée). Pas de TTL par ailleurs : cohérent avec
`ai_qualifications.csv`/`enrichment_reference.csv`, sans infrastructure
supplémentaire.

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

**Métriques** (`data/ai_usage.csv`, additives en fin de colonnes) :
`Sector_Initial_Unknown`, `Sector_Resolved_Reference`,
`Sector_Resolved_Deterministic` (règle sur organisation + description
d'activité étroitement extraite, jamais l'article complet — cf. §Sector
fiabilité), `Sector_Resolved_Source_LLM`, `Sector_Evidence_Rejected`,
`Sector_Enrichment_Cache_Hit`,
`Sector_Enrichment_Http_Attempted/Matched/Ambiguous/Not_Found/Error`,
`Sector_Resolved_Enriched_Deterministic`, `Sector_Resolved_Enriched_LLM`
(désormais réellement peuplée : dernier recours borné au libellé NAF, cf.
ci-dessus), `Sector_Remaining_Unknown`, `Org_Enrichment_Calls`,
`Org_Enrichment_Duration_s`, `Org_Enrichment_Cache_Hit_Rate`, et deux
compteurs additionnels (§Sector fiabilité) : `Sector_Resolved_Native`
(résolution directe depuis un champ structuré de la source, ex.
`entry.sector` RANSOMWARE_LIVE, invisible jusqu'ici) et
`Sector_LLM_Skipped_No_Evidence` (LLM sur contexte source jamais tenté,
routage pré-appel — distinct d'un appel fait puis rejeté).

**Panne non bloquante et REPLAY** : mêmes garanties que le §11 —
`ORG_ENRICHMENT_ENABLED=0` ou absence de résultat exploitable laisse
`Sector` à `Inconnu` sans jamais faire échouer la collecte ; `REPLAY` ne
traverse jamais `run_source`/`entry_to_item`, donc n'appelle jamais
l'enrichissement, même si les clés/variables d'environnement sont
présentes.

**Note de révision (§Sector fiabilité)** : un audit a identifié qu'une
règle déterministe pouvait classifier `Sector` à partir de vocabulaire
d'incident non représentatif de l'activité de la victime — cas concret :
pour `CYBERATTAQUE_ORG` (seule source combinant `include_content=True` sans
secteur structuré ni `title_is_organisation`), le fallback déterministe
scannait l'article complet, et le mot isolé « stade » (règle Sport)
matchait dans « à ce stade, aucune donnée... ». Corrections apportées,
volontairement resserrées (pas de refonte du pipeline Secteur) :
- `config.SECTOR_RULES` perd les mots isolés les plus dangereux, omniprésents
  dans tout récit d'incident cyber sans jamais décrire une activité :
  `stade`, `web`, `internet`, `digital`, `systemes`/`systems` (Sport/Tech),
  `association`, `syndicat` (Services, + un doublon mort `mutuelle`).
- Le fallback déterministe (`runner.py::entry_to_item`) ne reçoit plus
  jamais l'article complet : uniquement l'organisation et, si présente, une
  description d'activité **étroitement extraite**
  (`normalize.extract_activity_description`, vocabulaire de déclencheurs
  fermé — « spécialisée dans », « éditeur de », « club de football »...).
  Cette même fonction alimente aussi `source_facts.py::Activity_Description`
  (y compris désormais pour `CYBERATTAQUE_ORG`, qui ne la remplissait pas) :
  une seule implémentation, deux usages.
- Le LLM sur contexte source (§ ci-dessus, Phase 2) n'est plus tenté que si
  le contexte dépasse le seul nom de l'organisation ; BonjourLaFuite ne
  l'atteint jamais (contenu structurellement pauvre : organisation, date,
  liste de données compromises — jamais une description d'activité).
- `VEILLE_LLM` n'est concerné par aucun de ces changements (source
  analytique séparée, comportement et priorité de déduplication
  `dedup._preferred_qualification` inchangés).

## 13. Faits source : provenance déclarative, jamais canonique

Cyberwatch collecte davantage d'informations que ce qu'il conserve dans
`ITEMS`/`INCIDENTS` : `RawEntry` (interne à un collecteur) transporte
`summary`/`content` riches, mais `Item` ne garde que l'identité, les dates,
l'organisation, `Threat`/`Sector`/`Location`, le titre et l'URL. Les **faits
source**, dans `data/source_facts.csv` (schéma `SOURCE_FACT_COLUMNS` de
`cyberwatch/model.py`), conservent les faits supplémentaires **explicitement
publiés** par les sources déjà collectées — sans nouvelle requête réseau, sans
appel OpenAI, sans recherche Internet.

**Principe absolu** : *un fait source décrit ce qu'une source publie ; il ne
devient jamais une connaissance supposée sur l'organisation.*

### Qualification canonique vs faits source

| | Qualification canonique (`Item`) | Faits source (`source_facts.csv`) |
|---|---|---|
| Colonnes | `Threat`, `Sector`, `Location` | `Threat_Actor`, `Third_Party`, `Affected_Count`, `Data_Types_JSON`, `Vulnerabilities_JSON`, … (voir `model.py`) |
| Rôle | Alimente la vue incident dédupliquée du dashboard | Provenance déclarative, un fait par `(Item_ID, Source_ID)` |
| Résolution de contradiction | Une taxonomie fermée tranche (§4) | **Aucune** : chaque source garde sa formulation |
| Décidé par l'IA ? | Jamais l'identité ; Threat/Sector/Location seulement via le filet §11/§12 | Jamais — extraction déterministe uniquement |

Une contradiction entre sources **n'est jamais résolue** dans cette couche.
Pas de « dernier gagne », pas de majorité automatique, pas de fusion
arbitraire. Exemple attendu et légitime :

```
FrenchBreaches   : Affected_Count_Raw = "environ 1 000 comptes"
BonjourLaFuite   : Affected_Count_Raw = "1 023 personnes"
```
Les deux lignes coexistent dans `source_facts.csv`, chacune reliée à son
propre `Item_ID`.

### Politique d'extraction (`cyberwatch/source_facts.py`)

Quatre niveaux de confiance, du plus sûr au plus prudent :
1. champ structuré transmis directement par la source (`RawEntry.source_metadata`,
   ou champs déjà structurés comme `organisation`/`sector` pour Ransomware.live
   et Veille LLM) ;
2. structure syntaxique explicite propre à la source (« Via X »,
   « Données concernées : … », `CVE-AAAA-NNNNN`) ;
3. extraction déterministe prudente depuis `summary`/`content`, vocabulaire
   fermé (unités de quantité, verbes de compromission explicites) ;
4. sinon : champ vide. La précision prime sur le taux de remplissage — en
   cas d'ambiguïté, rien n'est deviné (ex. « 2,8 millions d'enregistrements »
   ne devient jamais un nombre de personnes).

`extract_source_fact(item, entry, spec) -> dict | None` fonctionne
uniquement à partir de ces trois objets, sans accès réseau. Elle n'est
invoquée par `runner.run_source()` que pour un `RawEntry` ayant produit un
`Item` valide (un article rejeté — hors périmètre, non cyber, sans victime
obligatoire — ne crée aucun fait).

**Aucune recherche Web OpenAI, aucun appel OpenAI supplémentaire** : cette
couche est strictement déterministe, distincte du filet de rattrapage LLM
(§11) et du pipeline Secteur (§12), qu'elle ne modifie jamais.

### Champs supportés par source

| Source | Champs alimentés |
|---|---|
| **BONJOURLAFUITE** | `Claim_Status_Raw` (marqueur brut, jamais interprété en `Claim_Status`), `Third_Party` (« Via … »), `Data_Types_JSON`/`Affected_Count*` (« Données concernées : … »), `Evidence_URLs_JSON` (tous les liens « Source » du bloc, y compris ceux au-delà du premier qui reste seul à fixer `Item.URL`) |
| **FRENCHBREACHES** | `Claim_Status`/`Claim_Status_Raw`, `Affected_Count`/`Unit`/`Raw`, `Data_Volume_Raw`, `File_Count`, `Data_Types_JSON`, `Threat_Actor`, `Third_Party`, `Vulnerabilities_JSON`, `CVSS_Raw`, `Activity_Description` — depuis `entry.summary`/`title` uniquement, aucune page détail chargée |
| **CYBERATTAQUE_ORG** | Mêmes champs que FrenchBreaches (hors statut) plus `Victim_Website` — `Third_Party`/`Threat_Actor` exigent une relation explicite de compromission (prestataire compromis, hébergeur affecté, plateforme tierce à l'origine, fournisseur explicitement impliqué) ; une simple co-mention ne suffit jamais |
| **RANSOMWARE_LIVE** | `Threat_Actor` (groupe), `Source_Sector_Raw`, `Attack_Date`/`Discovered_Date` distinctes (au lieu d'être fusionnées comme `Published_Date`), `Victim_Website`, `Evidence_URLs_JSON` (site victime et URL de revendication, quand distincts) |
| **VEILLE_LLM** | `Fine_Location` (localisation précise, distincte de `Location` = territoire), `Threat_Actor`, `Claim_Status_Raw`, `Cyberattack_Score`, `Impact`, `Summary`, `Evolution`, `Evidence_URLs_JSON`, `Source_Sector_Raw` — recopie directe du snapshot déjà structuré, aucun second LLM (`skip_ai_qualification` reste inchangé) |

`Evidence_JSON` relie un champ renseigné à la preuve brute qui le justifie
(ex. `{"Affected_Count_Raw": "environ 90 000 personnes"}`) ; `Source_Metadata_JSON`
conserve, pour traçabilité, la donnée structurée transmise par le collecteur.

### CREATE / MAJ / REPLAY

- **CREATE** reconstruit `source_facts.csv` depuis zéro, comme `items.csv`.
- **MAJ** conserve les faits historiques et ne remplace que ceux dont
  l'`Item_ID` est recollecté (fusion par `Item_ID`, `source_facts.merge_source_facts`)
  — aucun doublon, idempotent à fenêtre inchangée.
- **REPLAY** reste entièrement offline (§26) : il ne possède pas les
  `RawEntry` nécessaires pour recalculer les faits, donc `source_facts.csv`
  n'est **ni lu ni réécrit** — il reste tel quel entre deux `REPLAY`.

`Items_Hash`/`Incidents_Hash` ne changent pas : `source_facts.csv` n'entre
dans aucun calcul de hash canonique (V1, volontairement).

## 14. Stabilisation pré-release : couverture historique, doublons certains, gate qualité

Un audit pré-release a distingué deux catégories de défaut : ceux qui
réduisent la complétude (taux d'`Inconnu`, non traités ici) et ceux qui
rendent une donnée publiée **trompeuse ou fausse** — seuls ces derniers sont
corrigés ici (pas de fuzzy matching, pas de nouvelle heuristique ouverte,
pas de refonte de la déduplication).

### 14.1 Couverture historique (`History_Status`)

Un protocole peut aboutir (`Status=OK`) sans que l'historique collecté
couvre la fenêtre demandée depuis son début — cas de FrenchBreaches
(`feed_has_no_pagination`), dont la profondeur réelle recule avec le
temps. `Status`/`Coverage`/`Reason` ne devaient jamais porter cette
question en plus de la leur (cf. docstring de `status.py`) :
`History_Status` (`COMPLETE`/`TRUNCATED`/`UNKNOWN`) et
`Oldest_Available_Date` forment un axe orthogonal, calculé génériquement
dans `runner._resolve_history_status()` (aucune condition sur `source_id` :
ne devient `TRUNCATED` que si un collecteur renseigne
`CollectResult.oldest_available_date` et que celle-ci est postérieure au
début de fenêtre malgré `Status=OK`). Propagé dans `run_sources.csv`
(colonnes additives) puis `assets/data/status.json`. Le dashboard affiche
un signal discret (infobulle sur le chip Statut existant), pas de colonne
supplémentaire — respecte l'invariant « mêmes six champs pour toute
source sans traitement spécial » du détail des sources.

### 14.2 Doublons inter-sources certains

Deux mécanismes distincts, jamais mélangés :

- **Alias certains** (`data/organisation_aliases.csv`) : la seule façon
  sanctionnée d'unifier deux libellés différents pour la même organisation
  — `organisation_key()` reste sans rapprochement flou (§7). Chaque alias
  ajouté est confirmé par les données réelles (deux `Organisation_Key`
  distinctes pour la même organisation) et couvert par un test de
  régression dédié (`tests/test_organisation_aliases.py`). Un nouvel alias
  s'applique immédiatement à la déduplication d'items déjà collectés grâce
  à `dedup._effective_organisation_key()`, qui recalcule la clé courante à
  partir d'`Organisation_Raw` plutôt que de dépendre uniquement de
  `Organisation_Key` figé à la collecte.
- **Candidats d'audit** (`cyberwatch/duplicate_audit.py`) : signale sans
  jamais fusionner. Au signal historique (inclusion contiguë de mots)
  s'ajoutent deux signaux de correspondance EXACTE sur l'ensemble des mots
  — concaténation (`DUPLICATE_CANDIDATE_CONCATENATION`, « france casse » /
  « francecasse ») et permutation (`DUPLICATE_CANDIDATE_PERMUTATION`,
  « cravero motoculture » / « motoculture cravero ») — regroupés sous
  `HIGH_CONFIDENCE_REASON_CODES`, seuls exploitables par un gate bloquant
  (§14.4) : contrairement à l'inclusion, ils n'ont pas de faux positif
  institutionnel connu (une sous-entité distincte ne partage jamais
  exactement les mêmes mots que son entité mère).

Le marqueur de récidive (`dedup.RECURRENCE_MARKERS`) reste la seule garde
contre une fusion erronée d'attaques réellement distinctes sur la même
organisation (Son-Video : deux incidents en 2026, verrouillés par un test
dédié) — aucun alias ne doit jamais contourner cette protection.

### 14.3 `Threat_Actor` : sentinelles génériques

`source_facts._ACTOR_SENTINELS` (déjà existant pour filtrer les mots de
remplissage — « un », « le hacker », « inconnu »...) est étendu avec un
vocabulaire fermé de catégories génériques de menace qui ne sont jamais un
nom d'acteur : ransomware, rançongiciel, cybercriminel(s), pirate(s) — cas
réel corrigé, « revendiquée par le groupe Ransomware » produisait
`Threat_Actor="Ransomware"`. Un vrai groupe nommé (LockBit, Qilin, Akira...)
n'est jamais affecté par construction. `_valid_actor()` reste le point
d'entrée unique pour les 4 extracteurs concernés (FRENCHBREACHES,
CYBERATTAQUE_ORG, RANSOMWARE_LIVE, VEILLE_LLM).

### 14.4 Gate qualité : checklist manuelle de release

`scripts/audit_data_quality.py` reste volontairement hors CI (`ci.yml`
inchangé — les audits spécialisés restent manuels, jamais un gate
obligatoire, cf. §5). Deux contrôles bloquants supplémentaires, au même
niveau que `threat_backfill_candidates` déjà en place, activés via
`--check-regression` :
- `actor_sentinel_candidates` (§14.3) — toute ligne `source_facts.csv`
  dont `Threat_Actor` est une sentinelle générique fait échouer le
  contrôle ;
- `duplicate_high_confidence_candidates` (§14.2) — tout candidat
  concaténation/permutation exacte non résolu par un alias fait échouer le
  contrôle. L'inclusion de mots (containment) reste volontairement **non**
  bloquante : trop de faux positifs institutionnels légitimes pour
  interdire une release à chaque cas ambigu.

**Checklist obligatoire avant toute release**, exécutée à la main (jamais
par la CI) :
```
pytest
python -m cyberwatch check --allow-uninitialized
python -m cyberwatch test-repeat
python scripts/audit_data_quality.py --items data/items.csv \
    --source-facts data/source_facts.csv --check --check-regression
python -m cyberwatch build-site
python -m cyberwatch check --allow-uninitialized
```
Un candidat détecté aujourd'hui (avant correction de la donnée déjà
publiée) est attendu, pas un bug : ce gate documente précisément ce qui
reste à corriger, avant de faire à nouveau confiance à
`quality_baseline.json`.

**Méthode** : les nouveaux alias (§14.2) changent réellement
`Organisation_Key`, donc `Items_Hash`/`Incidents_Hash`, au prochain run
réel → `METHOD_ID` bumpé de `OBS-FR-OI-SIMPLE-SOURCING-7` à `-8`.
`History_Status`/les sentinelles `Threat_Actor` n'entrent dans aucun hash
canonique et n'auraient pas justifié ce bump à eux seuls.

### 14.5 Filet LLM de déduplication (quotidien)

Les deux mécanismes du §14.2 (alias statiques, candidats d'audit
non fusionnants) restent la première ligne, mais laissent volontairement
passer des doublons résiduels qu'aucune règle déterministe ne peut couvrir
sans faux positif — variantes typographiques imprévues, acronymes non
répertoriés, fautes de frappe. Ce filet ajoute une troisième couche,
strictement bornée et jamais autorisée à décider seule une identité :

```
génération de candidats (duplicate_audit.find_daily_llm_candidates)
  -> au plus 1 batch LLM par MAJ réelle (dedup_ai.challenge_candidates_batch)
  -> validations déterministes organisation + incident
  -> registre d'identité organisationnelle (data/organisation_identity_registry.csv)
  -> registre d'identité d'incident (data/incident_dedup_registry.csv)
  -> qualify() -> build_incidents_with_registry() (preuves fortes + verdicts persistés)
```

**Candidats.** Uniquement les items nouveaux ou rafraîchis de la MAJ en
cours contre le corpus historique (jamais toute la base contre elle-même,
§Lot 2). Chaque paire porte des signaux explicites et purement descriptifs
(`duplicate_audit.CandidateSignals` : clé exacte, forme compacte,
permutation de tokens, inclusion, acronyme, `Company_ID` partagé, domaine
victime partagé, score fuzzy) — le fuzzy sert uniquement à *proposer* un
candidat, jamais à l'autoriser : aucun signal, seul ou combiné, ne modifie
`Organisation_Key`. Le filet inclut aussi les fusions automatiques faibles
(`INCIDENT_MERGE_CANONICAL_NAME`, `INCIDENT_MERGE_ALIAS`, corroboration
ransomware) : une égalité de nom et une proximité de date ne valent pas verdict
final. Les rapprochements munis d'un identifiant source commun ou d'une autre
preuve forte ne consomment aucun appel. Au plus 5 candidats sont retenus par
nouvel item, les risques de faux merge étant prioritaires, avec un classement
entièrement déterministe.

**Un seul appel LLM.** `challenge_candidates_batch` structure tous les
candidats retenus du run en une unique requête à sortie structurée. Aucun
candidat n'entraîne un second appel : au-delà de la capacité
(`DEDUP_AI_DAILY_MAX_CANDIDATES`, `DEDUP_AI_MAX_CONTEXT_CHARS`), les
candidats en trop sont explicitement marqués `NOT_REVIEWED_CAPACITY`,
jamais silencieusement ignorés. Zéro candidat implique zéro appel. Le
transport et le budget passent par `llm_runtime` (tâche `dedup`), pas par
une politique de coût parallèle.

**Deux décisions indépendantes.** Le modèle répond `same_organisation` et
`same_incident` séparément (`SAME`/`DIFFERENT`/`UNKNOWN`), avec l'invariant
`same_incident=SAME ⇒ same_organisation=SAME`. Un même organisme peut
légitimement produire `same_organisation=SAME` / `same_incident=DIFFERENT`
(deux compromissions distinctes de SFR, par exemple). Les deux réponses ne
deviennent actionnables qu'après validation déterministe et persistance ; une
réponse `UNKNOWN` ne modifie jamais la production.

**Politique d'application.** Une proposition n'est produite que pour une
décision `OK`/`CACHE_HIT`, avec `same_organisation=SAME` et une confiance
`>= 0.85`. L'identité organisationnelle est persistée même si les événements
sont distincts : un conflit de date ou une récurrence ne change pas l'identité
de la victime.

La décision d'événement est persistée séparément dans
`data/incident_dedup_registry.csv`. `same_incident=DIFFERENT` devient un veto
fort reproductible ; `same_incident=SAME` confirme une fusion ambiguë, y
compris au-delà de la fenêtre éditoriale usuelle. Il ne peut jamais contourner
les trois preuves de séparation fortes : conflit de `Source_Item_ID`, marqueur
de récurrence explicite ou `Event_Date` incompatibles. `UNKNOWN`, confiance
insuffisante ou erreur n'écrivent rien.

**Registre d'identité organisationnelle**
(`data/organisation_identity_registry.csv`, distinct et complémentaire de
`organisation_aliases.csv` qui reste le référentiel statique versionné à la
main) : colonnes `Alias_Key,Canonical_Key,Alias_Raw,Canonical_Raw,Decision,
Origin,Confidence,Evidence,First_Seen,Last_Validated,Model,Prompt_Version,
Input_Hash`. Seules les lignes `Decision=SAME` influencent
`org_identity.effective_organisation_key()`, consultée après les identités
territoriales fortes et avant la clé canonique. Toute collision
(`A→C` puis `A→D`) ou tout cycle (`A→B→A`) est une erreur de qualité
explicite (`org_identity.merge_organisation_identity_rows`), jamais résolue
arbitrairement. Une fois les deux verdicts persistés, le regroupement est
reproductible : le moteur reconstruit les mêmes incidents à chaque run, y
compris `REPLAY`, qui ne consulte jamais le LLM mais lit les deux registres
comme des données canoniques.

**Non bloquant.** Une clé API absente, un timeout, une erreur HTTP, un
budget épuisé ou une sortie structurée invalide n'appliquent aucune
décision et ne bloquent jamais la collecte — le pipeline déterministe
continue. Le statut du filet (`OK`/`NO_CANDIDATES`/`LLM_DISABLED`/
`LLM_ERROR`/`BUDGET_BLOCKED`/`CAPACITY_LIMIT`) et la télémétrie complète
(candidats, décisions, coût, durée) sont journalisés dans
`data/dedup_ai_daily_usage.csv` et affichés par `cyberwatch report`.

**Backfill manuel.** `scripts/backfill_dedup_identity.py` est l'équivalent
volontaire pour rattraper l'historique déjà publié : plusieurs appels
autorisés, mêmes budget/cache/Structured Outputs, jamais lancé
automatiquement par `collect.yml`. `DEDUP_AI_DAILY_ENABLED=1` active le filet
sur les runs réels `maj` et `create`, toujours avec un seul batch borné.


## 15. Résolution des caractéristiques de la fiche incident

La fiche détail ne lit jamais directement une valeur isolée d'un collecteur.
Les faits bruts par source restent conservés dans `source_facts.csv` pour
l'audit ; `fact_resolution.resolve_incident_facts()` produit ensuite une vue
publique unique, déterministe et traçable, exportée dans
`assets/data/facts.json`. Le navigateur ne refait aucun arbitrage métier.

**Doctrine de publication.** Précision avant remplissage : une case vide est
préférée à une caractéristique seulement possible. Sont donc exclus des champs
publics les hypothèses, les faits niés, les catégories explicitement dites non
concernées, les simples populations générales de l'organisation et les mesures
correctives qui ne prouvent pas le vecteur réellement exploité. Une société
opératrice ou une marque victime ne peut pas devenir acteur de menace du seul
fait qu'elle est le sujet grammatical d'une déclaration.

**Volumes et périmètres.** Deux projections de la même phrase-source, du même
nombre et de la même unité sont fusionnées, en conservant le qualificatif
(`environ`, `au moins`, etc.) et le statut le plus documenté. Des unités
différentes restent distinctes. Les types de données atomiques sont séparés des
jeux ou périmètres composés afin de ne pas répéter des coordonnées comme
« systèmes », tout en conservant un périmètre tel que « données de livraison et
de facturation ».

**Présentation prudente.** La fiche parle de données « concernées » et
« documentées », jamais automatiquement « compromises » ou « exposées ».
`confirmed`, `reported`, `claimed`, `unknown`, `hypothesis` et les statuts
négatifs restent portés par le contrat JSON même lorsqu'un composant visuel ne
les affiche pas. Les sources cliquables restent attachées à l'incident et les
preuves textuelles demeurent dans le contrat résolu pour le contrôle.

Cette modification change les caractéristiques publiques d'un incident sans
modifier les faits bruts : `METHOD_ID` est donc bumpé de
`OBS-FR-OI-SIMPLE-SOURCING-9` à `-10`.


## Retrait du fallback des exports ChatGPT globaux (v0.7.38)

Les anciennes tables ChatGPT de `FRENCHBREACHES` et `CYBERATTAQUE_ORG` sont
archivées sous `bench/legacy/veillellm_exports`. Elles ne complètent plus aucun
champ de production : elles étaient figées au 17 août 2026, recréaient deux
sources déjà collectées directement et leur seul effet encore actif était un
fallback de localisation non soumis à un contrat de fraîcheur. Les SourceFacts,
la qualification canonique et les collecteurs directs les remplacent.

`VEILLE_LLM` désigne désormais exclusivement la veille complémentaire
Réunion/Mayotte et suit le contrat d'admission décrit plus haut.

### Référentiel déterministe des familles d’organisations

La qualification `Sector` dispose d'un canal `organisation_family` versionné dans `reference/organisation_families.csv`. Il couvre les familles institutionnelles et organisationnelles dont le nom complet ou le sigle constitue une preuve auto-descriptive : SDIS, préfectures, ministères, collectivités, CCAS/CIAS, organismes sociaux, ARS, établissements hospitaliers, CROUS/rectorats, juridictions, opérateurs publics et organisations syndicales connues.

La préséance est : override manuel → famille organisationnelle déterministe → NAF officiel précis → décision LLM finale. Une correspondance de famille est `HIGH`, auditée avec sa provenance et ne consomme aucun appel LLM. Les sigles ne sont jamais cherchés comme de simples sous-chaînes : leur mode de correspondance et les contre-exemples commerciaux sont testés.

SourceFacts applique désormais le même contrat de rattachement de l'activité à la victime au moment de l'acceptation et au moment de la promotion. Un statut sémantique `accepted` ne peut donc plus masquer une valeur vide publiée. Les abstentions de secteur LLM sont persistées avec `Decision_Status=ABSTAINED` et `Execution_Status=EXECUTED`, afin qu'un replay sans budget conserve `NO_MATCH` au lieu de réécrire l'histoire en `BUDGET_BLOCKED`.
