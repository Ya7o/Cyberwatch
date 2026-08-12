# Méthodologie exécutable OBS-FR-OI

**`Method_ID : OBS-FR-OI-SIMPLE-SOURCING-2`**
**Périmètre :** France métropolitaine, La Réunion, Mayotte, Maurice, Madagascar, Seychelles, Comores.

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
un statut global binaire (`OK` / `DEGRADED`). Ce vocabulaire mélangeait deux
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

**Statut global du run**, à trois niveaux motivés :

| Niveau | Règle | Lecture |
|---|---|---|
| `HEALTHY` | Toutes les sources planifiées sont `OK`. | Base complète |
| `DEGRADED` | Aucune source `CORE_DIRECT` en `FAIL`, mais au moins une source `PARTIAL` ou `FAIL`. | Base utilisable, angles morts listés |
| `BROKEN` | Une source `CORE_DIRECT` en `FAIL`, **ou** `Health_Score < 50`. | Ne pas conclure sur les tendances |

`Health_Score` = moyenne des couvertures pondérée par couche (`CORE_DIRECT` ×3,
autres ×1), les sources `SKIPPED` étant exclues du calcul.

### 1.2 `RANSOMWARE_LIVE` est activée

La version 1 la classait `CANDIDATE_DISABLED` faute d'accès opérationnel en
conversation. En code il s'agit d'une API JSON publique et gratuite fournissant
organisation, date, groupe et pays. La méthode la désignait elle-même comme
prioritaire, les sources françaises étant fortement orientées « fuite de données ».
`HACKMAGEDDON` reste désactivée.

### 1.3 Les couches de veille passent par Google News RSS

La version 1 prévoyait des requêtes de moteur de recherche. Aucun moteur
généraliste n'est appelable gratuitement depuis un script. Google News RSS le
remplace : gratuit, sans clé, et **déterministe dans sa forme** — la requête
exécutée est écrite telle quelle dans `SOURCES`.

Les quatre requêtes Q1–Q4 par entité sont **fusionnées en deux** requêtes reliées
par `OR`, que Google News traite nativement. Le rappel est équivalent pour moitié
moins d'appels : c'est le principal levier de maîtrise de la volumétrie.

Un **contexte territorial** est ajouté à chaque requête (« La Réunion »,
« Mayotte »…), sans quoi « Mairie de Saint-Denis » ramènerait massivement des
résultats de Seine-Saint-Denis.

**Limites assumées** : indexation plus faible des petits médias comoriens et
malgaches, et fenêtre RSS glissante. Ces sources rapportent honnêtement `PARTIAL`
plutôt qu'un faux `OK`.

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

Item_ID     = "ITM-" + SHA256(Source_ID|Published_Date|Organisation_Key|URL)[:16]
Incident_ID = "INC-" + SHA256(Organisation_Key|Component_Start_Date)[:12].upper()
```

Aucun rapprochement flou, aucune fusion assistée par IA. Deux libellés qui ne se
normalisent pas à l'identique restent deux organisations distinctes :
**un faux doublon est préférable à une fusion non reproductible.**

---

## 4. Déduplication et datation

1. Grouper par `Organisation_Key`.
2. Trier par `Published_Date`, `Source_ID`, `URL`, `Item_ID`.
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
| Quotidien (sources directes) | ~30 | 1–2 min |
| Hebdomadaire (balayage complet) | ~270 | 5–10 min |
| `CREATE` initial (année en cours) | ~300 | 10–20 min |

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
