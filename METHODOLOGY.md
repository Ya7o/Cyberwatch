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
