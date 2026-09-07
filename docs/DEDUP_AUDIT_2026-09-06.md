# Audit d'efficacité de la déduplication — 6 septembre 2026

## Verdict

La chaîne conserve les observations et rapproche correctement les identités
simples. Les deux défauts de construction reproduits pendant l'audit ont été
corrigés : une composante ne peut plus dépasser la borne temporelle par chaînage
ransomware et un verdict d'incident `SAME` compatible rejoint désormais une
composante déjà fermée. La reprise et les métriques ont également été séparées.
La qualité réelle des verdicts LLM restera à observer lors des prochaines
collectes, sans balayage historique ni appel réseau de rattrapage.

Les constats ci-dessous décrivent l'état audité avant correction et servent de
preuve de régression.

## Correctifs mis en œuvre

- réunion déterministe par organisation, avec priorité aux identités natives et
  aux décisions `SAME`, puis contrôle de tous les veto et de la fenêtre de 14 jours ;
- suppression du parcours ransomware entre organisations distinctes ;
- réconciliation de la file, statut `RETRY_EXHAUSTED` après trois erreurs réelles
  et maintien d'un statut de revue tant qu'une paire reste en attente ;
- persistance des résolutions de file uniquement avec le snapshot validé ;
- quatre métriques distinctes : doublons potentiellement manqués, fusions faibles,
  `SAME` non regroupés et paires en attente ;
- conservation des anciens champs `Potential_Duplicate_*` pour compatibilité.

Les contre-exemples J0/J13/J26 et A/B/C sont désormais des tests automatisés.

## Périmètre et méthode

Audit du **répertoire de travail actuel**, comprenant les modifications locales
et fichiers non suivis, et non du seul commit `374c9d6`. Lecture de la chaîne
identité → enrichissement → déduplication → publication, des registres, de la
configuration de collecte et des tests. Aucun appel réseau/LLM, aucune collecte,
aucune modification du code métier ou des données canoniques.

Pièces reproductibles :

- `audit/dedup_2026-09-06/probe.py` : mesures et cas limites hors réseau ;
- `audit/dedup_2026-09-06/measurements.json` : résultats complets ;
- `audit/dedup_2026-09-06/pytest.txt` : **1 044 tests réussis** après correction.

Commandes depuis la racine du dépôt :

```bash
rtk proxy .venv/bin/python audit/dedup_2026-09-06/probe.py
rtk pytest tests/ -q
```

Les reproductions sont des contre-exemples du comportement courant, pas des
incidents réels nouvellement découverts. L'audit ne prétend pas connaître la vérité
métier de toutes les paires à partir des seuls titres.

## Mesures sur le corpus

| Mesure | Résultat | Interprétation |
|---|---:|---|
| Observations → incidents | 54 → 35 | Réduction de 35,2 %, pas un taux de précision |
| Groupes | 17 simples, 17 doubles, 1 triple | 18 incidents corroborés par plusieurs observations |
| Identifiants d'observation ou natifs dupliqués | 0 | Bonne conservation de l'identité technique |
| Observations absentes des groupes | 0 | Aucune perte constatée sur ce corpus |
| Paires `MERGE` séparées dans le corpus | 0 | Cohérence paire/groupe sur les données présentes |
| Dates d'événement renseignées | 0 / 54 | Le corpus n'exerce pas les veto sur dates d'événement |
| Identifiants natifs renseignés | 50 / 54 | Cyberattaque 22/22, FrenchBreaches 28/28 ; BonjourLaFuite et Ransomware.live 0/2 chacun |
| Registre d'incidents | 3 `SAME` | 1 décision historique LLM, 2 validations manuelles |
| Registre dynamique d'organisations | 1 alias | Validation manuelle de Répar'Store / Répar’stores |
| Candidats LLM, balayage de toute la base | 14 paires, 8 couples de noms | Aucun signal structurel fort ; similarité textuelle seule |
| Candidats écartés par le top 5 | 0 | Pas de saturation constatée sur ce corpus |
| Construction des groupes | environ 0,10 s | Suffisant à cette taille |
| Génération des candidats, base entière | environ 0,13 s | Mesure locale, sans transport ni LLM |
| Corpus d'identité | 16/16 positifs couverts, 0 fusion négative connue | Couverture des candidats, pas rappel des fusions abouties |

Les 14 candidats incluent par exemple « Frères Toque / FFTir » et « Easypara /
Pass Pass ». Ce sont des rapprochements à filtrer, pas des doublons établis.
Leur présence illustre le bruit du seuil fuzzy 0,5. Sans annotation exhaustive,
aucun pourcentage de précision ou de rappel réel n'est justifié.

Les trois lignes `SAME` ne signifient pas trois fusions supplémentaires : avec
les alias et libellés actuels, retirer seulement le registre d'incidents conserve
35 groupes. Le bénéfice marginal du LLM ne peut donc pas être déduit du nombre de
verdicts persistés, surtout après les corrections manuelles du 6 septembre.

La reconstruction directe des incidents conserve les identifiants et les champs
de regroupement. Une différence sectorielle apparaît pour Jouvet SAS
(`INC-F87083F98EA4`, Construction / BTP → Inconnu). Ce test appelle le constructeur
bas niveau sur les CSV, sans rétablir les décisions sectorielles attachées aux
objets par l'enrichissement : il ne constitue pas un test du REPLAY opérationnel
complet et cette différence n'est pas classée comme défaut de déduplication.

## Constats prioritaires

### 1. P1 — Le second passage ransomware peut fusionner des observations sur 26 jours

**Code :** `cyberwatch/dedup.py:328–349`, `STRONG_KEEP_REASON_CODES` à la ligne 30.

Reproduction : même organisation, menace ransomware, observations A le 1er août
(Cyberattaque), B le 14 (Ransomware.live), C le 27 (FrenchBreaches). A–B et B–C
satisfont chacune la corroboration à 14 jours. A–C renvoie pourtant
`KEEP_SEPARATE / INCIDENT_KEEP_TIME_GAP`, avec 26 jours d'écart.

**Résultat obtenu : `[A, B, C]` dans un seul groupe.** Le second passage exige
une paire corroborante et l'absence de veto fort, mais ne vérifie pas l'étendue
temporelle de la composante résultante. Le simple dépassement temporel n'est pas
un veto fort. Le garde-fou de l'extension initiale ne protège donc pas cette passe.

Impact : épisodes éloignés regroupés et incidents sous-comptés. Contre-exemple
reproduit, pas d'occurrence identifiée dans les 54 observations présentes.

**Correction recommandée :** appliquer un invariant temporel à chaque réunion
de composantes, sur des dates sémantiquement comparables, en conservant tous les
veto. Tester explicitement J0/J13/J26 et les mélanges événement/publication.

### 2. P2 — Un `SAME` validé reste sans fusion quand un autre item a fermé le groupe

**Code :** `cyberwatch/dedup.py:290–311`, `cyberwatch/dedup_review.py:55–57`.

Reproduction : A le 1er août et B le 2 proviennent de FrenchBreaches avec des
identifiants natifs différents. C le 8 provient de Cyberattaque. Un verdict
`SAME` sur A–C passe `validate_ai_incident_decision()` et le moteur paire à paire
renvoie `INCIDENT_MERGE_LLM_CONFIRMED`.

**Résultat obtenu : `[A]`, `[B]`, `[C]`.** B a fermé la composante de A ; C n'est
comparé qu'à la composante courante de B. Le second passage ne répare que les
corroborations ransomware. A–C pourrait être regroupé sans violer le veto A–B.

Le suivi sait nommer ce cas `SAME_NOT_GROUPED`, mais ce statut n'est pas repris
automatiquement. Il ne suffit donc pas de valider et persister le verdict.
Une variante purement déterministe à J1/J2/J3 laisse aussi une paire `MERGE`
séparée ; le générateur quotidien exclut cette paire puisqu'il la croit déjà
tranchée (`duplicate_audit.py:523–527`).

**Correction recommandée :** rechercher les composantes compatibles de la même
organisation, y compris celles déjà fermées, en privilégiant les liens explicites
validés et en revérifiant tous les veto. Ne pas remplacer cette recherche par une
fermeture transitive sans contrainte, qui aggraverait le constat 1.

### 3. P2 — Le compteur « doublons potentiels » mesure ici des fusions déjà réalisées

**Code :** `cyberwatch/production.py:144`, `cyberwatch/duplicate_audit.py:315–400`.

`metric_row()` compte indistinctement tout `find_audit_candidates(items)` sous
`Potential_Duplicate_Pairs`. Sur la base actuelle, cette fonction retourne
**20 paires `POSSIBLE_FALSE_MERGE`, toutes déjà dans le même incident**, et aucun
`POSSIBLE_MISSED_DUPLICATE`. Les raisons sont 15 fusions sur nom et 5 sur alias.

Le calcul produirait 57,14 paires pour 100 incidents sous l'étiquette « doublons
potentiels », alors qu'il mesure ici la solidité de fusions existantes. De plus,
cet audit appelle `decide_merge()` sans le registre d'incidents : une confirmation
déjà persistée ne retire pas nécessairement la paire des fusions faibles à revoir.

Le benchmark d'identité explicite désormais sa portée
`candidate_generation_only_not_completed_merges`, ce qui est positif. Les anciens
champs `known_duplicate_recall_*` restent néanmoins des mesures de couverture.
`cmd_validate_business()` ne bloque que les fusions négatives connues ; il ne
vérifie pas un objectif de rappel des incidents effectivement regroupés.

**Correction recommandée :** séparer « doublons potentiellement manqués »,
« fusions à vérifier », « décisions validées non appliquées » et « paires non
examinées ». Évaluer le rappel et la précision sur des groupes d'incidents
annotés, avec le transport LLM simulé pour la mécanique et une évaluation
distincte des verdicts réellement produits.

### 4. P2 opérationnel — La reprise des paires non examinées n'est pas établie sur le dernier run

**Données :** `data/dedup_ai_daily_usage.csv`, absence de
`data/dedup_review_queue.json` lors de l'audit.

Le dernier run journalisé, `RUN-20260906T085824`, indique `LLM_DISABLED`,
11 candidats, zéro sélection, zéro appel et `Review_Required=0`. La cause de la
désactivation n'est pas renseignée dans cette ligne historique. Le workflow
actuel active explicitement le filet et prévoit un secret ; cela ne prouve pas
que ce dernier run disposait d'une clé, ni que le workflow distant actuel réussit.

Le code de reprise récemment présent conserve bien les nouveaux candidats
désactivés ; les tests le confirment. Mais `run_daily_dedup_net()` ne relance que
les nouveautés ou la file persistée (`runner.py:601`). Sans file, les candidats
historiques qui quittent la fenêtre de collecte ne sont pas réintroduits
automatiquement. Les 37 candidats du run du 31 août étaient également marqués
désactivés ; leurs ensembles peuvent se recouvrir, il ne faut pas les additionner.

Autre limite reproduite : après trois erreurs, une paire est exclue des reprises
(`dedup_review.py:27`) tandis qu'un run vide affiche `NO_CANDIDATES`
(`dedup_ai_telemetry.py:22`). `dedup_review_required` reste correctement à 1 et
la surveillance de production peut encore alerter : l'information n'est pas
entièrement perdue, mais le statut principal est ambigu et la paire reste bloquée.

**Action recommandée :** réconcilier une fois les paires historiques encore
pertinentes avec la file actuelle, puis vérifier un run réel activé. Exposer un
statut explicite de reprise épuisée avec une action de revue. Ne pas assimiler
« zéro appel » ou « aucun nouveau candidat » à « aucune revue restante ».

## Limites de politique et de performance

**Identifiant de publication ≠ identifiant d'incident.** À
`dedup.py:144–147`, deux identifiants natifs différents d'une même source imposent
un veto absolu. Deux articles Cyberattaque décrivant une notification puis son
suivi restent donc séparés et ne sont jamais soumis au LLM. C'est une politique
conservatrice existante, pas une régression nouvellement introduite. Elle protège
contre la fusion d'épisodes distincts mais plafonne le rappel ; préciser par
source si l'identifiant représente un article ou un incident.

**Les fusions par nom à trois jours ne sont pas réexaminées par le filet LLM.**
Une identité identique et des publications proches suffisent, même si les
qualifications de menace divergent. Ne pas utiliser la menace seule comme veto
automatique : les sources peuvent qualifier différemment un même incident.
En revanche, conserver une revue ciblée des conflits étayés est nécessaire pour
mesurer les faux regroupements. Un `same_organisation=SAME` avec
`same_incident=UNKNOWN` peut également entraîner une fusion par nom après ajout
de l'alias ; c'est l'effet des règles actuelles, pas une confirmation LLM de
l'incident.

**La croissance du coût CPU est déjà visible.** Le second passage parcourt les
composantes de toutes les organisations entre elles, même en l'absence complète
de ransomware. Mesure synthétique sur des organisations toutes distinctes :
environ **0,35 s pour 100 items, 2,8 s pour 300**. Un triplement produit environ
huit fois le temps, cohérent avec le parcours quadratique du code. Ces mesures
locales uniques ne sont ni un SLA ni une extrapolation de latence en production.
Restreindre cette passe aux organisations et sources éligibles, et mémoriser les
clés/dates. La génération quotidienne reste en O(nouveautés × historique) ; le
top 5 limite ce qui part au LLM, pas le coût du parcours de l'historique.

## Ordre de traitement proposé

1. Borne temporelle globale et test J0/J13/J26, avant toute hausse du rappel.
2. Application effective des `SAME` aux composantes compatibles ; régression
   A/B/C et contrôle `SAME_NOT_GROUPED`.
3. Compteurs séparés et reprise des candidats historiques du run désactivé.
4. Évaluation de précision/rappel sur des incidents annotés, incluant suivis
   éditoriaux, récidives, homonymes et dates d'événement contradictoires.
5. Réduction des comparaisons entre organisations et du bruit des candidats.

Les 1 044 tests réussis forment un socle de non-régression utile. Leur réussite,
la réduction de 54 à 35 lignes et les 16/16 noms couverts ne certifient pas,
séparément ou ensemble, l'efficacité réelle de la déduplication des incidents.
