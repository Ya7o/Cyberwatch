# Audit des secteurs non déterminés — production Cyberwatch

**Date : 5 septembre 2026. Livrable : diagnostic et plan correctif à transmettre.**

## 1. Conclusion décisionnelle

**La cause principale est une rupture de transmission entre les faits extraits et le secteur canonique.** Le LLM reconnaît déjà plusieurs activités et secteurs, mais l'enrichissement qui construit les incidents ne reçoit pas ces faits. Le tableau de bord affiche ensuite fidèlement le secteur resté `Inconnu`.

Deux défauts supplémentaires expliquent pourquoi connecter simplement tous les résultats du LLM ne suffirait pas : certaines descriptions sont éliminées puis figées en abstention dans le cache ; d'autres classements sont contradictoires ou insuffisamment étayés.

**Décision proposée :** corriger la transmission, la validation du couple activité/secteur et la traçabilité ; reprendre les incidents concernés avec des preuves vérifiées ; ajouter un contrôle de bout en bout avant publication. Ne pas remplacer automatiquement les inconnus par un secteur générique.

### Périmètre et chiffres vérifiés

Snapshot publié après la collecte du **4 septembre 2026 à 15:48:57 UTC+4**, commit [`c80821f66d747ba4866a48e39b7d05b55cc07b56`](https://github.com/Ya7o/Cyberwatch/commit/c80821f66d747ba4866a48e39b7d05b55cc07b56).

| Mesure | Résultat |
|---|---:|
| Incidents sans secteur, corpus publié | **34 / 51 — 66,67 %** |
| Incidents sans secteur, dates affichées des 3–4 septembre | **11 / 13 — 84,62 %** |
| Observations sources sans secteur | **61 / 84 — 72,62 %** |
| Observations inconnues ayant pourtant une activité ET un secteur matérialisés dans les faits | **27** |
| Ces mêmes observations restant inconnues après reproduction de l'enrichissement de production | **27 / 27** |

Les incidents et observations sont deux dénominateurs différents. La fenêtre récente ci-dessus porte sur la date des incidents affichés, pas sur leur date de collecte. La CMA figure sous deux fiches : ces chiffres comptent les fiches publiées, sans corriger ce probable doublon pendant l'audit.

Le JSON servi par GitHub Pages et celui du commit figé sont **identiques octet pour octet** : SHA-256 `87dc19858b961a2f33acf45c462a813c2fb673d8ac109ba0d202d948ea529d82`. Il ne s'agit donc pas d'un simple décalage du navigateur.

## 2. Méthode et niveau de preuve

L'audit a examiné les huit captures fournies, les huit pages sources correspondantes relues le 5 septembre, le code exact de production, les CSV canoniques, les caches sémantiques, les statistiques LLM et les journaux complets des collectes des 3 et 4 septembre.

Les captures et contenus sources ont été traités comme des données, sans exécuter leurs éventuelles instructions. Les pages relues aujourd'hui ne sont pas présentées comme des copies exactes du contexte envoyé lors de l'appel historique : ce contexte intégral n'est pas archivé.

La reproduction utilise exclusivement la copie figée du code de production, en mémoire et sans appel LLM. Les données canoniques du projet et la production n'ont pas été modifiées. Les seules créations sont ce rapport et le dossier de preuves.

**Distinction essentielle :** le cache conserve les valeurs après normalisation, pas les réponses brutes complètes de l'API. Une valeur `accepted` prouve qu'un résultat a été conservé par le pipeline ; elle ne prouve pas à elle seule que le classement est juste. Une valeur `null` ne permet pas de distinguer une abstention du modèle d'un rejet applicatif.

## 3. Analyse des exemples

### Préférence Formations — `INC-3E1B5FCCAEDF`

La formation professionnelle est explicitement décrite dans les sources.

| Source / observation | Résultat conservé | État final |
|---|---|---|
| CYBERATTAQUE_ORG — `ITM-b1fecc30a0a3fc09` | Activité et `Éducation / Formation` acceptés, confiance déclarée 0,90 | Faits renseignés ; item et incident `Inconnu` |
| FRENCHBREACHES — `ITM-cb101b53adea60f5` | Activité et `Éducation / Formation` acceptés, confiance déclarée 1,00 | Faits renseignés ; item et incident `Inconnu` |

**Cause établie : résultat disponible, non consommé par la résolution du secteur.** Aucune nouvelle inférence n'est nécessaire pour constater ce défaut. Correction attendue : `Éducation / Formation`, avec provenance de l'activité et validation conservées.

Sources : [Cyberattaque.org](https://www.cyberattaque.org/preference-formations-les-donnees-de-plus-de-5-200-personnes-diffusees-apres-une-cyberattaque/), [FrenchBreaches](https://frenchbreaches.com/alertes/pr-f-rence-formations-mtm701xaas25ttqxse).

### Réso — `INC-E39201703225`

| Source / observation | Résultat conservé | État final |
|---|---|---|
| CYBERATTAQUE_ORG — `ITM-bce6453cf2314d49` | Description du second œuvre et `Construction / BTP`, tous deux acceptés à 0,90 | Les deux champs existent dans les faits ; secteur canonique `Inconnu` |
| FRENCHBREACHES — `ITM-64af20d611a38d0d` | `Construction / BTP` accepté à 1,00 ; description en abstention | Secteur écarté lors de la matérialisation |

**Cause principale établie :** la preuve disponible chez Cyberattaque.org ne rejoint pas l'incident. Le second canal présente aussi le défaut de couple activité/secteur décrit pour ZeroGaspi.

**Point de taxonomie à trancher avant correction définitive :** le résultat LLM est `Construction / BTP`. Le site officiel présente aussi Réso comme un négoce spécialisé. Si Cyberwatch classe selon la filière métier, BTP est cohérent ; si la règle est l'activité économique principale du distributeur, `Commerce / Distribution` doit être examiné. Cette nuance ne justifie pas la perte silencieuse du résultat. [Présentation officielle de Réso](https://www.reso.fr/qui-sommes-nous/).

Sources d'incident : [Cyberattaque.org](https://www.cyberattaque.org/reso-plus-de-500-000-fichiers-internes-dans-une-fuite-massive-apres-une-cyberattaque/), [FrenchBreaches](https://frenchbreaches.com/alertes/reso-mtlxxb9d9050x5hmr8q).

### ZeroGaspi — `INC-F8CDDC2DD3B7`

| Source / observation | Description dans le cache | Secteur dans le cache | Faits publiés |
|---|---|---|---|
| CYBERATTAQUE_ORG — `ITM-0f0716ce4755d459` | `abstained`, `null`, `misses=2` | `Commerce / Distribution`, `accepted`, confiance 0,90 | Activité et secteur vides |
| FRENCHBREACHES — `ITM-4db2ae12f71a1693` | `abstained`, `null`, `misses=2` | `Commerce / Distribution`, `accepted`, confiance 0,80 | Activité et secteur vides |

**Cause immédiate établie :** le code refuse de matérialiser le rapprochement sectoriel si la description LLM associée n'a pas été acceptée. Le cache garde pourtant le secteur en `accepted`, ce qui rend ses statuts trompeurs pour un audit superficiel.

**Pourquoi la description a-t-elle disparu ?** Le motif historique exact est indémontrable avec les traces conservées. Le validateur exige notamment que la citation de description rattache textuellement l'activité à l'organisation. Une citation exacte de l'activité qui omet le nom peut donc être rejetée. Une reproduction avec une réponse simulée démontre ce mécanisme ; elle ne prétend pas reconstituer la réponse brute historique.

**Aggravants reproduits :**

- Un premier résultat manquant sur un nouveau champ sémantique est directement stocké avec `misses=2` et `abstained`. Ce compteur ne prouve donc pas deux tentatives.
- L'abstention est ensuite considérée comme un champ satisfait pour le même contenu et la même version ; elle n'est pas spontanément réexaminée.
- La phrase complète décrivant la commercialisation en ligne ne fournit aucune activité au fallback déterministe testé, et son classement direct retourne également `Inconnu` : le vocabulaire fermé ne couvre pas cette formulation.

Correction attendue : `Commerce / Distribution`, après réextraction/validation du couple avec preuve rattachée à ZeroGaspi. Il faut corriger cette étape **et** la transmission vers l'incident.

Sources : [Cyberattaque.org](https://www.cyberattaque.org/zerogaspi-une-base-de-80-000-clients-en-vente-apres-une-cyberattaque/), [FrenchBreaches](https://frenchbreaches.com/alertes/zerogaspi-mtly357yaln2xfqzy4).

### Chambre de Métiers et de l'Artisanat d'Occitanie

Deux fiches sont présentes : `INC-B7DBF665E661` et `INC-619638DA1C52` (« CMA Occitanie »).

- FrenchBreaches, `ITM-9c16af75e968a0f8` : description essentiellement nominale acceptée et `Association / Syndicat` accepté à 0,90, puis non transmis au secteur canonique.
- Cyberattaque.org, `ITM-1a7a19bfd19ae7f2` : description en abstention, `Services aux entreprises` accepté à 0,80 dans le cache, puis écarté des faits.
- Le classificateur déterministe renvoie `Inconnu` sur le nom développé mais `Commerce / Distribution` sur la description « Chambre de Métiers et de l'Artisanat. » : une règle range explicitement les chambres de métiers dans le commerce.

**Ce cas cumule rupture de transmission et erreur de taxonomie.** Trois propositions différentes ne constituent pas trois preuves valides. La CMA est un établissement public ; le secteur recommandé dans la taxonomie actuelle est `Administration / Collectivité`, à inscrire dans une règle documentée pour les organismes consulaires. [Annuaire officiel Service Public](https://lannuaire.service-public.gouv.fr/occitanie/haute-garonne/d8b3d986-d96a-4f1d-9ea8-1eba9e6aeea7).

Le rapprochement des deux fiches doit être vérifié sur leur identité et l'événement ; ne pas fusionner automatiquement à partir du seul secteur. Sources : [FrenchBreaches](https://frenchbreaches.com/alertes/chambre-de-m-tiers-et-de-l-artisanat-d-occitanie-mtktlb1edwrd1ok63hq), [Cyberattaque.org](https://www.cyberattaque.org/chambre-de-metiers-et-de-lartisanat-cyberattaque/).

## 4. Causes racines et preuves techniques

### R1 — Le consommateur métier manque en production — établi, priorité P0

Chaîne constatée :

```text
Article → extraction sémantique → normalisation → cache par champ
       → source_facts.csv : Activity_Description / Activity_Sector_Match
       → finalize_snapshot(items uniquement) → référence manuelle / déduplication
       → incidents.csv : Secteur=Inconnu → JSON → badge « Secteur non déterminé »
```

Dans [`runner.py`, lignes 808–810](https://github.com/Ya7o/Cyberwatch/blob/c80821f66d747ba4866a48e39b7d05b55cc07b56/cyberwatch/runner.py#L808), les faits sont fusionnés, puis `finalize_snapshot(report.items)` est appelé **sans les faits**. [`enrichment.py`, ligne 236](https://github.com/Ya7o/Cyberwatch/blob/c80821f66d747ba4866a48e39b7d05b55cc07b56/cyberwatch/enrichment.py#L236) enrichit avec le référentiel et construit les incidents, sans exploiter les descriptions extraites.

La reproduction sur 84 observations conserve inconnues les **27** observations déjà pourvues du couple activité/secteur. Le prompt ne peut pas réparer un consommateur absent.

### R2 — Validation séparée de champs dépendants, puis abstention persistante — établi

[`source_facts_ai.py`, ligne 867](https://github.com/Ya7o/Cyberwatch/blob/c80821f66d747ba4866a48e39b7d05b55cc07b56/cyberwatch/source_facts_ai.py#L867) valide la description avec un contrôle de rattachement à la victime, mais le secteur avec des conditions différentes. [`source_facts.py`, ligne 952](https://github.com/Ya7o/Cyberwatch/blob/c80821f66d747ba4866a48e39b7d05b55cc07b56/cyberwatch/source_facts.py#L952) refuse ensuite le secteur si la description LLM manque. Le même garde existe pour l'autre source autour de la ligne 1105.

[`_store_field_cache`, ligne 1266](https://github.com/Ya7o/Cyberwatch/blob/c80821f66d747ba4866a48e39b7d05b55cc07b56/cyberwatch/source_facts_ai.py#L1266) transforme immédiatement l'absence de certains nouveaux champs en abstention définitive pour cette version ; [`_read_field_cache`, ligne 1188](https://github.com/Ya7o/Cyberwatch/blob/c80821f66d747ba4866a48e39b7d05b55cc07b56/cyberwatch/source_facts_ai.py#L1188) la considère ensuite satisfaite.

Le principe de ne pas publier un secteur sans preuve liée à la victime reste utile. Il faut réparer la validation et la reprise du couple, pas supprimer ce garde.

### R3 — Taxonomie et arbitrage insuffisants — établi

La règle des chambres de métiers est erronée pour un classement institutionnel. D'autres contradictions sont visibles dans le même lot : ColisExpat reçoit `Transport / Logistique` et `Numérique / Technologie` selon la source ; Delicity reçoit `Hébergement / Tourisme / Restauration` et `Commerce / Distribution`.

Il faut distinguer l'activité de la victime, son canal numérique et le secteur de ses clients. Un score de confiance fourni par le LLM ne résout pas ces arbitrages et ne constitue pas une probabilité calibrée d'exactitude.

### R4 — L'observabilité masque l'étape réelle de perte — établi

- Le code ne sauvegarde que le résultat normalisé après lecture du JSON brut ([ligne 1445](https://github.com/Ya7o/Cyberwatch/blob/c80821f66d747ba4866a48e39b7d05b55cc07b56/cyberwatch/source_facts_ai.py#L1445)). Pas de motif détaillé par champ rejeté dans le cache examiné.
- [`site.py`, ligne 19](https://github.com/Ya7o/Cyberwatch/blob/c80821f66d747ba4866a48e39b7d05b55cc07b56/cyberwatch/site.py#L19) attribue systématiquement `NO_EVIDENCE` aux secteurs inconnus, même lorsqu'une preuve existe dans les faits. Tout secteur renseigné devient symétriquement `confirmed`, sans examen de sa provenance.
- Le cache et les statistiques SourceFacts portent `gpt-5-nano`, tandis que le transport partagé route la tâche vers **`gpt-4o-mini`** par défaut et enregistre ce modèle comme effectivement utilisé dans `llm_usage.json`. La reproduction confirme le routage. Le cache conserve le modèle demandé, pas nécessairement le modèle exécuté.
- Le 4 septembre : SourceFacts annonce **30 appels réussis, 0 échec, 2 appels bloqués**. Son compteur local atteint son plafond de 30 appels. Le transport partagé affiche **39 appels réussis au total, 0 échec, 0 blocage partagé**, coût total **0,0201825 $** sous le plafond de **0,03 $**. Les deux compteurs observent des frontières différentes. Les deux blocages locaux ne sont pas attribuables à des champs/items précis dans les traces examinées ; ils ne doivent pas être cachés. Ils n'expliquent pas la non-transmission des secteurs déjà matérialisés.
- SourceFacts estime son coût à **0,005995 $**, contre **0,01364655 $** pour cette tâche dans le transport partagé : le calcul spécialisé utilise le modèle demandé. L'estimation du transport est la référence la mieux étayée disponible, pas une facture fournisseur.

Logs examinés : [collecte du 3 septembre](https://github.com/Ya7o/Cyberwatch/actions/runs/33751597159), [collecte du 4 septembre](https://github.com/Ya7o/Cyberwatch/actions/runs/33869699921). Les étapes de collecte, validation et publication sont en succès malgré la proportion d'inconnus.

### R5 — Corrections locales présentes mais absentes de la version publiée — établi

Le poste local est sur `374c9d6`, avec de nombreuses modifications en cours. Il possède notamment `cyberwatch/sector_resolution.py` et l'audit du 1er septembre. **Le résolveur et `data/sector_resolution.csv` sont absents du commit publié examiné.** Les résultats locaux « zéro inconnu » du précédent document ne décrivent donc pas la production actuelle.

Cette piste locale constitue du travail préparatoire, mais doit être revue avant toute publication : son repli forcé vers `Services aux entreprises` ne prouve pas un secteur reconnu ; un rejeu peut même transformer un secteur précédemment estimé en `EXISTING_SECTOR` / `confirmed`, faute de provenance relue. Ses règles d'activité peuvent aussi primer sur une référence exacte ou un résultat sémantique plus pertinent. La correction ne doit pas être un déploiement aveugle de l'ensemble du dossier local.

## 5. Plan correctif exécutable

| Priorité / responsable proposé | Travail à réaliser | Preuve de clôture attendue |
|---|---|---|
| **P0 — Responsable pipeline** | Brancher un résolveur sectoriel unique sur les faits fusionnés, avant construction des incidents ; transmettre décision et provenance jusqu'au JSON. Prévoir la résolution au niveau incident lorsque plusieurs sources complètent le même événement. | Préférence Formations et Réso ne perdent plus leur preuve entre cache, faits, item et incident ; aucun conflit n'est tranché par l'ordre des lignes. |
| **P0 — Responsable extraction** | Valider activité, rattachement à la victime, secteur et preuve comme un ensemble dépendant. Réutiliser un voisinage textuel explicite pour les citations sans répétition du nom, en excluant tiers et homonymes. | ZeroGaspi classé avec preuve vérifiée ; une activité de fournisseur citée dans le même article n'est jamais attribuée à la victime. |
| **P0 — Responsable données** | Créer une version corrective ciblée des champs activité/secteur ; réexaminer les abstentions et les secteurs orphelins concernés. Privilégier le texte archivé, sinon dater la réhydratation. Ne pas payer à nouveau les autres champs valides. | Journal des champs invalidés, réparés, toujours absents et en conflit ; cache cohérent après reprise. |
| **P0 — Référent métier** | Définir activité principale vs filière ; arbitrer CMA, Réso, ColisExpat, Delicity ; corriger la règle des chambres consulaires. Ajouter des références exactes sourcées pour les cas validés. | Jeu de vérité attendu et documenté, avec motifs ; absence de classement automatique sur la seule clientèle ou le mot « plateforme ». |
| **P1 — Responsable observabilité** | Archiver requête utile, réponse brute, sortie normalisée, statut et rejet par champ ; relier Run_ID, Item_ID, Incident_ID, URL, hash du contenu, versions du prompt/schéma/validateur/taxonomie et identifiant de requête. | Pour chaque inconnue, le premier point de perte est identifiable sans nouvel appel LLM. |
| **P1 — Responsable LLM** | Enregistrer modèle demandé ET modèle réellement exécuté, usage/coût du transport, budget bloquant et champs différés. Distinguer absence prouvée, rejet récupérable, erreur technique et budget. | Plus d'étiquette modèle ambiguë ; rapprochement des compteurs local/global ; chaque blocage est attribué. |
| **P1 — Responsable publication / QA** | Ajouter les contrôles de cohérence de bout en bout et les métriques ci-dessous dans le chemin réel de publication. Remplacer `NO_EVIDENCE` générique par la cause réelle. | La CI reproduit la perte observée sur le code initial, puis passe sur la correction ; une régression bloque la nouvelle publication. |
| **P1 — Responsable exploitation** | Préparer une branche corrective propre depuis la version réellement publiée, isoler les changements pertinents, revoir le diff, puis reprendre les secteurs du corpus en place et régénérer les artefacts. | Rapport avant/après sur les 51 incidents ; identifiants et autres champs inchangés hors correction séparément justifiée. |

### Ordre de réalisation

1. **Figer la référence d'audit** et préparer le jeu de cas annotés : quatre exemples, autres inconnus récents et cas négatifs.
2. **Réparer transmission et validation**, avec rejeu local sans publication ; arbitrer les cas taxonomiques avant de définir leurs résultats attendus.
3. **Exécuter une reprise ciblée du corpus existant.** Une simple collecte « aujourd'hui/hier » ne suffit pas pour récupérer les incidents plus anciens. Ne pas reconstruire les identités ni effacer l'historique.
4. **Comparer et valider le résultat**, y compris les contradictions entre sources et la stabilité au second rejeu.
5. **Publier la correction et les artefacts ensemble** via le chemin unique du projet ; contrôler le JSON réellement servi et surveiller les sept collectes suivantes.

Conserver le snapshot précédent pour retour arrière si les contrôles échouent. Une publication bloquée doit produire une alerte explicite et laisser disponible le dernier snapshot validé.

## 6. Recette et critères d'acceptation

**Garantie visée : 100 % des incidents ayant une activité exploitable et un rattachement validé sont classés ou arbitrés explicitement ; aucun résultat valide ne se perd silencieusement.** On ne peut pas garantir l'exactitude de tous les secteurs futurs à partir de sources parfois absentes ou ambiguës. L'absence réelle de preuve doit rester visible, avec une action de recherche/révision, au lieu d'être maquillée.

| Contrôle | Critère mesurable |
|---|---|
| Couverture des exemples | Préférence Formations = Éducation / Formation ; ZeroGaspi = Commerce / Distribution ; CMA = Administration / Collectivité selon règle validée ; Réso = classement issu de l'arbitrage documenté. |
| Conservation des preuves | **0 incident `Inconnu` avec une décision sectorielle validée, non contradictoire et exploitable disponible** dans ses observations. |
| Couple activité/secteur | **0 secteur `accepted` orphelin** dans la vue des décisions publiables ; états techniques et métier distincts. |
| Corpus récent | Revue des **11 fiches inconnues des 3–4 septembre** ; chaque fiche reçoit un secteur prouvé ou une raison explicite et une action assignée. |
| Corpus complet | Revue des **34 inconnus** ; aucun classement forcé en Services aux entreprises pour satisfaire un taux. |
| Exactitude | **100 % des cas annotés de recette** respectés ; inclure tiers, homonymes, négations, articles sans activité, noms de marques et activités multiples. Étendre le jeu à chaque catégorie de la taxonomie avant d'affirmer une couverture globale. |
| Désaccords | Deux sources proposant des secteurs incompatibles produisent un arbitrage traçable, pas une sélection implicite du premier résultat. |
| Cache et reprise | Une version corrective réexamine les rejets récupérables ; une preuve réellement absente reste distincte d'un échec technique ; appels et tentatives comptés réellement. |
| Idempotence | Deuxième reprise : décisions, confiance et provenance identiques ; un secteur estimé ne devient pas confirmé sans nouvelle preuve. |
| Publication | Concordance vérifiée entre décisions, CSV incidents, `incidents.json`, `latest.json`, filtres et badges du dashboard. |
| Traçabilité | **100 % des décisions** ont statut, motif, version et références ; toute inférence expose sa preuve et son niveau de validation. |
| Exploitation | Suivi par source et catégorie : preuves présentes, rejetées, conflits, budgets bloqués, secteurs résolus et inconnus réels ; vérification sur sept collectes consécutives. |

Le taux brut d'inconnus reste un indicateur utile mais ne doit pas être l'unique garde. Le critère bloquant prioritaire est la **perte d'une preuve validée**. Le seuil global d'alerte peut être défini après revue du corpus ; des mentions locales de 10 % ou 20 % ne remplacent pas une politique cohérente et effectivement déployée.

### Liste des inconnus récents à traiter

| Date affichée | Fiche | Constat principal |
|---|---|---|
| 04/09 | Association des maires de France | Couple matérialisé sur une source, non transmis ; autre description en abstention. |
| 04/09 | Préférence Formations | Deux couples cohérents matérialisés, non transmis. |
| 03/09 | BCTI | Couple matérialisé sur FrenchBreaches, mais description surtout nominale : preuve d'activité à renforcer avant promotion. |
| 03/09 | Chambre de Métiers et de l'Artisanat d'Occitanie | Couple matérialisé, taxonomie incorrecte à arbitrer. |
| 03/09 | Charbonneaux-Brabant | Activité et Industrie / Manufacture matérialisés sur Cyberattaque.org ; conflit potentiel avec le mot « distribution » dans les règles. |
| 03/09 | CMA Occitanie | Description en abstention, secteur orphelin ; probable doublon à vérifier séparément. |
| 03/09 | ColisExpat | Deux couples matérialisés mais secteurs contradictoires. |
| 03/09 | Delicity | Deux couples matérialisés mais secteurs contradictoires. |
| 03/09 | Reso | Couple BTP matérialisé sur une source ; arbitrage activité/filière. |
| 03/09 | Tisséo | Deux couples Transport / Logistique cohérents, non transmis. |
| 03/09 | ZeroGaspi | Deux secteurs Commerce / Distribution en cache, descriptions en abstention. |

## 7. Dossier de preuves et reproduction

- [Résultats structurés, inventaire complet des inconnus et traces par observation](../audit/sector_2026-09-05/evidence.json).
- [Script de reproduction hors ligne](../audit/sector_2026-09-05/reproduce.py).
- [Journal complet de la collecte du 3 septembre](../audit/sector_2026-09-05/run_33751597159.log).
- [Journal complet de la collecte du 4 septembre](../audit/sector_2026-09-05/run_33869699921.log).
- [Manifeste de récupération des pages et du JSON servi](../audit/sector_2026-09-05/fetch_manifest.json).
- [Empreintes SHA-256 du dossier figé](../audit/sector_2026-09-05/sha256_manifest.json).

Depuis la racine du dépôt, sous WSL :

```bash
rtk proxy .venv/bin/python audit/sector_2026-09-05/reproduce.py
```

Le script affiche les résultats sur stdout et ne modifie pas les données métier. Il importe le code dans `audit/sector_2026-09-05/production`, et non les corrections locales. Les assertions vérifient la perte des 27 couples déjà matérialisés, la différence de validation selon la présence du nom dans la citation et l'abstention stockée dès la première écriture. Ces essais sont des preuves du diagnostic, pas une recette de correctifs déjà implémentés.

**État à la remise : audit et plan terminés ; correctifs proposés, non appliqués et non déployés.**
