# Audit des deux dernières collectes — 8 septembre 2026

**Verdict : les deux collectes ont été publiées avec succès technique, mais leur qualification n’est pas fiable de bout en bout.** Des doublons subsistent, une décision LLM sépare un même incident, plusieurs menaces ne correspondent pas aux preuves et des qualifications erronées ou incomplètes arrivent dans le volet détail. Les erreurs les plus urgentes concernent SNU, SAD’S Interim, Aveyron/OnRecrute, Footsider et les vecteurs d’attaque non étayés.

L’audit complet, avec un avis, les logs disponibles et les qualifications affichées pour **chacune des 73 fiches**, se trouve dans [INCIDENTS.md](../../audit/last_two_collections_2026-09-08/INCIDENTS.md). Les fiches historiques conservées ont également été examinées : certaines ont changé pendant ces runs sans nouvelle observation.

## Périmètre et preuve

| | Collecte 1 | Collecte 2 |
|---|---|---|
| Run | `RUN-20260907T183136` | `RUN-20260908T154840` |
| Début, UTC+4 | 7 septembre, 18:31:36 | 8 septembre, 15:48:40 |
| Déclenchement | Manuel | Planifié |
| GitHub Actions | [34133415793](https://github.com/Ya7o/Cyberwatch/actions/runs/34133415793) | [34222636343](https://github.com/Ya7o/Cyberwatch/actions/runs/34222636343) |
| Commit publié | `f402377` | `1fcfd09` |
| Fenêtre de publication des articles | 6–7 septembre | 7–8 septembre |
| Observations / incidents | 110 / 68 | 117 / 73 |
| Observations réellement nouvelles | 0 | 7 |
| Variation du nombre d’incidents | +1 net, 2 identifiants ajoutés et 1 retiré dans le CSV | +5 |

Le checkout initial s’arrêtait à `f402377`. La présence du run du 8 septembre a été vérifiée sur GitHub ; les snapshots ont été extraits depuis les commits, sans remplacer les données du checkout. Le parent `d1ae0d4` sert uniquement à mesurer les changements du premier run.

Les JSON publics `incidents.json`, `facts.json`, `status.json` correspondent exactement, après parsing, au snapshot `1fcfd09`. Le JavaScript public correspond au renderer local après normalisation des fins de lignes. Les constats portent donc bien sur les données servies au moment de l’audit.

Contrôles effectués : journaux Actions complets des deux runs ; observations et faits source ; 40 traces d’appels `source_facts` avec requêtes/réponses/rejets ; caches et files de reprise ; décisions sectorielles ; décisions et motifs de séparation dédup ; comparaison des snapshots ; recalcul des détails ; exécution réelle de `openIncident()` pour les 68 puis 73 fiches dans un DOM minimal ; relecture ciblée d’articles publics. Le recalcul reproduit **68/68 puis 73/73 détails**. Les erreurs sont reproductibles à partir des données canoniques, et non seulement dues à un ancien JSON oublié.

Limites : pas de nouvelle collecte, pas de nouvel appel LLM, pas de modification métier, pas de commit ni déploiement. Le rendu a été contrôlé fonctionnellement, sans recette visuelle de mise en page. Toutes les fiches ont été rapprochées de leurs preuves enregistrées ; la relecture externe des articles a été ciblée sur les anomalies, pas renouvelée intégralement pour chaque article historique. Les traces détaillées ne couvrent que les appels du run concerné ; l’absence de trace récente n’établit ni réussite ni échec d’une ancienne extraction.

## État réel des deux chaînes

| Mesure | 7 septembre | 8 septembre |
|---|---:|---:|
| Sources OK / PARTIAL / FAIL | 4 / 1 / 0 | 4 / 1 / 0 |
| Appels LLM totaux | 19 | 26 |
| Répartition | 18 qualification + 1 dédup | 3 extraction Cyberattaque + 22 qualification + 1 dédup |
| Échec d’appel API / blocage budget | 0 / 0 | 0 / 0 |
| Coût global estimé | 0,014158 $ | 0,017270 $ |
| État du filet dédup | **LLM_ERROR** | **LLM_ERROR** |
| Paires candidates / décisions exploitables | 17 / 13 | 21 / 18, dont 3 en cache |
| Paires en ERROR dans le journal du run | 4 | 3 |
| Paires restant à revoir | 6 | 10 |
| Incidents effectivement fusionnés par le filet | 0 | 0 |
| File de qualification : avant / reprises différées / après | 0 / 0 / 11 | 11 / 5 / 8 |
| Secteur inconnu, corpus incidents | **8/68 = 11,76 %** | **11/73 = 15,07 %** |
| Localisation inconnue, corpus incidents | **6/68 = 8,82 %** | **6/73 = 8,22 %** |
| Nouveaux items avec secteur inconnu | Sans nouveaux items | **5/7 = 71,43 %** |
| Nouveaux items avec localisation inconnue | Sans nouveaux items | **2/7 = 28,57 %** |

Les cinq nouveaux items à secteur inconnu ne représentent pas cinq nouveaux incidents mal sectorisés : l’item SAD’S récupère le secteur via Ransomware.live et Répar’stores via son autre observation. Trois nouvelles fiches restent sans secteur : Medikwestindies, SNU et Yvetot.

**Le succès API est distinct du succès de qualification.** Les traces `source_facts` ont toutes le statut `success`, mais enregistrent de nombreux champs rejetés. Les appels dédup réussissent aussi au transport ; certaines décisions par paire sont absentes ou invalides. `_store_batch_decisions()` transforme indifféremment `KeyError` et `ValueError` en `ERROR`. Les logs ne conservent pas le détail permettant de trancher entre ces deux causes pour chaque paire : il serait incorrect d’attribuer l’échec à une panne API ou au budget.

Le modèle effectivement utilisé est **gpt-4o-mini**, selon le routage versionné, malgré le modèle demandé `gpt-5-nano`. Les dépenses restent sous 0,03 $. Le manque de qualification ne s’explique donc pas par l’épuisement de ce plafond.

`VEILLE_LLM` est partielle sur les deux runs : snapshot régional du 2 septembre, âgé de 5 puis 6 jours pour une limite de 2 jours. Le « 99 % » est une valeur de couverture du collecteur, pas une estimation de fiabilité métier. L’alerte de production signale bien le filet dégradé, les secteurs et les territoires inconnus ; le workflow publie tout de même. L’issue de suivi existante est [#195](https://github.com/Ya7o/Cyberwatch/issues/195).

## P1 — Qualification des nouveaux incidents et des fiches réenrichies

| Incident | Résultat publié | Constat et résultat attendu |
|---|---|---|
| **SAD’S Interim** `INC-61993D19E8E2` | 5,79 To revendiqués dans le volet | La citation conservée désigne le réseau de l’État de **Berlin**, dans un rappel d’activité de Rhysida. Ce volume ne doit pas être attribué à SAD’S. Fusion des deux sources et secteur Services aux entreprises cohérents. Acteur Rhysida à conserver comme revendiqué, et non sans badge. |
| **SNU** `INC-EE0E8F96C169` | Intrusion / Confirmé ; 150 000 personnes en plus des comptes ; mots de passe, adresses postales, dates de naissance | La fiche mélange 2026 et le rappel de 2023. Le nombre de 150 000 personnes et plusieurs catégories viennent de 2023 ; les mots de passe sont mentionnés dans une exclusion. Pour 2026, conserver la fuite revendiquée, les deux ensembles de comptes et les réserves ; le vecteur IDOR reste revendiqué. Secteur public à résoudre. [Article](https://frenchbreaches.com/alertes/service-national-universel-snu-mtrfy9tvk9n0jcgh2yk). |
| **Yvetot Normandie** `INC-995C9F7252C1` | Secteur et territoire inconnus ; aucun volume ; pas d’acteur | Le LLM propose Administration / Collectivité, rejeté par le contrôle du rattachement à la victime. Seine-Maritime et 250 documents sont acceptés, mais le territoire reste inconnu et `File_Count=250` disparaît de la résolution des volumes. Le nom lazymean10 existe dans les claims, tandis que le scalaire « Il » est rejeté. La fuite est documentée ; le mode d’accès ne l’est pas. [Article](https://www.cyberattaque.org/cc-yvetot-normandie-les-documents-administratifs-en-fuite-apres-une-cyberattaque/). |
| **Medikwestindies** `INC-5D2D1691FC39` | France métropolitaine ; secteur inconnu ; acteur « l’auteur » ; résumé vide | Le contexte hydraté décrit un site destiné à des étudiants en médecine de **Guadeloupe**. Le défaut métropolitain est injustifié ; l’identité exacte de l’exploitant et son secteur restent à instruire. La capture est datée du 3 juin 2017 : ne pas présenter ce signalement récent comme une attaque survenue en 2026. ANKA Team est cité dans le texte ; conserver le volume revendiqué et la nuance des mots de passe hachés. Preuve : contexte et réponses archivés pour `ITM-21712d3c95aeb085`. |
| **AMF, nouvelle fiche BLF** `INC-DD17DC78C96C` | Nouvelle fiche du 8 septembre, sans résumé ; menace sans statut | Doublon probable de la fiche du 4 septembre, que la revue LLM ne résout pas. Le statut confirmé de BLF ne passe ni dans les types ni dans le statut de menace de cette fiche. Le secteur Association / Syndicat est correct. [BLF](https://bonjourlafuite.eu.org/). |
| **Footsider** `INC-0042AA05B202` | Ransomware ; 100 000 utilisateurs parmi les volumes | L’article documente une fuite, pas un rançongiciel. La vieille valeur `Item.Threat=Ransomware` est transformée en preuve par le résolveur, alors que `threat_tentative=Fuite de données` existe. Les 100 000 utilisateurs décrivent la taille commerciale historique du service, pas l’incident. Secteur Sport correctement résolu. [Article](https://www.cyberattaque.org/footsider-cyberattaque/). |
| **Jinko** `INC-A3D0A851E662` | Vecteur « identifiants compromis » | La citation énumère plusieurs causes possibles et dit qu’il est impossible de les départager. Ne pas promouvoir cette hypothèse en vecteur. Santé, France et regroupement des sources sont cohérents. |
| **BumFot** `INC-8A100D3C8D40` | Résumé affirmatif au second run ; impact retiré | Le nouveau résumé perd la réserve revendiquée du premier. Deux valeurs de 1 300 utilisateurs demeurent avec des scopes différents, mais l’interface les présente sans ces scopes. Le secteur Numérique est résolu ; le regroupement est conservé. |
| **Les Curistes** `INC-D2432B2095FD` | ChimeraZ à la fois acteur et tiers ; secteur inconnu | Confusion certaine de rôle : ChimeraZ est l’attaquant cité. Le secteur inconnu résulte d’un conflit Tourisme / Santé, à arbitrer selon l’activité réelle. La proposition LLM Transport au second run a été correctement rejetée. |
| **Snexi** `INC-CE20778A3019` | Intrusion / Confirmé | Le résumé et l’impact enregistrent une violation de données personnelles. La menace a été rétrogradée à Intrusion au premier run. Corriger la lecture de ces preuves, plutôt que s’appuyer uniquement sur un vocabulaire restreint du résumé. |

**Causes communes.** `_claim_status()` cherche des mots de statut à l’échelle du texte, sans isoler l’événement ni les phrases interrogatives ou historiques. Ainsi la confirmation de 2023 contamine SNU, et le titre interrogatif sur la confirmation contamine Medikwestindies. Les résolveurs de champs héritent ensuite de ce statut global. La résolution des volumes ne contrôle pas suffisamment la victime, la date et le périmètre. Le résolveur de menace n’exploite qu’une partie des preuves, notamment titre, résumé et impact ; il ignore des faits riches utiles et survalorise une ancienne valeur Ransomware.

## P1 — Déduplication : les paires et leur devenir

| Ensemble | Fiches restant séparées | Diagnostic |
|---|---|---|
| **Aveyron / OnRecrute** | `INC-EEC788C594CA` / `INC-A11BA9A22689` | **Faux négatif établi, introduit par le run du 7.** La décision SAME organisation / DIFFERENT incident, confiance 0,85, devient un interdit de fusion persistant. Motif recalculé : `INCIDENT_KEEP_LLM_DIFFERENT`. Les deux articles décrivent pourtant la même plateforme, le même acteur et les mêmes volumes. [Cyberattaque](https://www.cyberattaque.org/aveyron-cyberattaque-emplois/), [FrenchBreaches](https://frenchbreaches.com/alertes/aveyron-mtp0hyfwss6ietkec1q). |
| **Répar’stores / Répar’Store** | `INC-B44C794AB35B` / `INC-DC0BCFD579B8` | **Doublon établi par les sources.** BLF est rattaché à Cyberattaque au second run ; FrenchBreaches reste à part. Le LLM classe les organisations DIFFERENT à 0,5 et clôt cette paire. Aucun seuil de validation équivalent à une fusion n’empêche cette clôture négative. La variante singulier/pluriel reste non rapprochée. [FrenchBreaches](https://frenchbreaches.com/alertes/r-par-store-mtoa0qd4rlpkduc13t), [Cyberattaque](https://www.cyberattaque.org/reparstores-les-donnees-clients-exposees-apres-une-cyberattaque/). |
| **Clinique de Vontes / INICEA** | `INC-2C5CD2459F83` / `INC-45561E350283` | **Doublon établi**, hérité et toujours publié. Deux slugs FrenchBreaches portent le même suffixe d’identifiant. Le blocage recalculé est `INCIDENT_KEEP_CONFLICTING_SOURCE_ITEM_ID`. Les sources changent de composante au premier run ; un identifiant est remplacé. Pas de revue LLM de cette paire sur les deux runs. Le périmètre plus large INICEA et la réserve sur les « patients » doivent être conservés. [Article](https://www.cyberattaque.org/cyberattaque-clinique-de-vontes/). |
| **CMA Occitanie / nom développé** | `INC-619638DA1C52` / `INC-B7DBF665E661` | **Doublon fortement étayé** : même institution, même date et fuite de 1 029 profils. Pas de paire dans les journaux des deux runs ; motif `INCIDENT_KEEP_NO_COMPATIBLE_COMPONENT`. Un fragment a les faits, l’autre le territoire. [Cyberattaque](https://www.cyberattaque.org/chambre-de-metiers-et-de-lartisanat-cyberattaque/), [FrenchBreaches](https://frenchbreaches.com/alertes/chambre-de-m-tiers-et-de-l-artisanat-d-occitanie-mtktlb1edwrd1ok63hq). |
| **AMF du 4 / AMF du 8** | `INC-2C5CEAE9E3AC` / `INC-DD17DC78C96C` | **Doublon probable à arbitrer** en rapprochant la notification BLF. Pour un même nouveau signal, le LLM produit SAME incident à 0,6 contre FrenchBreaches et DIFFERENT à 0,5 contre Cyberattaque. Les deux propositions sont refusées, sans rapprochement final. |

Le garde-fou a correctement bloqué une proposition **Snexi = SAD’S Interim**, pourtant marquée SAME/SAME par le modèle à 0,6. Le regroupement déterministe des deux sources SAD’S fonctionne, comme l’ajout BLF à la composante Répar’stores. L’audit ne démontre donc pas que toutes les fusions sont erronées.

Les métriques `Missed_Duplicate_Candidate_Pairs=0` et `Validated_Same_Not_Grouped_Pairs=0` ne prouvent pas l’absence de doublons : Aveyron est explicitement marqué DIFFERENT, et plusieurs autres cas ne deviennent pas des SAME validés. Les **42 paires de fusion faible** et les **47 paires potentielles** du dernier corpus sont des pistes de revue, pas 42 ou 47 erreurs établies.

Les ERROR du run du 7 concernent quatre comparaisons BumFot avec Frères Toque ou La Maison Des Travaux. Ceux du 8 concernent Yvetot/Storia Mundi, BumFot/La financière d’Orion et BumFot/Frères Toque. Les identifiants, résultats et tentatives sont joints dans l’annexe de chaque fiche.

## Secteurs inconnus et localisations

**Les onze secteurs inconnus au dernier run sont tous expliqués dans les logs, mais les motifs ne signifient pas toujours que la source manque d’information.**

| Incident | Cause observée | Action à préparer |
|---|---|---|
| Yvetot | Description et secteur LLM rejetés sur le rattachement à la victime | Reconnaître « CC » / Communauté de communes et l’activité institutionnelle ; Administration / Collectivité. |
| SNU | Couple activité/secteur rejeté | Reprendre le sujet institutionnel et le secteur public, en isolant les rôles des structures partenaires. |
| Medikwestindies | Description médicale/étudiante rejetée ; exploitant mal identifié | Instruire l’activité du site ; ne pas confondre santé des données et secteur de la victime. |
| Aveyron | Identité trop générique, fragment séparé | Réunir l’incident OnRecrute et ses preuves sectorielles. |
| SPA du Pays de Montbéliard | Activité rejetée et en attente | Qualifier la protection animale/association avec une preuve rattachée à l’entité. |
| Répar’Store | Fragment isolé, activité rejetée | Rapprocher la composante correctement classée Construction / BTP. |
| Tisséo | `NO_ACTIVITY_EVIDENCE` malgré les faits décrivant un réseau de transports | Récupérer l’activité Transport / Logistique. |
| Géofoncier | Description d’activité foncière non résolue | Arbitrer la taxonomie selon le service réellement fourni. |
| LebonSiege | Preuve trop courte/rejetée pour le site de vente en ligne | Reprendre une phrase complète rattachant l’activité commerciale à l’entité. |
| Les Curistes | Conflit Tourisme / Santé | Arbitrage métier étayé ; l’inconnu vaut mieux qu’un secteur arbitraire. |
| Accent Rouge | Conflit Culture / Commerce sur l’aménagement intérieur | Corriger l’interprétation de l’activité puis arbitrer, sans forcer le taux. |

Les **six territoires inconnus** sont Yvetot, Aveyron, SPA du Pays de Montbéliard, CMA Occitanie, Dropbox et Stade Montois. Répar’stores sort de cette liste au second run grâce à BLF, tandis que Yvetot y entre.

Le contrôle reproduit `classify_location(given=...) == Inconnu` pour **Seine-Maritime, Allondans/Doubs, Mont-de-Marsan, Aveyron et Guadeloupe**. Les champs fins de Yvetot, SPA et Stade Montois n’ont donc pas les moyens de corriger le territoire. Pour Medikwestindies, l’absence de territoire Guadeloupe dans la taxonomie laisse en place le défaut France métropolitaine. Pour Dropbox, une localisation inconnue reste défendable sans preuve du périmètre des comptes affectés. Un **domaine web `amf.asso.fr`** apparaît par ailleurs dans la localisation précise de l’AMF : c’est une mauvaise valeur, même si le territoire général est correct.

## Qualifications historiques encore publiées dans ces deux collectes

Le premier run n’ajoute aucun item mais modifie de nombreuses qualifications. Tous les passages de Fuite vers Intrusion ne sont pas des erreurs : **CGT Éduc’Action, SDIS de la Somme et de l’Essonne** décrivent notamment indisponibilité, altération ou accès administrateur. En revanche, **Snexi, PassPass, AMF, ColisExpat, Géofoncier, LiveTrail et Shipup** portent des preuves d’exposition/extraction que la menace principale ne restitue pas correctement. Les autres cas ambigus sont marqués « à vérifier » dans l’annexe.

Les défauts suivants restent reproductibles dans les deux snapshots, indépendamment du succès des nouveaux appels :

- **Jouvet SAS** : 157 victimes du bilan mensuel de Qilin affichées comme volume de l’incident.
- **Zéro Logement Vacant et FFTir** : exploitation de vulnérabilité affichée malgré des preuves négatives ou non concluantes ; ZLV affiche aussi un volume de personnes et un déroulé trop affirmatifs.
- **Actis Location et Ville de Libercourt** : risques futurs de phishing utilisés comme vecteurs d’entrée.
- **ColisExpat et Micromania** : Landmark Global France et Shipup employés comme acteurs revendicateurs ; **Delicity**, **Medikwestindies**, **Marie Blachère** conservent des désignations génériques d’acteur.
- **Répar’stores** : données bancaires affichées alors que la source les exclut. Les réserves dans les claims ne sont pas présentées comme telles dans le volet.
- **YouFid et Charbonneaux-Brabant** : des enregistrements deviennent des personnes dans l’impact ou le résumé sans preuve d’unicité.
- **SPA** : texte de rétablissement « confirmé » avec une citation qui ne documente que les travaux en cours.

Ces exemples sont des défauts observés ; ils ne constituent pas une mesure statistique de précision de l’ensemble des articles.

## P2 — Pertes au volet détail

| Mesure | R1, 68 fiches | R2, 73 fiches |
|---|---:|---:|
| Champs scalaires présents | 140 | 148 |
| Dont citation conservée dans le JSON | 122 | 130 |
| Champs scalaires au statut unknown | 44 | 48 |
| Volumes présents, avec citation | 86 | 90 |
| Volumes au statut unknown | 55 | 56 |
| Catégories de données présentes | 283 | 309 |
| Catégories au statut unknown | 231 | 248 |
| Catégories supprimées par le renderer | **60 sur 34 fiches** | **67 sur 38 fiches** |

Les citations des 130 scalaires et des 90 volumes du dernier JSON ne sont pas transmises à leurs lignes par `openIncident()`. La menace et le secteur font exception : leurs citations sont passées. Les systèmes et périmètres deviennent des chaînes qui perdent leurs statuts. Le rendu de `unknown` est vide ; celui des secteurs `inferred`/`referenced` devient « Documenté ». Une partie des informations de statut présente dans les données n’est donc pas visible ou change de sens.

`dataTypeFamily()` renvoie `null` pour plusieurs catégories acceptées par le serveur : contrats, données RH, commandes, commentaires, etc. L’annexe indique les valeurs exactes perdues **pour chaque fiche**. La solution consiste à corriger le contrat de normalisation et à rendre les catégories acceptées, plutôt qu’à réintroduire sans contrôle toutes les chaînes brutes.

Les résumés sont absents sur AMF BLF, Medikwestindies, Chambre de Métiers et de l’Artisanat d’Occitanie, La Maison Des Travaux et LCommerce. Cette absence n’est pas assimilée automatiquement à une erreur ; pour Medikwestindies, le rejet du résumé est explicitement traçable. Le volet ne propose cependant pas de diagnostic permettant de distinguer donnée absente, qualification rejetée et reprise en attente.

## Corrections à prioriser et recette

1. **Corriger les faits trompeurs avant le prochain réenrichissement global** : SAD’S/Berlin, SNU/2023, Footsider/Ransomware, faux vecteurs, faux rôles et catégories démenties. Conserver une preuve, un statut et un périmètre par affirmation.
2. **Réparer la déduplication sur copie** : annuler la décision Aveyron DIFFERENT erronée ; normaliser les identifiants de source Vontes malgré le changement de slug ; reprendre les variantes Répar’stores et CMA ; arbitrer AMF avec la notification. Vérifier les identifiants stables, les dates et toutes les sources après fusion.
3. **Fiabiliser les qualifications** : séparer incident courant, historique et contexte de groupe ; tenir compte des négations et questions ; intégrer les faits riches dans la menace ; transporter File_Count ; résoudre les lieux fins vers une taxonomie territoriale adaptée.
4. **Corriger le volet** : accès à la preuve par valeur, statuts explicites, conservation des catégories acceptées, distinction risque/impact constaté, et affichage des périmètres des volumes.
5. **Rendre les erreurs auditables** : raison exacte d’un rejet de paire, réponse brute dédup ou équivalent exploitable, traitement des décisions négatives peu confiantes, métriques sur les faits réellement acceptés et transmis. Le nombre d’appels `success` ne doit pas servir de taux de bonne qualification.

La recette doit rejouer les cas réels de cet audit sur une copie, jusqu’au HTML, puis vérifier les regroupements et les preuves. Les **22 cas métier** et les contrôles de cohérence du workflow passent sur les deux runs, mais ne couvrent pas ces erreurs. Aucun nouveau lancement de collecte n’a été utilisé comme test pendant cet audit.

## Dossier livré

- [Annexe des 73 incidents](../../audit/last_two_collections_2026-09-08/INCIDENTS.md), [registre d’avis JSON](../../audit/last_two_collections_2026-09-08/review_ledger.json).
- [Mesures](../../audit/last_two_collections_2026-09-08/metrics.json) et [reproductions techniques](../../audit/last_two_collections_2026-09-08/technical_checks.json).
- [Preuves R1](../../audit/last_two_collections_2026-09-08/run1_evidence.json), [preuves R2](../../audit/last_two_collections_2026-09-08/run2_evidence.json), [HTML R1](../../audit/last_two_collections_2026-09-08/run1_render.json), [HTML R2](../../audit/last_two_collections_2026-09-08/run2_render.json).
- [Journal Actions R1](../../audit/last_two_collections_2026-09-08/actions_34133415793.log), [journal Actions R2](../../audit/last_two_collections_2026-09-08/actions_34222636343.log), snapshots immuables et réponses de qualification dans le même dossier.

Rejeu hors réseau, depuis la racine WSL : `.venv/bin/python audit/last_two_collections_2026-09-08/analyze.py`, `node audit/last_two_collections_2026-09-08/render_probe.cjs`, puis `metrics.py`, `technical_checks.py` et `build_report.py` avec le même interpréteur Python. Ces sondes écrivent uniquement dans le dossier d’audit ; aucun fichier canonique n’est modifié.
