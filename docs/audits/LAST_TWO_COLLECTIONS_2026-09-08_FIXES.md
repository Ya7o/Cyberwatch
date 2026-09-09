# Corrections après audit des deux dernières collectes

Date d'application : 9 septembre 2026.

Ce document complète l'audit du 8 septembre. L'audit initial reste la photographie des données publiées avant correction ; le présent document décrit l'état reconstruit localement à partir des 117 observations.

## Résultat

- 68 incidents après déduplication, contre 73 avant correction.
- 7 secteurs inconnus sur 68, contre 11 sur 73.
- 3 localisations inconnues sur 68, contre 6 sur 73.
- 1 072 tests automatisés réussis.
- 22 cas métier sur 22 réussis.
- 16 doublons connus sur 16 retrouvés, sans faux regroupement connu.
- Contrôle de cohérence du snapshot, des données canoniques et du site : réussi.

Les cinq regroupements corrigés concernent Aveyron/OnRecrute, Répar’stores, Clinique de Vontes/INICEA, CMA Occitanie et AMF. Les décisions négatives peu confiantes ne ferment plus définitivement la revue, les réponses de lot absentes ou invalides reçoivent une raison explicite, et les identifiants FrenchBreaches dont seul le slug change peuvent être rapprochés.

## Qualifications corrigées

Les corrections éditoriales sont versionnées dans `data/editorial_corrections.json` et rejouables avec `scripts/apply_editorial_corrections.py`. Elles corrigent notamment :

- SAD’S Interim : retrait du volume de 5,79 To relatif à Berlin, acteur Rhysida conservé comme revendiqué ;
- SNU : fuite de données revendiquée, secteur public, retrait des données et du volume historiques de 2023, conservation des volumes 2026 et du vecteur IDOR revendiqué ;
- Yvetot Normandie : Administration, France métropolitaine, 250 fichiers et acteur lazymean10 avec leurs statuts ;
- Medikwestindies : Guadeloupe, acteur ANKA Team et datation explicite de la capture de 2017 ;
- Footsider, Snexi, PassPass, AMF, ColisExpat, Géofoncier, LiveTrail et Shipup : menace principale corrigée en fuite de données ;
- Jouvet, Zéro Logement Vacant, FFTir, Actis Location et Ville de Libercourt : retrait des volumes ou vecteurs non étayés ;
- Les Curistes, ColisExpat, Micromania, Delicity et Marie Blachère : rôles d'acteur ou de tiers corrigés ;
- Répar’stores : retrait des données bancaires explicitement exclues par la source ;
- YouFid et Charbonneaux-Brabant : unité corrigée en enregistrements ;
- SPA du Pays de Montbéliard : rétablissement conservé comme signalé, sans confirmation indue.

Le calcul générique isole désormais les phrases interrogatives et les rappels historiques pour déterminer le statut d'une affirmation. Il transporte aussi les nombres de fichiers, reconnaît la Guadeloupe et rattache plusieurs lieux fins au territoire français approprié. La résolution de menace peut recevoir une correction éditoriale traçable quand les signaux génériques contredisent les preuves relues.

## Volet détail

Le volet affiche désormais les statuts auparavant invisibles, conserve les preuves des champs scalaires, systèmes et jeux de données, montre le périmètre des volumes et classe dans « Autres » les catégories de données acceptées par le serveur qui n'appartiennent pas à une famille connue. Les qualifications ne disparaissent donc plus silencieusement au rendu.

## Cas encore inconnus

Les secteurs encore inconnus sont Medikwestindies, Les Curistes, SPA du Pays de Montbéliard, Accent Rouge, Tisséo, Géofoncier et LebonSiege. Les localisations encore inconnues sont SPA du Pays de Montbéliard, Dropbox et Stade Montois Omnisports. Ces valeurs restent inconnues parce que les preuves présentes ne permettent pas une attribution assez sûre ou qu'un conflit métier subsiste.

## Rejeu

```bash
.venv/bin/python scripts/apply_editorial_corrections.py --write
.venv/bin/python -m cyberwatch check
.venv/bin/python -m pytest -q
.venv/bin/python -m cyberwatch validate-business
```
