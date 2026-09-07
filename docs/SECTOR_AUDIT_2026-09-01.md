# Audit racine — secteurs inconnus

Date de reproduction : 1er septembre 2026  
Périmètre : snapshot publié, pipeline d'ingestion, faits auxiliaires, déduplication,
publication et métriques de production.

## Résultat exécutif

Le taux de **40,74 %** était exact : **11 incidents sur 27** avaient
`Secteur=Inconnu`. Ils provenaient de **19 items sur 42** (45,24 %).

Après correction : **0 incident sur 27** et **0 item sur 42** restent inconnus.
La cible de publication est désormais **strictement inférieure à 10 %** et un
garde de pré-export bloque une publication à 10 % ou plus.

La baisse n'est pas présentée comme un gain automatique de vérité : les 11
incidents corrigés portent `sector_status.status=referenced`, une confiance de
0,90, le motif, la preuve textuelle et l'URL de validation. Un repli sans preuve
reste possible pour satisfaire la contrainte « aucun Inconnu », mais il est
marqué `inferred_low`, confiance 0,20, et compté séparément.

## Preuve 1 — reproduction avant correction

Commande :

```bash
python -m cyberwatch production-status
python scripts/audit_sectors.py
```

Extrait du journal initial :

```text
incidents: 27
unknown incidents: 11
unknown incident rate: 40.74 %
items: 42
unknown items: 19
unknown item rate: 45.24 %
```

La photographie immuable des identifiants concernés est conservée dans
`audit/sector_baseline_2026-09-01.json`.

## Preuve 2 — les 11 incidents concernés

| Incident | Organisation | Sources | Cause immédiate |
|---|---|---|---|
| INC-C64E07B15B3F | La financière d’Orion | CYBERATTAQUE_ORG | aucune preuve sectorielle structurée |
| INC-CFAAEC3E334A | Courir | CYBERATTAQUE_ORG, FRENCHBREACHES | marque non auto-descriptive |
| INC-D63CEE9E9005 | FFTir | CYBERATTAQUE_ORG | sigle absent des règles sûres |
| INC-D9A0C6DBD358 | Easypara | CYBERATTAQUE_ORG, FRENCHBREACHES | marque non auto-descriptive |
| INC-92B98E38166E | LCommerce | BONJOURLAFUITE | source image très pauvre |
| INC-3C5B9E546782 | Marie Blachère | CYBERATTAQUE_ORG, FRENCHBREACHES | nom de marque sans activité dans l'article |
| INC-68BCE0C36286 | Zéro Logement Vacant | CYBERATTAQUE_ORG, FRENCHBREACHES | service public non reconnu par le nom |
| INC-195F06B69C3A | Actis Location | CYBERATTAQUE_ORG, FRENCHBREACHES | « location » jugé trop ambigu |
| INC-70B5B8B5751D | Frères Toque | trois sources | aucune activité explicitée |
| INC-A3C6A92F895D | Lingor | CYBERATTAQUE_ORG, FRENCHBREACHES | marque non auto-descriptive |
| INC-E39645DF5E4E | Qare | CYBERATTAQUE_ORG | activité présente dans un résumé, pas dans le canal activité |

## Preuve 3 — analyse des 19 items

Le journal reproductible a contrôlé les trois canaux de preuve existants pour
chacun des 19 items :

```text
Source_Sector_Raw absent      19 / 19
Activity_Description absent   19 / 19
Activity_Sector_Match absent  19 / 19
```

Répartition par source :

```text
CYBERATTAQUE_ORG  10
FRENCHBREACHES     7
BONJOURLAFUITE     2
```

Ce résultat explique pourquoi augmenter seulement le vocabulaire des règles
n'aurait pas suffi : les articles d'incident décrivent surtout l'attaque et les
données compromises, rarement l'activité économique de la victime.

## Causes racines

### R1 — séparation sans consommateur

`Source_Sector_Raw`, `Activity_Description` et `Activity_Sector_Match` étaient
bien extraits dans `source_facts.csv`. Cependant, la documentation et le code
imposaient que cette couche ne modifie jamais `Item.Sector`. Aucun résolveur
postérieur ne consommait ces champs avant `build_incidents_with_registry`.

Conséquence : une preuve sectorielle pouvait exister sans atteindre l'incident.

### R2 — politique nominale volontairement trop prudente

`classify_sector_name` n'acceptait que des noms quasi auto-descriptifs : mairie,
hôpital, université, fédération sportive développée, etc. Les marques Courir,
Qare, Easypara, Lingor ou Marie Blachère étaient volontairement rejetées.

Cette prudence réduisait les faux positifs, mais sans référentiel de marques
elle transformait systématiquement l'absence de preuve locale en `Inconnu`.

### R3 — référentiel exact incomplet

`data/enrichment_reference.csv` savait déjà enrichir des organisations exactes,
mais aucune des 11 organisations n'y figurait. Le mécanisme existait ; sa
couverture nationale était insuffisante.

### R4 — aucune stratégie de dernier recours

Après source structurée, référence et règles sûres, le pipeline terminait
directement par `Inconnu`. Il n'existait ni catégorie opérationnelle de repli,
ni score, ni journal permettant d'accepter consciemment une baisse de fiabilité.

### R5 — métrique liée au dernier run, pas toujours au snapshot courant

Un REPLAY pouvait corriger `items.csv` et `incidents.csv` sans ajouter de ligne
de collecte à `production_metrics.csv`. `production-status` continuait alors à
afficher l'ancien taux. La qualité secteur/localisation est désormais calculée
sur le snapshot courant ; durée, coût et requêtes restent issus du dernier run.

## Corrections implantées

### Cascade de résolution

Ordre strict, du plus fiable au moins fiable :

1. secteur déjà canonique ;
2. `Source_Sector_Raw` structuré — confiance 0,95 ;
3. règles déterministes sur `Activity_Description` — confiance 0,80 ;
4. `Activity_Sector_Match` — confiance 0,85, utilisé seulement si aucune
   règle explicite ne tranche ;
5. référentiel exact avec URL — confiance 0,90 ;
6. règles sur résumé factuel — confiance 0,65 ;
7. règles sur nom — confiance 0,60 ;
8. règles sur titre — confiance 0,50 ;
9. repli `Services aux entreprises` — confiance 0,20, statut `inferred_low`.

Le niveau 9 garantit techniquement zéro `Inconnu`. Sa faiblesse reste observable
dans `data/sector_resolution.csv`, `status.json` et `incidents.json`.

### Référentiel exact des 11 organisations

| Organisation | Secteur retenu | Preuve |
|---|---|---|
| La financière d’Orion | Finance / Assurance | site officiel, gestion de patrimoine |
| Courir | Commerce / Distribution | site officiel, vente de sneakers |
| FFTir | Sport | site officiel de la Fédération française de tir |
| Easypara | Commerce / Distribution | site officiel, parapharmacie en ligne |
| LCommerce | Commerce / Distribution | Annuaire des entreprises, vente à distance |
| Marie Blachère | Commerce / Distribution | site officiel, réseau de boulangeries/magasins |
| Zéro Logement Vacant | Administration / Collectivité | service public numérique beta.gouv.fr |
| Actis Location | Services aux entreprises | location de manutention aux professionnels |
| Frères Toque | Hébergement / Tourisme / Restauration | service de commande/livraison de repas |
| Lingor | Finance / Assurance | conseil et investissement en métaux précieux |
| Qare | Santé | téléconsultation médicale |

### Traçabilité et affichage

Chaque item produit une ligne dans `data/sector_resolution.csv` : secteur avant
et après, statut, raison, confiance, preuve et URL. Le dashboard distingue un
secteur confirmé, déclaré, référencé, estimé ou estimé à faible confiance.

### Garde de publication

`pre_export_checks` refuse désormais un snapshot si le taux d'incidents sans
secteur est supérieur ou égal à 10 %. Le statut de production utilise la même
cible. La CI teste aussi le repli et la publication de la provenance.

## Preuve 4 — journal après correction

```text
overall OK
items 42
incidents 27
problems []
unknown_items 0
unknown_incidents 0
sector_rows 42
```

Agrégation du journal :

```text
Status confirmed   23 items
Status referenced  19 items
Status inferred     0 item
Status inferred_low 0 item
```

Agrégation publique par incident :

```text
confirmed  16 incidents
referenced 11 incidents
unknown     0 incident
```

La cible `< 10 %` est donc atteinte à **0,00 %**, sans recours au repli faible
sur le snapshot courant.

## Commandes de contrôle

```bash
python scripts/audit_sectors.py
python -m cyberwatch production-status
python -m cyberwatch check
python -m cyberwatch build-site
python -m pytest tests/ -q
python -m ruff check cyberwatch scripts tests
python -m mypy
node --check assets/dashboard-v2.js
```

`scripts/audit_sectors.py` est en lecture seule et peut être joint tel quel aux
logs d'une CI ou d'un run d'exploitation.
