# Corrections sectorielles — 5 septembre 2026

Les corrections sont implémentées et validées localement. Sur la copie du
snapshot de production audité (84 articles, 51 incidents), les incidents au
secteur inconnu passent de **34 à 0**. Le second traitement ne modifie aucun
secteur ni fait. Aucun secteur générique de secours n'est utilisé.

## Causes traitées

L'audit initial est dans `SECTOR_AUDIT_2026-09-05.md`. Les faits d'activité
étaient extraits mais ne rejoignaient pas la résolution du secteur avant
l'agrégation. Le cache pouvait accepter un secteur sans description valide
et compter deux échecs dès le premier essai. La réponse brute et le motif
précis de rejet n'étaient pas conservés. Les anciennes décisions pouvaient
perdre leur provenance lors d'une reprise.

## Implémentation

- `enrichment.finalize_snapshot` résout désormais les secteurs à partir des
  faits avant de construire les incidents ; le runner utilise cette même voie.
- Description et correspondance sectorielle sont validées ensemble. La preuve
  doit concerner l'activité de la victime, pas celle d'un fournisseur ou client.
  Une citation partielle peut être étendue dans sa phrase source ; une
  description littérale peut être récupérée depuis une citation valide.
- Seuls les champs d'activité obsolètes du cache sont réexaminés. Un premier
  échec laisse un véritable nouvel essai possible. Un secteur orphelin est rejeté.
- Les contradictions de classification ou entre sources restent explicites.
  Les références exactes sourcées permettent un arbitrage documenté. La reprise
  ne transforme pas une inférence en confirmation.
- `data/sector_resolution.csv` conserve motif, statut, confiance, citation, URL
  et version de politique. La provenance affichée est liée à l'incident.
- `check`, les contrôles avant export et `build-site` détectent les pertes de
  transmission. La génération du site vérifie aussi la projection des décisions
  vers les incidents. Le seuil de 10 % d'inconnus reste une alerte, sans forcer
  une classification dépourvue de preuve.
- Le journal `data/source_facts_ai_trace.json` conserve, pour le run courant,
  contexte envoyé, demande, réponse brute, valeurs acceptées, motifs de rejet,
  identifiants et versions. Il ne contient pas les en-têtes ni la clé API.
  Les statistiques distinguent modèle demandé et modèle effectif ; le coût
  utilise le modèle effectif. Les traces sont sauvegardées aux checkpoints et
  en fin de processus. Elles ne reconstituent pas les réponses historiques perdues.

## Résultats et références

| Cas signalé | Secteur corrigé | Fondement |
|---|---|---|
| Préférence Formations | Éducation / Formation | Activité de formation professionnelle citée |
| ZeroGaspi | Commerce / Distribution | Vente en ligne explicitement décrite |
| Réso | Commerce / Distribution | Référentiel sourcé : négoce de matériaux |
| CMA Occitanie et libellé développé | Administration / Collectivité | Identité institutionnelle et référence officielle |

Les deux incidents CMA restent distincts : aucune fusion n'a été effectuée.
Le référentiel inclut également les arbitrages sourcés nécessaires aux autres
cas audités. Les URL et descriptions examinées figurent dans
`audit/sector_2026-09-05/reviewed_references.json` et
`data/enrichment_reference.csv`.

La copie corrigée est dans `audit/sector_2026-09-05/corrected_data/`, avec son
`sector_repair_report.json`. Les fichiers de production téléchargés dans
`audit/sector_2026-09-05/production/` restent la preuve avant correction.
Quelques articles individuels peuvent manquer de preuve propre même si une
autre source permet de classer leur incident ; cela reste visible dans le rapport.

Le corpus local est différent : **42 articles et 27 incidents**. Il a été repris
sans remplacement par la copie de production. Herbiolys passe de commerce à
industrie sur référence officielle. Les identifiants et champs non sectoriels
des incidents sont conservés. Les fichiers du tableau de bord local sont régénérés.

## Validation et mise en service

Validation effectuée : 1 009 tests automatisés, Ruff, mypy (10 fichiers), budget
de complexité et syntaxe JavaScript. Le corpus métier passe ses 18 cas sans
erreur ; les 16 doublons attendus sont retrouvés sans fusion abusive connue.
Deux générations successives des JSON du tableau de bord sont identiques.
Les tests couvrent les exemples figés, les conflits, le mauvais rattachement
d'activité, les reprises de cache et la trace de réponse du LLM.

Pour appliquer la reprise sur le corpus d'un environnement intégrant ce code :

```bash
python scripts/repair_sectors.py                 # simulation et rapport
python scripts/repair_sectors.py --write         # reprise sectorielle seule
python -m cyberwatch check
python -m cyberwatch build-site
python -m cyberwatch validate-business
```

Avant mise en service, conserver une copie du corpus et exécuter ces commandes
sur le même checkout que celui publié. Le script refuse les appartenances
d'articles ambiguës et conserve les identifiants existants. Il n'effectue aucun
appel LLM. Archiver le rapport et les traces du run avec les artefacts internes
existants ; suivre les inconnus et conflits par source et motif dans le CSV de
décisions. Vérifier les quatre exemples dans les JSON publiés après déploiement.

**Aucun push ni déploiement n'a été effectué.** Le résultat 51/51 est vérifié sur
le snapshot audité ; les futures sources sans preuve suffisante doivent rester
signalées pour investigation plutôt que recevoir un secteur inventé.
