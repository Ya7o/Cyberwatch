# P0 — Reset + baseline

Statut : **EXÉCUTÉ — génération 1 publiée le 2026-08-21**

Le reset total `zero` a été exécuté et publié. `data/post_reset_baseline.json` est
la baseline officielle de la **génération 1**, reconstruite intégralement depuis un
staging certifié `ZERO`.

| | Ancienne base (génération 0) | Génération 1 |
|---|---:|---:|
| Items | 1055 | **1051** |
| Incidents | 868 | **871** |
| Doublons d'ID | 0 | **0** |
| Couverture Threat | 99,43 % | **99,43 %** |
| Couverture Location | 95,26 % | **94,10 %** |
| Couverture Sector | 45,97 % | **41,67 %** |

La génération 0 est **historique**. Elle reste accessible pour rollback uniquement,
via le tag `archive/pre-zero-32516336880-1` et l'artifact `reset-total-zero-*`
accompagné de son SHA-256. Elle ne doit jamais être réinjectée automatiquement dans
une reconstruction : c'est précisément ce que le mode `zero` sert à rendre inutile.

L'écart de couverture Sector s'explique et se résorbe seul : le registre Sector se
reconstruit à chaque run depuis `enrichment_reference.csv`, les SourceFacts et le
cache d'enrichissement organisationnel, or ce cache est reparti de zéro avec un
plafond de 200 appels par passe, là où la génération 0 l'avait accumulé sur des
dizaines de runs quotidiens. Chaque `collect.yml` reprend l'enrichissement là où la
passe précédente s'est arrêtée. Aucun champ n'est comblé artificiellement : une
organisation non encore enrichie reste `Inconnu`.

Ce chantier ferme la phase plateforme après un reset total certifié et la publication d'une baseline mesurable. Le reset réel reste une opération manuelle car il accède au réseau, utilise le secret OpenAI et peut engager un coût.

## Contrat

Le chemin canonique est `.github/workflows/cold-reset.yml` uniquement.

Il réalise dans cet ordre :

1. préflight offline ;
2. manifeste et baseline de l'état courant ;
3. archive de rollback ;
4. staging isolé ;
5. reconstruction déterministe sans LLM ;
6. qualification bornée ;
7. passes sémantiques bornées ;
8. SourceFacts borné ;
9. enrichissement organisations ;
10. tests, check et génération dashboard ;
11. audit post-reset ;
12. génération de `data/post_reset_baseline.json` ;
13. export des artifacts ;
14. publication uniquement si `publish=true` et si toutes les étapes précédentes ont réussi.

## Dry-run obligatoire

Premier lancement recommandé :

- `publish=false` ;
- fenêtre `start` explicitement choisie ;
- plafonds LLM conservateurs ;
- conserver l'artifact `reset-total-*`.

Le dry-run ne modifie pas `main`. Il permet de lire :

- `reset-preflight.json` ;
- `reset-baseline-before.json` ;
- `reset-audit.json` ;
- `reset-after.json` ;
- le staging `data/` et `assets/data/` ;
- `data/post_reset_baseline.json` produit dans le staging.

## Audit

`python -m cyberwatch.reset_baseline audit` bloque seulement les erreurs qui rendent le snapshot impropre à la publication :

- zéro item ;
- zéro incident ;
- doublons de `Item_ID` ;
- doublons de `Incident_ID` ;
- dernier run explicitement non `OK` ;
- source du dernier run en `FAIL`.

Les grosses variations par rapport à l'état précédent sont des **warnings**, pas des blocages automatiques : baisse de volume supérieure à 20 % ou baisse de couverture supérieure à 10 points. Elles doivent être examinées, mais une différence de méthode ou un nettoyage légitime ne doit pas être transformé en faux échec technique.

## Baseline officielle

Après publication, `data/post_reset_baseline.json` devient le point zéro du cycle produit/data. Il contient notamment :

- nombre d'items et d'incidents ;
- ratio items/incidents ;
- doublons d'identifiants ;
- couverture Threat / Sector / Location aux niveaux item et incident ;
- état et volume par source ;
- durée du dernier run et durée par source ;
- résumé LLM de la dernière passe disponible.

Cette baseline n'est pas un nouveau framework de gates. Elle sert à répondre à une question simple : **une évolution ultérieure améliore-t-elle ou dégrade-t-elle réellement Cyberwatch ?**

## Publication finale

Après validation du dry-run, relancer le même workflow avec les mêmes paramètres et `publish=true`.

La publication n'est acceptable que si :

- l'audit retourne `GO` ;
- les warnings importants sont expliqués ;
- le dashboard généré est cohérent ;
- le coût LLM est compatible avec le plafond choisi ;
- les artifacts permettent un rollback.

## Clôture du P0

Après le premier reset publié avec `data/post_reset_baseline.json` :

- plateforme générale : **CLOSED / maintenance only** ;
- qualification, identité, dedup, runtime LLM, incremental, quality framework et cold reset restent **FROZEN** ;
- un chantier moteur ne se rouvre que sur bug, régression mesurée, sécurité, coût réel ou blocage produit ;
- la roadmap bascule sur **Data quality → Sources → Dashboard/Produit → Analytics**.
