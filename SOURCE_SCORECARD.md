# Source scorecard

Le scorecard P1 sert à prioriser les investissements **Data / Sources** à partir des données déjà publiées. Il est entièrement offline : aucun accès réseau, aucun appel LLM et aucune mutation des CSV canoniques.

Commande :

```bash
python -m cyberwatch.source_scorecard --markdown
python -m cyberwatch.source_scorecard --output /tmp/source-scorecard.json
```

## Mesures par source

Pour chaque source active, le rapport expose :

- nombre d'items et d'incidents touchés ;
- incidents exclusifs et incidents corroborés ;
- organisations distinctes ;
- date du dernier item et fraîcheur ;
- fiabilité sur les derniers runs (`OK` / `PARTIAL` / `FAIL`) ;
- durée moyenne et rendement items/appel ;
- taux de `Inconnu` pour Threat, Sector et Location ;
- avertissements directement actionnables.

L'`Index` 0–100 est un **outil de priorisation**, pas une certification de qualité :

- 30 % fiabilité récente ;
- 20 % fraîcheur ;
- 20 % complétude Threat/Sector/Location ;
- 20 % contribution exclusive ;
- 10 % efficacité de collecte.

Lorsqu'une composante n'est pas mesurable, les poids disponibles sont renormalisés. Une forte contribution exclusive n'est pas une preuve de véracité : elle indique seulement qu'une source apporte des incidents que les autres ne fournissent pas.

## Angles morts

Le rapport agrège aussi la couverture du snapshot par territoire, menace et secteur. Il signale explicitement les territoires méthodologiques sans incident publié ainsi que les taux globaux d'inconnus.

Ces signaux doivent guider le P1 :

1. corriger une source si sa fiabilité ou sa fraîcheur se dégrade réellement ;
2. challenger une source coûteuse qui apporte peu d'incidents utiles ;
3. chercher de nouvelles sources lorsqu'un territoire ou un type d'incident reste structurellement sous-couvert ;
4. ne pas rouvrir les moteurs `FROZEN` pour compenser un problème qui est en réalité un manque de source.

Le scorecard est ajouté automatiquement au résumé GitHub Actions des runs `create`, `maj` et `replay` qui produisent un snapshot exploitable.

## Décisions de portefeuille

`python -m cyberwatch.source_portfolio --markdown` transforme ensuite ces mesures en décisions `KEEP`, `WATCH`, `REVIEW` ou `DEACTIVATION_CANDIDATE`, et classe les sources inactives à reprober selon les angles morts réellement observés. Cette seconde étape reste non mutante.
