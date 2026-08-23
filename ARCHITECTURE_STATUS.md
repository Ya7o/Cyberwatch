# Statut d'architecture Cyberwatch

Date de décision : 2026-08-21

Cyberwatch entre en phase de consolidation. Le moteur technique est considéré suffisamment mature pour les enjeux actuels du produit. La priorité de développement passe désormais de l'architecture interne à la qualité des données, aux sources, au dashboard et aux usages analytiques.

## Statut des domaines

| Domaine | Statut | Règle d'évolution |
|---|---|---|
| Collecte | ACTIVE | nouvelles sources, fiabilité et couverture |
| Dashboard | ACTIVE | valeur utilisateur et lisibilité |
| Data quality | ACTIVE | problèmes mesurés sur les données publiées |
| Qualification | FROZEN | bug, régression, sécurité ou besoin produit bloquant uniquement |
| Identity | FROZEN | bug ou perte de déterminisme uniquement |
| Dedup | FROZEN | régression mesurée ou cas métier réellement observé |
| LLM runtime | FROZEN | coût réel, bug ou incompatibilité fournisseur uniquement |
| Incremental runtime | FROZEN | divergence ou régression de performance mesurée uniquement |
| Quality framework | FROZEN | défaut de détection démontré uniquement |
| Cold reset | FROZEN | maintenance corrective uniquement |

`FROZEN` ne signifie pas immuable. Cela signifie qu'une amélioration purement architecturale, une préparation à un besoin hypothétique ou une abstraction plus élégante ne suffit plus à justifier un chantier.

### Réouverture documentée : filet LLM de déduplication (2026-08-23)

Les domaines `Dedup`, `Identity` et `LLM runtime` ont été rouverts pour un
besoin métier réel et déjà observé : des doublons résiduels (variantes de
nom, acronymes, fautes de frappe) échappaient au moteur déterministe et aux
aliases statiques, produisant des organisations distinctes dans le dashboard
pour une même victime. Le chantier ajoute un filet LLM optionnel, borné à un
batch par MAJ réelle (`cyberwatch/dedup_ai.py:challenge_candidates_batch`),
dont les décisions ne sont appliquées qu'après validation déterministe
(`cyberwatch/dedup_ai.py:validate_ai_dedup_decision`) et persistées dans
`data/organisation_identity_registry.csv` — jamais une fusion directe. Le
moteur déterministe (`dedup.decide_merge`/`group_components`) reste seul
juge de la fusion d'incident ; voir §14.5 de `METHODOLOGY.md`. Les trois
domaines redeviennent `FROZEN` à l'issue de ce chantier : toute évolution
ultérieure doit à nouveau satisfaire le critère de réouverture ci-dessous.

## Clôture P0

Le développement du P0 est terminé lorsque le workflow de reset certifié et la mesure post-reset sont présents sur `main`.

La clôture opérationnelle du P0 intervient au premier reset total publié qui produit `data/post_reset_baseline.json` avec un audit `GO`. Le runbook est `P0_RESET_BASELINE.md`.

À partir de cette publication, la baseline post-reset devient le point zéro des décisions de performance et de qualité. Elle ne doit pas devenir un nouveau framework de certification : elle sert à constater les régressions réelles avant de rouvrir un domaine gelé.

## Surface opérationnelle canonique

Trois workflows GitHub Actions structurent l'exploitation :

- `.github/workflows/ci.yml` : validation de développement ;
- `.github/workflows/collect.yml` : collecte quotidienne et opérations courantes ;
- `.github/workflows/cold-reset.yml` : reconstruction exceptionnelle de la base.

Aucun nouveau workflow automatique ne doit être ajouté sans besoin opérationnel distinct impossible à couvrir par ces trois chemins.

## Garde-fou anti-complexité

Avant d'ajouter un module transversal, une policy, un runtime, un contrat, une baseline ou une couche d'observabilité, répondre explicitement à ces questions :

1. Quel problème réel et observé cela corrige-t-il ?
2. Quelle métrique, régression, panne ou fonctionnalité utilisateur démontre ce besoin ?
3. Pourquoi le mécanisme existant ne peut-il pas absorber le changement ?
4. Quel coût de maintenance supplémentaire cette couche introduit-elle ?

Si les réponses reposent principalement sur une évolution future hypothétique, le changement doit être refusé ou reporté.

## Chaîne canonique

```text
collecte
  -> normalisation
  -> qualification
  -> déduplication
  -> contrôles
  -> données canoniques
  -> dashboard
```

La complexité interne n'est acceptable que lorsqu'elle protège directement la fiabilité de cette chaîne ou augmente une valeur produit mesurable.

## Critère de réouverture d'un domaine FROZEN

Un domaine gelé peut être rouvert lorsqu'au moins une condition est vraie :

- bug reproductible ;
- régression de qualité ou de performance mesurée ;
- perte de déterminisme ou de traçabilité ;
- coût opérationnel significatif et constaté ;
- changement externe imposant une adaptation ;
- fonctionnalité produit prioritaire impossible à livrer sans cette modification.

Une hausse potentielle de propreté, d'élégance, de généricité ou de sophistication ne constitue pas un critère de réouverture.
