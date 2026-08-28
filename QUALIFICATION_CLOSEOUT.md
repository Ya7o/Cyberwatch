# Clôture du chantier Qualification

Statut : **CLOS**

Date de clôture : 2026-08-20

Ce document fige l'architecture et les invariants du chantier Qualification. Toute évolution ultérieure de Sector, Location ou Threat doit être traitée comme une amélioration continue ou un nouveau chantier, et non comme une dette ouverte du chantier initial.

## Architecture finale

La qualification suit désormais le contrat suivant :

```text
Sources / règles / référentiels / contexte / registre / LLM
                         ↓
              QualificationCandidate
                         ↓
                QualificationPolicy
                         ↓
              QualificationDecision
                         ↓
                       Item
```

Les producteurs sont exécutés selon une précédence explicite, de la source la plus autoritaire vers les fallbacks les plus faibles. L'arbitre final reste déterministe et indépendant de l'ordre des candidats.

Précédence canonique :

```text
SOURCE_NATIVE
> MANUAL_REFERENCE
> STRUCTURED_SOURCE
> ORG_CONTEXT_SECTOR
> ORG_SECTOR_REGISTRY
> SAFE_NAME_RULE
> OFFLINE_BACKFILL
> THREAT_STABILIZATION
```

Depuis le 28 août 2026, `LLM_SOURCE_FALLBACK` n'est plus un producteur actif :
les tables ChatGPT globales qui l'alimentaient ont été archivées comme
benchmarks. Son identifiant reste interprétable uniquement pour relire les
anciennes provenances et restaurer les valeurs historiques contaminées.

Les trois champs `Sector`, `Location` et `Threat` partagent le même contrat décisionnel.

## Provenance et explicabilité

Chaque décision qualifiante porte au minimum :

- l'item et le champ concernés ;
- la valeur précédente ;
- la valeur candidate ;
- la valeur finale ;
- l'origine ;
- la confiance ;
- la preuve et la stratégie de raccord lorsqu'elles existent ;
- la décision appliquée ou rejetée.

Lorsqu'un candidat perd l'arbitrage, la provenance expose également :

- `Rejected_reason` ;
- `Winning_origin` ;
- `Winning_value`.

Un fallback ne peut donc plus écraser silencieusement une qualification plus autoritaire.

## Invariants de sécurité

Les invariants suivants définissent le contrat de fermeture du chantier :

1. la précédence des origines est explicite et totale ;
2. l'arbitrage est déterministe ;
3. le résultat ne dépend pas de l'ordre des candidats ;
4. les couches les plus faibles ne peuvent pas empêcher la génération d'un candidat plus fort ;
5. le LLM reste un challenger borné par la policy et ne devient jamais une vérité implicite ;
6. les cas insuffisamment prouvés peuvent rester `Unknown`, `REVIEW` ou `CONFLICT` ;
7. la déduplication reste une étape aval indépendante ;
8. un snapshot identique doit produire les mêmes hashes et les mêmes décisions ;
9. le chemin incrémental doit rester en parité avec le chemin canonique ;
10. toute dégradation mesurable doit être visible dans les quality gates ou l'historique de dérive.

## Garde-fous et certification

La clôture s'appuie sur les contrôles déjà actifs dans la CI :

- tests unitaires de qualification ;
- golden qualification avant et après requalification ;
- quality gate relatif à la baseline publiée ;
- gate qualité global ;
- garde de précision Sector ;
- benchmark du registre Sector par canal ;
- policy d'auto-qualification Sector ;
- audit des applications contextuelles ;
- test de répétabilité ;
- contrôles structurels ;
- parité qualification incrémentale ;
- Dedup Golden indépendant.

Les métriques par origine, les baselines et l'historique par source permettent de distinguer volume, couverture, inconnus, décisions appliquées/rejetées, gains, régressions et dérives.

## Qualification incrémentale

Le runtime incrémental est protégé par :

- un dirty-set préqualification ;
- un digest des dépendances ;
- une validation shadow ;
- un contrôle de parité avec la qualification canonique ;
- des invariants de performance et de réutilisation.

La réutilisation n'est autorisée que lorsque le contrat de dépendances et de parité permet de démontrer que le résultat est équivalent au chemin complet.

## Ce qui n'est plus bloquant

Les sujets suivants sont explicitement sortis du chantier de clôture et relèvent désormais de l'amélioration continue :

- augmenter encore la taille du golden ;
- améliorer les scores Sector ou Location ;
- réduire les règles lexicales particulières dans `context_sector.py` ;
- convertir les derniers producteurs historiques en fonctions purement fonctionnelles sans mutation intermédiaire ;
- ajouter une UI dédiée aux métriques de qualification et de dérive ;
- optimiser davantage le coût et la durée de qualification ;
- nettoyer les anciennes branches Git de développement.

Aucun de ces points ne remet en cause l'arbitrage final, la provenance, la répétabilité ou les gates de qualité du système publié.

## Critère de réouverture

Le chantier Qualification ne doit être rouvert que si au moins un des invariants de sécurité précédents n'est plus garanti, par exemple :

- une origine faible peut écraser une origine forte ;
- une décision n'est plus explicable ;
- la qualification incrémentale diverge du chemin complet ;
- un changement de code peut régresser le golden sans blocage CI ;
- l'ordre d'exécution redevient porteur de priorité métier implicite.

Une simple amélioration de couverture, de précision, de performance ou d'ergonomie ne constitue pas une réouverture du chantier.

## Décision de clôture

Le chantier Qualification est considéré **clos** dès lors que ce document est mergé sur `main` avec la CI complète verte.
