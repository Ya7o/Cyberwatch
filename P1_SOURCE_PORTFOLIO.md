# P1 — Source portfolio

Le P1.2 transforme les métriques du scorecard en décisions de maintenance du portefeuille de sources, sans automatiser l'activation ou la désactivation.

## Objectif

Décider à partir de données observées plutôt qu'à l'intuition :

- conserver les sources qui apportent une valeur mesurable ;
- surveiller les sources moyennes ;
- examiner les sources faibles ;
- identifier les rares cas où une désactivation mérite d'être étudiée ;
- réévaluer en priorité les sources inactives qui couvriraient un angle mort réel.

## Commandes

```bash
python -m cyberwatch.source_scorecard --markdown
python -m cyberwatch.source_portfolio --markdown
```

Les deux commandes sont offline, déterministes et sans mutation de `sources.py`.

## Décisions sur les sources actives

- `KEEP` : index >= 65 ;
- `WATCH` : index entre 50 et 65 ;
- `REVIEW` : index < 50 mais preuve insuffisante pour proposer une désactivation ;
- `DEACTIVATION_CANDIDATE` : index < 35, au moins 5 runs observés, fiabilité < 50 % et aucun incident exclusif.

`DEACTIVATION_CANDIDATE` n'est jamais une suppression automatique. Une source peut rester importante pour un territoire, une menace ou une fonction de corroboration même si son rendement brut est faible.

## Priorité des sources inactives

Le classement donne d'abord du poids à une source qui couvre un territoire actuellement sans incident dans le snapshot. Viennent ensuite la diversification régionale, le caractère direct/core, l'existence d'un collecteur dédié et d'un test de succès explicite. Les blocages connus (`403`, `404`, coquille JavaScript) diminuent fortement la priorité.

Le classement ne prétend pas qu'une source inactive fonctionne aujourd'hui. Il dit seulement dans quel ordre il est rationnel de la reprober.

## Règle de développement

Une nouvelle source ne doit être développée que si :

1. elle couvre un angle mort observé, ou apporte une classe d'incidents actuellement mal couverte ;
2. son accès est techniquement démontré par `probe`/`diagnose` ou un contrat API/flux explicite ;
3. elle apporte une information exclusive ou une amélioration de couverture suffisamment forte pour justifier son coût d'entretien ;
4. son intégration réutilise les collecteurs existants lorsqu'ils suffisent.

Une source supplémentaire qui ne fait que dupliquer les mêmes incidents n'est pas un progrès produit.

## Clôture P1.2

Le chantier est considéré clos lorsque le scorecard et le portefeuille sont présents dans le résumé des runs et que toute décision d'ajout/retrait de source peut être reliée à une métrique observée. Les recherches de nouvelles sources deviennent alors des travaux Data ponctuels, pas un chantier d'architecture permanent.
