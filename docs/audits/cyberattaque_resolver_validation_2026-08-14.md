# Validation du resolver Cyberattaque.org — 2026-08-14

## Méthode

Le corpus figé contient 408 réponses de l'API WordPress Cyberattaque.org,
capturées le 2026-08-14. Le benchmark est exécuté avec `--offline` : aucun
collecteur ni client HTTP n'est instancié. Le golden set LLM est uniquement
lu, jamais modifié.

Le corpus du resolver exclut toute ligne `CYBERATTAQUE_ORG`. Pour l'article de
date D, seuls les items d'autres sources publiés de D-14 à D sont admissibles.
Ainsi un article ne peut ni se confirmer lui-même ni exploiter une information
postérieure.

## Résultat causal

| Mesure | Valeur |
|---|---:|
| Articles | 408 |
| Matchs baseline | 362 |
| Matchs final | 367 |
| Différences finales | 41 |
| Résolutions directes | 393 |
| Résolutions resolver | 1 |
| MULTI | 6 |
| NEGATED | 3 |
| NO_VICTIM | 5 |
| Faux positif resolver | 0 |
| Donnée future en vue causale | 0 |

Le seul match resolver causal est l'article « 678 438 lignes de données
fiscales… », rattaché à la Direction générale des Finances publiques avec des
confirmations BonjourLaFuite/FrenchBreaches datées du même jour.

## Limites et décision

Le resolver est causal, déterministe et ne crée pas de faux positif dans le
corpus figé. Son apport est toutefois limité à un seul article causalement
confirmé. **VALIDÉ MAIS INUTILE** : conserver le code simple en MAJ, sans
ajouter de règles ou d'heuristiques supplémentaires.
