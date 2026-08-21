# Ré-audit LLM obligatoire avant reset DB

Le reset/rebuild de la base ne doit être déclenché qu'après un ré-audit LLM sur le commit destiné à être reconstruit.

## Préflight offline

Exécuter :

```bash
python -m cyberwatch.llm_preflight
```

Le préflight ne doit effectuer aucun appel réseau ni LLM. Il doit confirmer le routage effectif suivant, sauf override explicitement documenté :

- `qualification` → `gpt-5-nano`
- `source_facts` → `gpt-4o-mini`
- `cyberattaque_semantic` → `gpt-4o-mini`
- `dedup` → `gpt-4o-mini`

Le rapport doit inventorier les caches compatibles, incompatibles et sans métadonnée de modèle. Un `NO-GO` interdit le reset jusqu'à analyse des invalidations.

## Ré-audit après merge

Vérifier, sur `main` :

1. routage réel par tâche et precedence des overrides ;
2. budgets globaux et quotas par tâche ;
3. absence de chemin direct pouvant contourner `LlmRuntime.post_response()` ;
4. compatibilité `model + prompt + schema + content/identity` des caches ;
5. taux de cache et backlog froid estimé avant rebuild ;
6. télémétrie `task/model/tokens/cost/latency/retries/cache` ;
7. validation mécanique des preuves et Structured Outputs ;
8. comportement sur 429, 5xx, timeout, budget épuisé et réponse incomplète ;
9. coût par sortie/fait accepté pour les tâches sémantiques ;
10. zéro appel LLM lors du rebuild cache-only de validation.

## Gates de reset

Le reset est `GO` seulement si :

- la suite de tests est verte ;
- `python -m cyberwatch.llm_preflight` ne remonte aucune invalidation inexpliquée ;
- le modèle effectif est visible dans la télémétrie par tâche ;
- les plafonds de coût sont inférieurs ou égaux au budget opérationnel décidé ;
- les caches et registres nécessaires au rebuild sont sauvegardés et conservés ;
- le rebuild prévu force les nouveaux appels LLM à zéro pour la première reconstruction.

Après le rebuild cache-only, comparer avant/après : nombre d'items/incidents, stabilité des IDs, taux d'`Inconnu`, cache hits/misses, qualité SourceFacts et régressions de qualifications connues vers `Inconnu`.
