# Runtime LLM Cyberwatch

## Principe

Le LLM est une couche auxiliaire. Il ne décide jamais `Item_ID`, `Organisation_Key` ou `Incident_ID`, et ne remplace pas une valeur canonique déjà prouvée. Les règles structurées et déterministes restent prioritaires ; l'IA intervient seulement sur un manque sémantique explicite et doit pouvoir s'abstenir.

## Architecture

Tous les transports OpenAI passent par `cyberwatch.llm_runtime` :

- qualification `Threat` / `Sector` / `Location` via `cyberwatch.ai` ;
- faits sémantiques via `cyberwatch.source_facts_ai` ;
- challenger de déduplication via `cyberwatch.dedup_ai` (qui réutilise le transport de `ai`) ;
- claims / timeline / relations éditoriaux via `cyberwatch.collectors.semantic_claims`.

Les politiques métier, caches spécialisés et validateurs restent dans leurs modules. Le runtime commun ne devient pas une source de vérité : il fournit transport, retry, budget et télémétrie.

## Garde-fous

Les appels sémantiques riches utilisent Structured Outputs (`json_schema`, `strict=true`). Chaque claim doit contenir un extrait `evidence` retrouvé dans l'article. Les nombres sont revalidés mécaniquement. Les statuts `hypothesis`, `denied`, `negated` et `unknown` ne doivent jamais être promus silencieusement en faits confirmés.

Le texte source est traité comme donnée non fiable : les prompts demandent explicitement d'ignorer les instructions éventuellement contenues dans l'article. Aucun outil ni agent n'est exposé au modèle.

## Budget global

Le runtime applique un garde-fou de processus, en plus des sous-budgets métier historiques :

- `LLM_MAX_CALLS_PER_RUN` : 3000 par défaut ;
- `LLM_MAX_COST_USD_PER_RUN` : 2 USD par défaut ;
- `LLM_TIMEOUT_SECONDS` : 30 s par défaut ;
- `LLM_MAX_RETRIES` : 2 par défaut.

Les sous-systèmes conservent leurs limites (`AI_*`, `SOURCE_FACTS_AI_*`, `DEDUP_AI_*`). Une tâche ne peut donc pas contourner le plafond global en respectant uniquement son budget local.

## Télémétrie

`data/llm_usage.json` est écrit en fin de processus lorsqu'au moins un appel a été tenté. Il agrège :

- appels tentés/réussis/échoués/bloqués ;
- retries, timeouts, HTTP 429 et 5xx ;
- tokens input/cache/output/reasoning ;
- coût estimé ;
- durée cumulée ;
- ventilation par tâche.

Les métriques spécialisées existantes restent disponibles (`data/ai_usage.csv`, `data/source_facts_ai_usage.json`). Les extracteurs riches ajoutent également `accepted_facts_per_call`, `cost_per_accepted_fact` et `latency_per_accepted_fact` dans leur cache de résultat.

## Cache et compatibilité

Les caches métier ne sont pas fusionnés artificiellement : leurs granularités diffèrent et font partie de leur contrat de reproductibilité. Le transport commun n'invalide pas les caches existants. Les versions de prompt Cyberattaque.org et editorial ont été conservées lorsque le changement ne modifiait que le transport.

Une invalidation doit être déclenchée uniquement lorsqu'un changement peut modifier la décision : prompt métier, schéma sémantique, modèle ou contenu pertinent.

## Sélection des appels

Le LLM ne doit pas être appelé parce qu'un article est simplement long. L'extracteur partagé privilégie un gap observable : ambiguïté, plusieurs événements/dates, richesse relationnelle ou champs structurés encore manquants.

La règle de coût à préserver est :

```text
donnée structurée → extraction déterministe → cache → LLM → validation mécanique → abstention
```

## Validation

La CI doit rester exécutable sans `OPENAI_API_KEY`. Les appels réseau sont simulés dans les tests. Les contrôles obligatoires avant merge sont :

```bash
python -m pytest
python scripts/check_dedup_golden.py
python scripts/check_rich_facts_closeout.py
```

Le benchmark API réel reste volontairement séparé de la CI standard. `bench/qualification_bench.py` permet un T0/T1 frais avec cache vide et échantillon figé.

## KPI de décision

Le coût brut n'est pas un KPI suffisant. Les décisions de modèle/prompt doivent être fondées sur :

- précision / rappel sur golden ;
- taux d'abstention correcte ;
- taux d'evidence non supportée ;
- gain marginal par rapport au déterministe ;
- faits validés par appel ;
- coût par fait validé ;
- latence par fait validé ;
- taux de cache sur contenu inchangé.

Une variante de prompt ou un modèle plus cher ne doit être adopté que s'il améliore significativement ces métriques, pas parce qu'il produit davantage de valeurs non `Inconnu`.
