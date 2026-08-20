# Cyberattaque.org — backfill sémantique

## Contrat

Le backfill sémantique est auxiliaire : il enrichit `data/source_facts.csv` et le cache sémantique, sans modifier directement l'identité des items/incidents ni les règles de déduplication.

Le workflow `.github/workflows/cyberattaque-rich-backfill.yml` effectue un seul rebuild déterministe du corpus, puis traite le sémantique par lots bornés. Il ne relance pas `CREATE core` entre les lots.

## Reprise

Le moteur est `cyberwatch/cyberattaque_semantic_backfill.py`, exposé par :

```bash
python scripts/backfill_cyberattaque_semantic.py \
  --start 2026-01-01 \
  --max-calls 25 \
  --progress data/quality/cyberattaque_semantic_progress.json \
  --backlog data/quality/cyberattaque_semantic_backlog.json
```

Les états de backlog sont :

- `pending` : candidat non encore traité faute de budget ;
- `completed_llm` : traité par un nouvel appel sémantique ;
- `completed_cache` : résultat réutilisé depuis le cache ;
- `failed_retryable` : échec technique pouvant être rejoué ;
- `not_candidate` : article ne nécessitant pas de filet sémantique.

Le cache est indexé par hash de contenu + version de prompt + modèle. Un article inchangé avec le même contrat sémantique ne doit donc pas consommer un nouvel appel.

## Télémétrie

`data/quality/cyberattaque_semantic_progress.json` expose notamment :

- `posts_fetched`, `matched_items` ;
- `llm_calls`, `cache_hits`, `updated` ;
- `pending`, `failed_retryable`, `completed` ;
- `backlog_remaining`, `duration_s`, `cache_entries`.

Chaque lot du workflow publie son checkpoint (`source_facts`, cache, progression et backlog) avant de passer au suivant.

## Clôture

Le verdict est calculé par :

```bash
python scripts/certify_cyberattaque_semantic_closeout.py
```

`READY` exige simultanément :

- certification rich facts `certified=true` ;
- `backlog_remaining=0` ;
- `pending=0` ;
- `failed_retryable=0`.

Un backlog positif signifie `NOT_READY`, mais n'est pas une panne : les checkpoints restent publiables et le traitement peut reprendre. Lorsqu'un run annonce que le backlog est épuisé, le workflow exige strictement `READY`.

## Réouverture du chantier

Le développement ne doit être rouvert que si l'une des propriétés suivantes casse :

- le backlog ne décroît pas entre des passages avec budget disponible ;
- des articles inchangés ne réutilisent plus le cache ;
- interruption + reprise ne converge plus vers le même résultat qu'un run complet ;
- la certification rich facts régresse ;
- des erreurs `failed_retryable` persistent sans cause externe identifiable.
