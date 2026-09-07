# Runbook de production J3–10

## Cibles

| Indicateur | Cible | Source de vérité |
|---|---:|---|
| Fraîcheur du snapshot | `< 36 h` | `data/snapshot.json` |
| Succès des runs planifiés | `≥ 95 %` sur les 30 derniers | `data/run_log.csv`, `Trigger=schedule` |
| Série de stabilisation | `7` succès planifiés consécutifs | `data/run_log.csv` |
| Secteur inconnu | `< 20 %` des incidents publiés | `data/production_metrics.csv` |
| Localisation inconnue | `< 5 %` des incidents publiés | `data/production_metrics.csv` |

Les doublons potentiels, le taux de faux positifs du corpus, les faux négatifs,
la durée, les requêtes, les appels LLM et le coût sont suivis sans seuil de
blocage automatique. Un « doublon potentiel » est une paire envoyée à l'audit,
pas un doublon confirmé. Son taux est exprimé en paires candidates pour 100
incidents ; il peut donc dépasser 100 si un incident participe à plusieurs
paires.

## Publication

`collect.yml` mémorise le SHA de `main` au démarrage. Juste avant le commit, il
récupère `origin/main` et annule la publication si ce SHA a changé. Le push
normal, sans rebase automatique, protège la dernière fenêtre entre ce contrôle
et l'écriture distante.

## Clé OpenAI du workflow

La clé de production est un secret GitHub du dépôt. Elle se consulte ou se
remplace dans **Settings → Secrets and variables → Actions → Repository
secrets**, entrée `Cyberwatchapi`. GitHub ne permet pas de relire sa valeur
après enregistrement ; seule son existence et sa date de mise à jour sont
visibles. `.github/workflows/collect.yml` injecte ce secret dans la variable
`OPENAI_API_KEY` uniquement pendant l'étape `Collecter`.

Pour confirmer la configuration sans divulguer la valeur :

```bash
python scripts/check_llm_config.py
```

Le fichier `.env` local est ignoré par Git. Ne jamais copier la valeur du
secret dans une issue, un log, un rapport d'audit ou un fichier versionné.

## Reprise secteur et déduplication du 6 septembre 2026

La commande suivante reconstruit d'abord les CSV dans un dossier séparé :

```bash
python scripts/backfill_sector_dedup.py
```

Après revue de `validation/sector_dedup_2026-09-06/backfill/`, `--apply`
recopie les artefacts validés dans `data/`. La reprise est idempotente. Elle
n'appelle pas l'API OpenAI : les deux paires historiques sont appuyées par les
décisions relues dans `audit/sector_dedup_2026-09-06/`.

Le retour arrière local restaure les fichiers contenus dans
`validation/sector_dedup_2026-09-06/before.tar.gz`, puis reconstruit le site et
relance `check` et `validate-business`. Avant restauration, vérifier que la
liste des chemins de l'archive reste contenue dans le dépôt.

## Notification

`monitor.yml` vérifie la production toutes les six heures. Une collecte en
échec, un snapshot périmé ou une cible qualité dépassée ouvre ou met à jour un
ticket unique `[Cyberwatch] Alerte production`. Le ticket est clôturé au retour
dans les cibles.

## Diagnostic

```bash
python -m cyberwatch production-status --markdown
python -m cyberwatch report
python -m cyberwatch validate-business
```

La série `0/7` est normale au démarrage du dispositif : les deux anciens runs
ne portent pas de preuve de déclenchement et sont donc marqués `unknown`. Ne
jamais les requalifier manuellement en runs planifiés.

## Qualification et reprise différée

La file `data/source_facts_retry_queue.json` contient les extractions de faits
interrompues par une panne, une clé absente, un budget épuisé ou un premier
rejet récupérable. Une collecte reprend au plus cinq entrées antérieures après
avoir traité les nouveaux articles. Les colonnes `SourceFacts_Retry_*` de
`data/production_metrics.csv` donnent le stock avant le run, les tentatives et
le reliquat ; `SOURCE_FACTS_RETRY_MAX_PER_RUN` ajuste la limite sans modifier la
fenêtre de collecte.

Pour recalculer hors réseau secteur, menace et localisation sur le snapshot
existant :

```bash
python scripts/repair_qualifications.py          # simulation
python scripts/repair_qualifications.py --write  # application contrôlée
python -m cyberwatch check
python -m cyberwatch build-site
```

La reprise refuse toute modification d'identifiant ou de champ extérieur aux
trois qualifications. Son rapport est écrit dans
`data/qualification_repair_report.json`.
