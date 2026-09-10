# Cyberwatch

Cyberwatch collecte des incidents cyber publiquement documentés, les enrichit,
les déduplique puis publie un dashboard statique.

**Production : https://ya7o.github.io/Cyberwatch/**

Chaque mise à jour cherche seulement les publications d'aujourd'hui et d'hier.
Le corpus déjà publié est conservé tel quel et n'est jamais reconstruit par le
workflow quotidien.

## Chaîne unique

```text
collecte -> identité -> enrichissement -> déduplication -> publication
```

- `data/items.csv` contient les observations issues des sources ;
- `data/incidents.csv` contient les incidents dédupliqués ;
- `assets/data/` est généré pour le dashboard ;
- `main` contient le code, les données et la production GitHub Pages.

La purge utilise la même CLI et le même workflow que la collecte.

## Sources actives

| Source | Accès |
|---|---|
| `FRENCHBREACHES` | RSS |
| `BONJOURLAFUITE` | HTML |
| `CYBERATTAQUE_ORG` | contenu paginé |
| `RANSOMWARE_LIVE` | API JSON |
| `VEILLE_LLM` | snapshot versionné La Réunion / Mayotte |

`VEILLE_LLM` conserve les signaux non confirmés comme `CANDIDATE`, mais seuls
les enregistrements `ACCEPTED` entrent dans le corpus. Deux événements d'une
même organisation et d'un même jour restent distincts lorsque leur
localisation diffère.

## Commandes

```bash
# exécution / collecte
pip install -r requirements.txt

# développement, tests et audit de dépendances
pip install -r requirements-dev.txt

# quotidien : aujourd'hui + hier uniquement
python -m cyberwatch maj

# vider le corpus et le dashboard, sans lancer de collecte
python -m cyberwatch PURGE

# contrôles et dashboard
python -m cyberwatch check
python -m cyberwatch build-site
python -m cyberwatch report
python -m cyberwatch report --qualification [--run-id RUN-…]
python -m cyberwatch production-status --markdown
python -m cyberwatch validate-business
python scripts/apply_editorial_corrections.py --items ITM-…,ITM-…
python scripts/evaluate_qualification.py
python scripts/code_health.py --module-budget 0 --function-budget 0
python scripts/git_governance_audit.py
python scripts/audit_sectors.py
```

`report --qualification` rend, pour un run, les deux tableaux de qualification —
extraction → décision par champ, et déduplication par paire — à partir des
journaux de `data/llm_runs/<RUN_ID>/`. Sans option, `report` conserve son
résumé habituel du dernier run. L'état du verdict (`COMPLETE`, `PARTIAL`,
`NOT_NEEDED`, `UNKNOWN`) est aussi publié dans `assets/data/status.json` ; un
verdict `PARTIAL` affiche « Qualification incomplète » dans le dashboard et
dans le rapport de production, sans interrompre la publication.

`scripts/apply_editorial_corrections.py --items` applique une reprise ciblée :
simulation par défaut, rapport avant/après détaillé, et refus d'écriture si une
observation ou un incident hors périmètre change sémantiquement. `--write`
enregistre les données canoniques, régénère les artefacts et consigne la
réparation dans `data/editorial_repair_report.json`.

`scripts/evaluate_qualification.py` mesure le modèle courant sur les textes
figés de `bench/qualification_eval/expectations.json`, sans écriture en
production. Les étages validation et publication sont mesurés hors réseau ;
l'étage « réponse brute » exige `--api` **et** `OPENAI_API_KEY`, et reste sinon
déclaré « performance non mesurée ».

`maj` ajoute les dernières publications calendaires. Elle peut accéder au
réseau et utiliser l'API OpenAI si `OPENAI_API_KEY` est présente. Sans clé, la
collecte continue et les valeurs non résolues restent `Inconnu`.

Le routage LLM utilise `gpt-5-mini` pour l'extraction de faits, l'analyse
sémantique et la déduplication, et `gpt-5-nano` pour les autres tâches.
`OPENAI_MODEL` permet de remplacer le modèle globalement ; les variables
`<TASK>_MODEL` (par exemple `SOURCE_FACTS_MODEL` ou `DEDUP_MODEL`) ont priorité
pour une tâche donnée. Les appels utilisent l'API Responses avec des sorties
JSON structurées et un effort de raisonnement `minimal` par défaut.

`MAJ` et `PURGE` sont aussi acceptées en minuscules. `MAJ` conserve le stock
existant et fonctionne également sur une base neuve ou purgée. La fenêtre
couvre hier et aujourd'hui à La Réunion (UTC+4) : les dates des sources étant
traitées à la journée, ce n'est pas un filtre glissant à l'heure près.

`PURGE` efface immédiatement les items, incidents, faits, registres calculés,
caches, files de reprise, journaux et rapports générés dans `data/`, puis
régénère le dashboard vide. Elle ne lance ni collecte ni appel LLM. Les
sources, référentiels, alias et corrections éditoriales sont conservés.
La prochaine `MAJ` collecte uniquement sa fenêtre quotidienne ; elle ne
recharge pas tout l'historique. La purge est locale jusqu'à la publication
des fichiers : elle ne réécrit pas l'historique Git.
Les chemins de cache personnalisés doivent rester dans `data/` ; sinon la
purge s'arrête avant toute suppression.

En production, la clé n'est pas stockée dans le dépôt. Elle se trouve dans
GitHub : **Settings → Secrets and variables → Actions → Repository
secrets**, sous le nom `Cyberwatchapi`. Le workflow
`.github/workflows/collect.yml` l'injecte dans `OPENAI_API_KEY`. Sa valeur ne
doit jamais apparaître dans les journaux, les fichiers de données ou les
rapports d'audit.

## Cadre éditorial et licence

Cyberwatch est un outil de veille fondé sur des publications publiques. Une
fiche n’est ni une attribution, ni une confirmation globale de tous les faits,
et l’absence de fiche ne prouve pas l’absence d’incident. Les niveaux de preuve
et les limites sont détaillés dans [METHODOLOGY.md](METHODOLOGY.md).

Pour une correction, un doublon ou une source cassée, ouvrir une
[issue GitHub](https://github.com/Ya7o/Cyberwatch/issues) en fournissant une
source publique vérifiable. La politique complète figure dans
[docs/EDITORIAL_POLICY.md](docs/EDITORIAL_POLICY.md). Le code est distribué sous
[licence MIT](LICENSE).

La politique de branches, tags, rétention et entretien du dépôt est documentée
dans [docs/GIT_GOVERNANCE.md](docs/GIT_GOVERNANCE.md).

L'audit sectoriel et ses corrections sont documentés dans
[docs/SECTOR_IMPLEMENTATION_2026-09-05.md](docs/SECTOR_IMPLEMENTATION_2026-09-05.md).
Le seuil de 10 % d'inconnus déclenche une alerte ; les pertes de transmission
de secteurs étayés bloquent la publication. Aucun secteur générique n'est
attribué pour améliorer le taux. Statut, confiance, motif, preuve et version
de politique sont conservés dans `data/sector_resolution.csv`.

## GitHub Actions

Trois workflows, avec un seul chemin d'écriture des données :

- `ci.yml` audite les dépendances, exécute la suite complète et vérifie que les
  artefacts du dashboard sont reproductibles ;
- `collect.yml` lance une collecte quotidienne à 11 h à La Réunion et publie
  directement les données sur `main` si la branche n'a pas changé pendant le
  run ;
- `monitor.yml` contrôle la fraîcheur toutes les six heures et ouvre, met à
  jour ou clôt un ticket GitHub `[Cyberwatch] Alerte production`.

Le lancement manuel de `collect.yml` propose `operation: MAJ` (par défaut)
ou `PURGE`. La purge publie le dashboard vide sur `main` avec le même verrou
d'écriture que la collecte ; elle ne désactive pas la prochaine MAJ planifiée.
Un plafond global
de 0,03 $ couvre l'extraction de faits et le filet final de déduplication. Les
usages détaillés sont consignés dans `data/llm_usage.json`.

Chaque collecte ajoute une ligne à `data/production_metrics.csv` : taux de
secteur/localisation inconnus, candidats doublons, faux positifs et faux
négatifs du corpus, durée, requêtes, appels LLM et coût. Seuls les runs dont
`Trigger=schedule` comptent dans la preuve des sept succès consécutifs ; les
lancements manuels ne peuvent donc pas gonfler cet indicateur.

Les métriques distinguent aussi les nouveaux items du corpus historique et
suivent la file `data/source_facts_retry_queue.json` : qualifications différées,
tentatives du run et reliquat. Une erreur technique ou un budget épuisé ne
perd donc plus silencieusement un article lorsqu'il sort de la fenêtre de deux
jours.

Les cibles suivies sont : snapshot de moins de 36 h, succès planifié d'au
moins 95 %, secteur inconnu sous 20 % et localisation inconnue sous 5 %.

## Vérification rapide

```bash
python -m pytest tests/ -q
python -m cyberwatch validate-business
node --check assets/dashboard-v2.js
node --check assets/dashboard-integrity.js
```
