# Correctif de la chaîne de qualification et de déduplication — 10/09/2026

Livrables de la correction des défauts établis par l'audit de
`RUN-20260910T072351`. Tout est produit hors réseau, sans collecte réelle,
sans push, et sans écriture dans `data/` ni `assets/data/` autre que la
régénération normale du dashboard.

## Ce qui est livré

| Fichier | Contenu |
|---|---|
| `run_audite_qualification.md` | Tableaux extraction → décision par champ et déduplication par paire du run audité, plus les 17 valeurs de cache réutilisées et le verdict que les contrats actuels leur appliquent. |
| `reprise_ciblee_simulation.json` | Simulation de la reprise ciblée sur l'état audité reconstitué : avant/après complet, sans écriture. |
| `reprise_ciblee_resultat.json` | Résultat de la même reprise avec `--write` : 130 observations, 75 incidents, redirection et file de déduplication réconciliée. |
| `evaluation.json` | Bilan de l'évaluation isolée du modèle courant sur les textes figés. |

Reproduction :

```bash
python -m cyberwatch report --qualification --run-id RUN-…
python scripts/build_audited_snapshot.py /tmp/etat-audite
python scripts/apply_editorial_corrections.py --items ITM-0c085da888611a12,ITM-f2c9b54af4eae1da
python scripts/evaluate_qualification.py
```

## Résultat sur les deux observations du Tampon

Un seul incident, `INC-AF70EBB0A692`, deux sources, **Le Tampon**,
Administration / Collectivité, La Réunion, menace **Inconnu**, aucun vecteur
d'accès publié, aucun nombre de victimes, aucune donnée exposée affirmée.
`INC-F7E0A7E8A73F` devient une redirection.

## Ce qui reste explicitement non mesuré

L'étage « réponse brute du modèle » de `evaluate_qualification.py` n'a pas été
exécuté : il exige `--api` **et** `OPENAI_API_KEY`, et respecte alors le
plafond partagé de 0,03 $. Le bilan porte donc la mention **« performance non
mesurée »**. Les étages validation et publication, eux, sont mesurés hors
réseau. Aucune comparaison de modèles n'a été conduite et aucune supériorité
n'est revendiquée.

Le run audité est antérieur à la journalisation des lectures de cache : ses
17 valeurs acceptées ne figurent pas dans sa trace et sont reprises depuis les
preuves figées par l'audit. Les runs suivants les tracent nativement.

## Périmètre de la reprise

La reprise ciblée porte sur les six observations traitées par le run audité :
les deux nouveautés du Tampon et les quatre articles Citadium/Printemps relus.
**Le corpus canonique du dépôt ne contient pas les deux observations du
Tampon** — le run audité n'a jamais été commité — de sorte que la reprise est
sans effet sur `data/` en l'état. Elle est donc démontrée sur l'état audité
reconstitué par `scripts/build_audited_snapshot.py`, à partir de
`audit/latest_collection_2026-09-10/run_snapshot.json`.
