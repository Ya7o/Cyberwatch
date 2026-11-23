---
name: audit-cyberwatch
description: Audite les derniers résultats du tableau de bord Cyberwatch après un déploiement. Vérifie la collecte, l’identité, la déduplication, la qualification et la publication, corrige les anomalies confirmées et pousse les correctifs validés sur main.
---

# Audit Cyberwatch

Lance ce déroulé à la demande explicite d’un audit Cyberwatch de bout en bout.
Respecte les restrictions demandées, par exemple « audit seul » ou « sans push ».

## Délimiter l’audit

- Lis `AGENTS.md` et le README. Identifie le dernier déploiement qui touche la
  chaîne et, si disponible, le SHA effectivement servi par GitHub Pages.
- Examine les résultats publiés depuis ce déploiement dans
  [l’interface de production](https://ya7o.github.io/Cyberwatch/).
  Si la borne est incertaine, explique la période retenue. Indique les dates
  selon le fuseau `Indian/Reunion`.
- Choisis des incidents publiés représentatifs et des observations collectées
  sans publication correspondante. Trace les premiers jusqu’aux sources et
  suis les secondes jusqu’à leur décision de publication.

## Vérifier la chaîne

1. **Collecte.** Rapproche les entrées sources de `data/items.csv`. Vérifie
   la fraîcheur, les entrées manquantes, les erreurs et les reprises à l’aide
   de `data/run_log.csv`, `data/run_sources.csv` et des exécutions de
   `collect.yml`.
2. **Identité et déduplication.** Relie les observations à leur incident dans
   `data/incidents.csv`. Vérifie les regroupements, les références sources
   conservées et les identifiants. Distingue les doublons persistants des
   fusions abusives et examine les décisions en attente si elles expliquent
   un écart.
3. **Qualification.** Vérifie l’enrichissement, les statuts et l’éligibilité à
   la publication selon les règles du dépôt. Contrôle les preuves des secteurs
   attribués et les motifs des secteurs `Inconnu`, des rejets et des cas en attente.
4. **Publication.** Rapproche les données canoniques de `data/`, les JSON générés
   de `assets/data/` servis par GitHub Pages et leur rendu dans le tableau
   de bord. Vérifie les publications manquantes, répétées, obsolètes ou
   inattendues, ainsi que l’ordre, les dates et les filtres.

Appuie chaque anomalie sur un identifiant, un horodatage, une source ou un lien
vers une exécution. Si l’écart vient d’un décalage de déploiement, identifie les
versions comparées.

## Corriger et valider

- Corrige chaque anomalie confirmée à l’étape où elle apparaît. Préserve les
  modifications locales étrangères à l’audit. Corrige la source ou la
  génération lorsqu’un écart touche un fichier généré.
- Rejoue les cas concernés via les points d’entrée habituels et les jeux de
  test du dépôt. Contrôle l’idempotence si le correctif touche les reprises,
  la déduplication ou la publication.
- Lance les contrôles du dépôt applicables au correctif.

  ```bash
  python -m pytest tests/ -q
  python -m cyberwatch check --allow-uninitialized
  python -m cyberwatch validate-business
  node --check assets/dashboard-v2.js
  node --check assets/dashboard-integrity.js
  ```

- Vérifie le rendu local ou de préproduction si l’interface est touchée.
  Réserve les opérations de production autorisées au workflow
  `.github/workflows/collect.yml`, conformément à `AGENTS.md`.
  Valide les correctifs avec des jeux de test hors production.

## Pousser sur main et rendre compte

- Si des correctifs sont validés, vérifie l’état de `main` côté distant,
  crée un commit ciblé et pousse sur `main` sans forcer. Si la branche
  impose une pull request, suis le flux du dépôt.
- Vérifie le SHA distant et, si disponible, la CI associée. Si le push
  déclenche un déploiement, vérifie le SHA servi et contrôle à nouveau les
  résultats concernés dans l’interface dès que le déploiement est visible.
- Donne la période, le périmètre vérifié, les anomalies et leurs correctifs,
  les résultats des tests, le SHA et l’état de la CI et du déploiement.
  Indique les points encore ouverts et la raison de chacun dans le compte
  rendu de la session.
