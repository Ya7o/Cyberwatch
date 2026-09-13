# Benchmark d'activation — activité externe (niveau 2)

Version du corpus : `2026-09-13.external-activity.1` — 20 incidents, évalués hors ligne.

**Verdict : PASS**

## Portes bloquantes

| Porte | Résultat | Détail |
| --- | --- | --- |
| `cas_executes` | réussie | 20/20 |
| `zero_faux_positif` | réussie | [] |
| `zero_erreur_identite` | réussie | [] |
| `zero_secteur_sans_activite_prouvee` | réussie | [] |
| `decisions_correctes` | réussie | 20/20 |
| `rappel_sur_cas_repondables` | réussie | 9/9 |
| `idempotence` | réussie | [] |
| `budget_par_cas` | réussie | [] |
| `budget_llm_total` | réussie | 5 |
| `budget_reseau_total` | réussie | 21 |

Total : 20/20 décisions correctes, 11 abstentions, 21 requêtes HTTP, 5 appels de modèle.

## Détail par incident

| Cas | Ce qu'il teste | Attendu | Obtenu | Motif | Req. | LLM | OK |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `01-nom-simple-site-officiel` | nom simple, site officiel facile, activité déterministe | Transport / Logistique | Transport / Logistique | `EXTERNAL_ACTIVITY_VERIFIED` | 1 | 0 | oui |
| `02-url-de-reference` | URL de validation du référentiel, secteur déterministe | Commerce / Distribution | Commerce / Distribution | `EXTERNAL_ACTIVITY_VERIFIED` | 1 | 0 | oui |
| `03-site-officiel-difficile` | page-défi après HTTP 200, ordre des candidats | Industrie / Manufacture | Industrie / Manufacture | `EXTERNAL_ACTIVITY_VERIFIED` | 2 | 0 | oui |
| `04-activite-mappee-par-le-mapper` | activité prouvée, secteur résolu par le mapper taxonomique existant | Numérique / Technologie | Numérique / Technologie | `EXTERNAL_ACTIVITY_VERIFIED` | 1 | 1 | oui |
| `05-citation-choisie-par-le-modele` | citation désignée par le modèle, puis revalidée déterministement | Hébergement / Tourisme / Restauration | Hébergement / Tourisme / Restauration | `EXTERNAL_ACTIVITY_VERIFIED` | 1 | 1 | oui |
| `06-citation-inventee-par-le-modele` | citation absente de la page téléchargée, rejetée mécaniquement | Inconnu | Inconnu | `EXTERNAL_QUOTE_NOT_GROUNDED` | 1 | 1 | oui |
| `07-homonyme-nom-plus-long` | la page nomme une entité plus large que la victime | Inconnu | Inconnu | `EXTERNAL_IDENTITY_HOMONYM` | 1 | 0 | oui |
| `08-homonyme-resolu-par-alias` | un alias validé résout l'homonymie au lieu d'être bloqué par elle | Numérique / Technologie | Numérique / Technologie | `EXTERNAL_ACTIVITY_VERIFIED` | 1 | 0 | oui |
| `09-nom-court-ambigu` | nom court ambigu, la page décrit une autre entreprise | Inconnu | Inconnu | `EXTERNAL_NO_QUOTE` | 1 | 0 | oui |
| `10-marque-et-forme-juridique` | marque contre société juridique, forme postposée acceptée | Numérique / Technologie | Numérique / Technologie | `EXTERNAL_ACTIVITY_VERIFIED` | 1 | 0 | oui |
| `11-organisation-absente-de-la-page` | la page ne nomme pas la victime : la bonne réponse est Inconnu | Inconnu | Inconnu | `EXTERNAL_IDENTITY_NOT_NAMED` | 1 | 0 | oui |
| `12-piege-prestataire` | activité attribuée à un prestataire, refusée après désignation | Inconnu | Inconnu | `EXTERNAL_ACTIVITY_THIRD_PARTY` | 1 | 1 | oui |
| `13-piege-filiale` | appartenance à un groupe : le métier décrit est celui de la maison mère | Inconnu | Inconnu | `EXTERNAL_ACTIVITY_NOT_DESCRIBED` | 1 | 0 | oui |
| `14-recit-d-incident-seul` | la page ne décrit que l'incident, jamais le métier | Inconnu | Inconnu | `EXTERNAL_NO_QUOTE` | 1 | 0 | oui |
| `15-activite-reellement-ambigue` | activité prouvée mais trop vague : abstention justifiée | Inconnu | Inconnu | `EXTERNAL_ACTIVITY_VERIFIED` | 1 | 1 | oui |
| `16-registre-homonyme-qare` | fiche de registre concordante par le nom, sans corroboration indépendante | Inconnu | Inconnu | `EXTERNAL_IDENTITY_UNVERIFIED` | 1 | 0 | oui |
| `17-registre-corrobore-par-la-commune` | fiche de registre corroborée par la commune du siège | Transport / Logistique | Transport / Logistique | `EXTERNAL_ACTIVITY_VERIFIED` | 1 | 0 | oui |
| `18-registre-conflit-de-preuve` | la raison sociale classerait ailleurs que le code d'activité | Inconnu | Inconnu | `EXTERNAL_EVIDENCE_SECTOR_CONFLICT` | 1 | 0 | oui |
| `19-cible-interdite-et-redirection` | adresse privée résolue et redirection vers un service de métadonnées | Inconnu | Inconnu | `EXTERNAL_REDIRECT_REJECTED` | 1 | 0 | oui |
| `20-reutilisation-du-cache` | preuve réutilisée d'un incident à l'autre, sans nouvelle requête | Transport / Logistique | Transport / Logistique | `EXTERNAL_ACTIVITY_VERIFIED` | 1 | 0 | oui |
