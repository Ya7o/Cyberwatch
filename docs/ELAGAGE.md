# Élagage du dashboard — 11 septembre 2026

Le périmètre retenu réduit le contrat LLM et les données envoyées au navigateur.
Il conserve le corpus canonique, les preuves et les outils de diagnostic.

1. Demander seulement `summary`, `incident_summary`, `data_types`,
   `activity_description`, `activity_sector_match` et `threat_candidate` au LLM,
   selon les besoins et les caches de chaque article. Retirer `impact`,
   `initial_access`, `threat_actor`, `third_party`, `fine_location`,
   `affected_counts`, `affected_systems` et `affected_datasets` des demandes.
2. Départager les résumés validés avec les champs conservés, puis la priorité
   de source et un ordre stable. Les détails historiques ne donnent plus de
   bonus aux anciens articles. Les deux paragraphes restent issus d'un seul article.
3. Publier dans `facts.json` seulement la version, la headline et les paragraphes.
   Réduire les incidents aux champs affichés, y compris les réserves de secteur
   et de menace, les liens source et les trois indicateurs de sensibilité.
4. Retirer de `status.json` les blocs sans lecteur : entités, groupes de couverture,
   angles morts, historique et analytics non affichées. Réduire les lignes source
   en conservant leur état, leur date, leur durée, leur volume et leur motif.
   Conserver intégrité, qualification et suivi de production.
5. Ne plus réécrire la veille par entité quand sa couche n'a aucune source active.
   Journaliser uniquement les couches sélectionnées qui ont des sources actives.
6. Isoler les régressions du Tampon et de reprise éditoriale du corpus vivant.

Les versions des six champs conservés ne changent pas : leurs caches restent
réutilisables. Les anciens validateurs restent nécessaires à la lecture des
preuves historiques. La reprise retire les champs abandonnés de la file courante,
sans effacer les pannes des champs conservés ni les archives des runs précédents.

La reconstruction du site ne collecte rien et n'appelle pas le LLM. Les détails
de `data/` et les calculs analytics utilisés par les outils internes sont conservés.
Les économies réelles de tokens seront mesurables lors d'une prochaine collecte.

## Validation locale

La suite complète passe : **1 261 tests**, dont les sept régressions auparavant
liées au corpus vivant. Les deux scripts JavaScript passent `node --check` et
`cyberwatch check --allow-uninitialized` valide les 7 items et 3 incidents.
La reconstruction conserve toutes les valeurs actuellement lues par le dashboard.
Le corpus canonique est inchangé.

| Fichier | Avant (octets) | Après (octets) | Réduction |
| --- | ---: | ---: | ---: |
| `facts.json` | 11 133 | 1 453 | 86,9 % |
| `status.json` | 43 632 | 9 105 | 79,1 % |
| `incidents.json` | 8 008 | 3 295 | 58,9 % |
| `latest.json` | 8 008 | 3 295 | 58,9 % |

Ces mesures portent sur le corpus local de 3 incidents. Aucun déploiement ni
appel LLM réel n'a été effectué pour cette validation.
