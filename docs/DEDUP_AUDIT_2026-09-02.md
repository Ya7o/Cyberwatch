# Audit de la chaîne de déduplication — 2026-09-02

## Décision

La chaîne conserve une autorité déterministe en production. Les corrections
implantées sont limitées aux deux risques P1 et à l'identité native de
`RANSOMWARE_LIVE` : aucune fusion probabiliste n'est ajoutée.

## État observé du snapshot

Le snapshot contient 42 items, 27 incidents et un registre d'incident persistant
avec 1 décision `SAME`. Les identifiants natifs sont présents pour :

```text
CYBERATTAQUE_ORG  17 / 17
FRENCHBREACHES    22 / 22
BONJOURLAFUITE     0 / 2
RANSOMWARE_LIVE    0 / 1 (item historique, avant le correctif du collecteur)
```

Cette absence historique n'est pas réparée par heuristique : le collecteur
Ransomware renseigne désormais `Source_Item_ID` lorsqu'une clé native (`id`,
`post_id`, `claim_id`, UUID ou slug) est fournie par l'API.

## Corrections

### Temps

`dedup._temporal_pair()` compare les deux `Event_Date` lorsqu'elles existent,
sinon les deux `Published_Date`. Une `Event_Date` ne peut donc plus être
comparée directement à la publication de l'autre item. Le veto sur deux dates
d'événement contradictoires reste prioritaire.

Une décision LLM `same_incident=SAME` est refusée au-delà de
`config.INCIDENT_GAP_DAYS` (14 jours). La borne est appliquée avant l'écriture
du registre et à nouveau lors de la construction des composantes.

### Identité Ransomware

Les doublons d'une même revendication sont dédupliqués par identifiant natif.
Sans identifiant, le fallback structuré combine organisation, date, groupe et
URL : deux groupes distincts le même jour ne sont plus supprimés ensemble.

Les combinaisons de corroboration ransomware autorisées sont explicitement
`RANSOMWARE_LIVE`/`CYBERATTAQUE_ORG`, `RANSOMWARE_LIVE`/`FRENCHBREACHES` et
`CYBERATTAQUE_ORG`/`FRENCHBREACHES`. Les signaux indiquent maintenant les vraies
sources `claim=` et `report=`.

## Tests de non-régression ajoutés

- Event_Date / Published_Date mixte, dans les deux ordres ;
- `SAME` LLM à J+9 et J+14 accepté ; J+15 refusé ;
- refus de persistance d'un `SAME` LLM au-delà de la borne ;
- deux groupes ransomware le même jour conservés, doublon natif supprimé.

La décision `SAME` d'organisation reste indépendante : deux épisodes éloignés
peuvent toujours être reconnus comme la même organisation sans être fusionnés.
