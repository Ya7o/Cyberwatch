# Routine Veille LLM — contrat de production

Ce dossier ne contient qu'une source de production : la veille complémentaire
La Réunion / Mayotte. FrenchBreaches et Cyberattaque.org sont collectés par
leurs collecteurs directs ; une routine ChatGPT ne doit pas recréer leurs
tables ni les réinjecter dans l'enrichissement.

## Sortie canonique

La routine remplace
`cyberattaques_reunion_mayotte_2026.json` par un document conforme à
`schema-v2.json`. Elle conserve tous les signaux utiles dans `records`, mais
attribue obligatoirement une admission à chacun :

- `ACCEPTED` : une référence publique documente une cyberattaque, une
  compromission, une fuite, une exfiltration, un rançongiciel, un DDoS, un
  malware, un compte compromis, un incident tiers cyber ou une autre action
  cyber explicite visant une entité de La Réunion ou de Mayotte ;
- `CANDIDATE` : panne, indisponibilité, vandalisme physique, incident
  informatique, rumeur ou signal territorial dont l'origine cyber n'est pas
  démontrée.

Le score est un indicateur analytique. Il ne décide jamais l'admission. Un
`ACCEPTED` doit avoir une `type_menace` canonique différente de `Inconnu`. Si
la nature précise n'est pas démontrée mais que l'incident cyber l'est, utiliser
`Autre cyber`. Une absence de preuve reste `CANDIDATE`.

Chaque record doit conserver au moins une URL documentaire directement liée au
signal. Les snippets de moteur de recherche ne sont pas des preuves. Aucun nom,
date, territoire, menace, secteur, acteur ou impact ne doit être inventé.

## Consigne pour la routine ChatGPT

1. Relire le snapshot courant et effectuer une veille ciblée Réunion/Mayotte.
2. Chercher d'abord les communications des victimes et autorités, puis les
   sources spécialisées et la presse locale.
3. Dédupliquer par événement ; une reprise d'un même fait enrichit `sources`
   mais ne crée pas une nouvelle ligne.
4. Réévaluer l'admission de chaque signal à partir des preuves disponibles.
5. Mettre à jour `generated_at`, `record_count`, `accepted_count` et
   `candidate_count`.
6. Produire uniquement le JSON conforme au schéma. Ne produire ni CSV, ni
   table FrenchBreaches, ni table Cyberattaque.org.

Le collecteur publie uniquement les `ACCEPTED`. Les `CANDIDATE` restent dans le
fichier pour permettre une promotion ultérieure si une preuve apparaît. Un
snapshot âgé de plus de deux jours est signalé `PARTIAL` sans bloquer les autres
sources.
