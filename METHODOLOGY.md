# Méthode du prototype

## BonjourLaFuite : faits natifs et activité historique

BLF produit un résumé déterministe dès qu'un type de données est publié,
sans écraser un résumé existant. Les bulles et le statut publié sont conservés.
Les types de données servent à l'impact et à la sensibilité, jamais au secteur.

Avant le mapping secteur, les composantes d'incident exclusivement BLF,
inconnues et sans activité ni rubrique exploitable recherchent une activité
historique FrenchBreaches/Cyberattaque.org via l'identité canonique et ses alias.
Une citation attribuant l'activité à l'organisation est obligatoire. L'URL de
l'article améliore le score (2 contre 1 sans URL), puis la date de publication
départage les preuves. Une observation future n'est pas réutilisée. Seules les
descriptions identiques après normalisation sont reconnues compatibles ; les
autres restent en conflit, y compris si leur secteur est identique.

`Source_Metadata_JSON.blf_activity` conserve l'origine, l'item et la source
historiques, l'organisation, la citation, l'URL et le score. Les origines sont
`BLF_ACTIVITY_REUSE`, `BLF_EXTERNAL_ACTIVITY`, `BLF_ACTIVITY_CONFLICT` ou
`BLF_NO_ACTIVITY_EVIDENCE` ; `blf_origin=BLF_NATIVE` identifie les faits natifs.
Les preuves réutilisées sont réévaluées à chaque collecte/replay, et retirées
si elles ne sont plus admissibles. La résolution reste pure et utilise le
mapper secteur existant. Aucun appel LLM n'analyse une fiche BLF.

`OrganisationActivityProvider` est un point d'injection pour un second lot :
aucun provider réseau n'est branché par défaut. Une implémentation devra lire
un contenu vérifiable, privilégier site officiel, registre public puis source
éditoriale fiable. Le contrat exige identité concordante, activité, citation,
URL HTTP(S), provider et confiance >= 0,8. Un résultat de recherche seul,
une déduction depuis le nom ou les données volées ne constituent pas une preuve.

Cyberwatch sert à voir chaque jour les nouveaux incidents cyber, lire une
petite synthèse et ouvrir la fiche détaillée si nécessaire.

## Pipeline

```text
collecte -> identité -> enrichissement -> déduplication -> publication
```

1. **Collecte** — cinq sources publiques fournissent les observations du jour.
2. **Identité** — les noms sont normalisés et quelques alias connus sont
   appliqués sans modifier l'identifiant de l'observation.
3. **Enrichissement** — menace, secteur, localisation et faits utiles sont
   complétés. Une valeur incertaine peut rester `Inconnu`.
4. **Déduplication** — les règles simples regroupent d'abord les observations.
   Un batch LLM final compare seulement les nouveautés à la base et rattrape
   les variantes de nom restantes.
5. **Publication** — `data/` est enregistré puis `assets/data/` est généré pour
   le dashboard GitHub Pages.

Les composantes d'incident sont réunies dans un ordre stable : identité native,
décision `SAME` validée, puis règles déterministes. Chaque réunion contrôle tous
les membres des deux groupes. Un veto natif, une récidive explicite, une date
d'événement contradictoire ou une étendue temporelle supérieure à 14 jours ne
peut donc pas être contourné par une chaîne de rapprochements.

La file du filet LLM distingue les doublons potentiellement manqués, les fusions
faibles à vérifier, les décisions `SAME` encore incompatibles avec les garde-fous
et les paires en attente. Une panne, une désactivation ou une limite de capacité
reste visible ; seules les erreurs de traitement consomment les trois tentatives
automatiques. Les décisions et suppressions de file ne deviennent canoniques
qu'avec le snapshot validé.

Les extractions de qualification bloquées par une panne, une clé absente ou un
budget épuisé entrent dans une file persistante distincte. Elle conserve
l'observation, le hash du contenu, les champs différés et le contexte public
borné, puis reprend quelques articles par collecte même lorsqu'ils ont quitté
la fenêtre aujourd'hui/hier. Une absence explicite devient une abstention
terminale, qui n'est pas un échec et n'ouvre aucune reprise ; une valeur fournie
mais rejetée bénéficie d'un second examen. Pour le couple activité/secteur, ce
second examen est le dernier : après deux rejets sur une même version de champ
et un même contenu, le dossier passe en rejet persistant, aucun appel
automatique ne repart, mais il reste visible et l'alerte de production reste
active jusqu'à résolution ou changement de version.

## Fenêtre quotidienne

`maj` collecte aujourd'hui et hier, car les sources exposent généralement une
date sans heure précise. Les observations plus anciennes restent disponibles,
mais ne sont ni recollectées ni recalculées.

## Contrôle de production

Une source, l'extraction de faits ou le LLM peuvent échouer sans bloquer les
autres. Le déterministe reste le résultat de repli. Le run, ses inconnus, ses
candidats doublons, sa durée, ses requêtes et son coût sont toutefois mesurés :
une incertitude reste visible et ne devient jamais un succès implicite.

Le corpus métier versionné contrôle hors réseau le périmètre cyber, la menace,
le secteur, la localisation et les rapprochements d'identité. La production
utilise uniquement `main`, un workflow quotidien d'écriture et un dashboard
statique ; le monitor de fraîcheur est strictement en lecture seule.

## Niveaux de preuve

Les statuts qualifient une affirmation précise, pas la fiche entière :

| Niveau | Sens dans Cyberwatch |
|---|---|
| **Confirmé** | élément explicitement établi par une source directe ou suffisamment étayé par les éléments publiés ; |
| **Rapporté** | élément relaté par une source identifiable sans confirmation indépendante suffisante ; |
| **Revendiqué** | déclaration attribuée à un acteur, notamment une revendication d’attaque ; |
| **Hypothèse / non confirmé** | piste ou interprétation conservée comme incertaine et jamais présentée comme un fait ; |
| **Démenti** | élément explicitement contesté ou nié ; il est conservé pour éviter qu’il soit réintroduit comme positif ; |
| **Inconnu** | aucune preuve publiable suffisante pour renseigner le champ. |

Une corroboration par plusieurs liens augmente la traçabilité mais ne remplace
pas une confirmation. Les champs sensibles et les volumes restent associés à
leur propre statut et à leurs sources.

## Limites et corrections

La couverture dépend de sources publiques, de leurs délais et de leur
accessibilité. Les résultats ne mesurent donc ni l’incidence réelle de la
cybercriminalité, ni la performance de sécurité d’une organisation. Les
tendances sont neutralisées tant que deux fenêtres continues de 30 jours ne
sont pas disponibles.

La politique éditoriale, l’avertissement d’usage et le canal de correction sont
publiés dans [docs/EDITORIAL_POLICY.md](docs/EDITORIAL_POLICY.md).

### Résolution sectorielle opérationnelle

La résolution privilégie le référentiel exact sourcé et les identités
institutionnelles explicites, puis les faits de la source : secteur structuré
ou activité étayée permettant une inférence. La description et le secteur
sémantique forment une paire validée, liée à l'organisation victime. Le récit de
la cyberattaque, l'activité d'un prestataire et la seule appartenance à un
groupe ne sont jamais l'activité de la victime. Une désignation
institutionnelle — « la mairie », « la municipalité » — n'est retenue que si la
phrase citée ou celle qui la précède immédiatement la rattache explicitement à
la victime, sans autre collectivité nommée dans cette fenêtre.
Les contradictions restent inconnues et sont journalisées ; aucun repli
générique n'est autorisé. Chaque refus porte son motif — absence explicite,
activité non décrite, activité de tiers, identité ambiguë, citation introuvable
ou contradiction sectorielle — et la couverture sectorielle publiée se lit
séparément de l'état d'extraction. Une inférence ne devient pas une confirmation
lors d'une reprise. Chaque décision conserve sa provenance dans
`data/sector_resolution.csv`. Les contrôles de transmission bloquent la
publication si un secteur étayé est perdu. Le seuil d'inconnus est une alerte.
Le détail est publié dans `docs/SECTOR_IMPLEMENTATION_2026-09-05.md`.

### Menace et localisation

La menace principale est résolue à partir des affirmations positives du titre
et des faits structurés. Les négations sont retirées avant la détection ; un
défaut de flux ne peut pas écraser une menace spécifique étayée. L'événement
principal prime sur son vecteur d'accès et sur un risque futur cité dans la
source.

Une localisation textuelle est retenue seulement avec un marqueur territorial
non ambigu. Un nombre de comptes ressemblant à un code postal n'est pas une
preuve, et la proposition localisant un prestataire ou un autre tiers est
écartée. Un lieu fin sourcé peut corriger le défaut géographique d'une source
lorsque sa citation nomme explicitement la victime. Des territoires
incompatibles dans un même incident produisent `Inconnu` au lieu d'un choix par
ordre lexical.


### Secteur établi et description d'activité

La qualification sectorielle et la description métier sont évaluées séparément.
Une référence exacte sourcée, une identité institutionnelle explicite ou une
rubrique sectorielle attachée à l'article suffisent à établir le secteur sans
forcer une description d'activité. Une rubrique source est `reported`, une
identité ou activité interprétée reste `inferred`.

Une fois le secteur étayé, les champs activité/secteur ne sont plus demandés ni
repris automatiquement. Les refus antérieurs restent dans les traces et caches
pour audit ; ils ne déclenchent plus d'alerte sectorielle. Les secteurs inconnus,
non étayés ou contradictoires restent signalés, ainsi que les difficultés de
qualification des autres champs. Les règles de priorité et le refus de
l'activité d'un prestataire sont conservés.
