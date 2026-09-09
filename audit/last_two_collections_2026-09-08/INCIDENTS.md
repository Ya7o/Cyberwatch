# Audit incident par incident — collectes des 7 et 8 septembre 2026

73 fiches distinctes, présentes dans au moins un des deux snapshots ; 68 fiches au premier run et 73 au second. Toutes ont été jointes aux observations, faits source, décisions sectorielles, traces disponibles et au HTML produit par le véritable renderer. Les avis distinguent erreurs établies et points à instruire ; une absence de champ n’est pas, seule, la preuve d’une mauvaise extraction.

R1 = RUN-20260907T183136, R2 = RUN-20260908T154840 (UTC+4). « Pas de trace » signifie absence de nouvel appel source_facts tracé dans ce run, et non échec ni absence de qualification déterministe. Les appels généraux cyberattaque_semantic ont une télémétrie séparée. Les 73 fiches R2 se trouvent dans [run2_evidence.json](run2_evidence.json), avec toutes leurs preuves par Item_ID ; [run1_evidence.json](run1_evidence.json) conserve l’état R1. Les données canoniques et le code métier n’ont pas été modifiés.

Les champs affichés sans badge restent identifiés `unknown` dans ce rapport. Les catégories masquées par le renderer sont explicitement listées. Les citations complètes et statuts par valeur se trouvent dans les JSON de preuve, pour éviter de surcharger chaque fiche.

| Incident | Priorité | Secteur R2 | Menace R2 | Territoire R2 |
|---|---|---|---|---|
| [Association des Maires de France](#inc-dd17dc78c96c) | P1 | Association / Syndicat | Fuite de données | France métropolitaine |
| [Medikwestindies](#inc-5d2d1691fc39) | P1 | Inconnu | Fuite de données | France métropolitaine |
| [SAD'S Interim](#inc-61993d19e8e2) | P1 | Services aux entreprises | Ransomware | France métropolitaine |
| [BumFot](#inc-8a100d3c8d40) | P2 | Numérique / Technologie | Fuite de données | France métropolitaine |
| [CC Yvetot Normandie](#inc-995c9f7252c1) | P1 | Inconnu | Fuite de données | Inconnu |
| [Jinko](#inc-a3d0a851e662) | P1 | Santé | Fuite de données | France métropolitaine |
| [Service national universel](#inc-ee0e8f96c169) | P1 | Inconnu | Intrusion | France métropolitaine |
| [Snexi](#inc-ce20778a3019) | P1 | Construction / BTP | Intrusion | France métropolitaine |
| [Aveyron](#inc-eec788c594ca) | P1 | Inconnu | Fuite de données | Inconnu |
| [Footsider](#inc-0042aa05b202) | P1 | Sport | Ransomware | France métropolitaine |
| [Les Curistes](#inc-d2432b2095fd) | P1 | Inconnu | Fuite de données | France métropolitaine |
| [OnRecrute.enAveyron.fr](#inc-a11ba9a22689) | P1 | Administration / Collectivité | Fuite de données | France métropolitaine |
| [SPA du Pays de Montbéliard](#inc-c0c26c209432) | P2 | Inconnu | Intrusion | Inconnu |
| [Jouvet SAS](#inc-f87083f98ea4) | P1 | Construction / BTP | Ransomware | France métropolitaine |
| [La Maison Pour Tous](#inc-c59598db9453) | P2 | Construction / BTP | Fuite de données | France métropolitaine |
| [PassPass](#inc-36a1cf778488) | P1 | Transport / Logistique | Intrusion | France métropolitaine |
| [Répar'Store](#inc-dc0bcfd579b8) | P1 | Inconnu | Fuite de données | France métropolitaine |
| [Répar’stores](#inc-b44c794ab35b) | P1 | Construction / BTP | Fuite de données | France métropolitaine |
| [YouFid](#inc-44385edb45c1) | P2 | Services aux entreprises | Fuite de données | France métropolitaine |
| [Accent Rouge](#inc-3ac6333a7a42) | P2 | Inconnu | Fuite de données | France métropolitaine |
| [Association des maires de France](#inc-2c5ceae9e3ac) | P1 | Association / Syndicat | Intrusion | France métropolitaine |
| [Clinique de Vontes](#inc-2c5cd2459f83) | P1 | Santé | Fuite de données | France métropolitaine |
| [Clinique de Vontes](#inc-45561e350283) | P1 | Santé | Fuite de données | France métropolitaine |
| [Collège Saint-Michel](#inc-f8485fb8b618) | P2 | Éducation / Formation | Fuite de données | France métropolitaine |
| [Préférence Formations](#inc-3e1b5fccaedf) | P2 | Éducation / Formation | Fuite de données | France métropolitaine |
| [Storia Mundi](#inc-2690c398c621) | P2 | Culture / Médias / Loisirs | Fuite de données | France métropolitaine |
| [BCTI](#inc-83ba7d2dcbf4) | P2 | Construction / BTP | Fuite de données | France métropolitaine |
| [Chambre de Métiers et de l’Artisanat d’Occitanie](#inc-b7dbf665e661) | P1 | Administration / Collectivité | Fuite de données | France métropolitaine |
| [Charbonneaux-Brabant](#inc-52ed884732bc) | P2 | Industrie / Manufacture | Fuite de données | France métropolitaine |
| [CMA Occitanie](#inc-619638da1c52) | P1 | Administration / Collectivité | Fuite de données | Inconnu |
| [ColisExpat](#inc-47cd44fa27b9) | P1 | Transport / Logistique | Intrusion | France métropolitaine |
| [Delicity](#inc-693abeb9bf8a) | P1 | Numérique / Technologie | Fuite de données | France métropolitaine |
| [Reso](#inc-e39201703225) | P2 | Commerce / Distribution | Fuite de données | France métropolitaine |
| [Tisséo](#inc-b56c65c3fdac) | P2 | Inconnu | Fuite de données | France métropolitaine |
| [ZeroGaspi](#inc-f8cddc2dd3b7) | P2 | Commerce / Distribution | Fuite de données | France métropolitaine |
| [Dropbox](#inc-6bd2de3819f9) | P2 | Numérique / Technologie | Incident tiers | Inconnu |
| [FNIM](#inc-64fe6b5ddb80) | P2 | Association / Syndicat | Fuite de données | France métropolitaine |
| [Géofoncier](#inc-c4996b1885d9) | P1 | Inconnu | Intrusion | France métropolitaine |
| [La Boutique du Volet](#inc-b18279aa1f95) | P2 | Commerce / Distribution | Fuite de données | France métropolitaine |
| [LiveTrail](#inc-cfb60e563eb4) | P1 | Numérique / Technologie | Intrusion | France métropolitaine |
| [Micromania](#inc-ce9040dc18ab) | P1 | Commerce / Distribution | Fuite de données | France métropolitaine |
| [Ministère de la Transition écologique](#inc-15a9f3ac6ac8) | P2 | Administration / Collectivité | Intrusion | France métropolitaine |
| [Shipup](#inc-90a8d0197e17) | P1 | Numérique / Technologie | Intrusion | France métropolitaine |
| [Stade Montois Omnisports](#inc-582e355e2705) | P2 | Sport | Intrusion | Inconnu |
| [Ville de Libercourt](#inc-df5c519783e8) | P1 | Administration / Collectivité | Ransomware | France métropolitaine |
| [Bio en Hauts-de-France](#inc-72fe2288a677) | P2 | Agriculture / Agroalimentaire | Fuite de données | France métropolitaine |
| [Herbiolys](#inc-b0e6bde8801f) | P2 | Industrie / Manufacture | Fuite de données | France métropolitaine |
| [La financière d’Orion](#inc-c64e07b15b3f) | P2 | Finance / Assurance | Fuite de données | France métropolitaine |
| [LebonSiege](#inc-26e2a421ad48) | P2 | Inconnu | Fuite de données | France métropolitaine |
| [Timetonic](#inc-d4ec64dbba06) | P2 | Numérique / Technologie | Fuite de données | France métropolitaine |
| [Carte De Pêche](#inc-c25397468c49) | P2 | Association / Syndicat | Fuite de données | France métropolitaine |
| [CGT Éduc’Action](#inc-82f1b88b7cc2) | Observation | Association / Syndicat | Intrusion | France métropolitaine |
| [Courir](#inc-cfaaec3e334a) | P2 | Commerce / Distribution | Intrusion | France métropolitaine |
| [FFTir](#inc-d63cee9e9005) | P1 | Sport | Fuite de données | France métropolitaine |
| [SDIS de la Moselle](#inc-4a2f32292a93) | P2 | Administration / Collectivité | Fuite de données | France métropolitaine |
| [SDIS de la Somme](#inc-fc866dcd1981) | Observation | Administration / Collectivité | Intrusion | France métropolitaine |
| [SDIS de l’Essonne](#inc-bd3012e03337) | Observation | Administration / Collectivité | Intrusion | France métropolitaine |
| [SDIS des Bouches-du-Rhône](#inc-8b71255fd2c5) | P2 | Administration / Collectivité | Fuite de données | France métropolitaine |
| [SDIS des Vosges](#inc-7ea20e0eebb7) | P2 | Administration / Collectivité | Fuite de données | France métropolitaine |
| [SDIS du Bas-Rhin](#inc-c6401641511b) | P2 | Administration / Collectivité | Fuite de données | France métropolitaine |
| [SDIS du Gard](#inc-d910ad541b6b) | P2 | Administration / Collectivité | Intrusion | France métropolitaine |
| [Easypara](#inc-d9a0c6dbd358) | P2 | Commerce / Distribution | Fuite de données | France métropolitaine |
| [La Maison Des Travaux](#inc-eb3ac8cb9892) | P2 | Commerce / Distribution | Ransomware | France métropolitaine |
| [La Ville de Tarnos](#inc-39643434bf76) | P2 | Administration / Collectivité | Ransomware | France métropolitaine |
| [LCommerce](#inc-92b98e38166e) | P2 | Commerce / Distribution | Fuite de données | France métropolitaine |
| [Marie Blachère](#inc-3c5b9e546782) | P2 | Commerce / Distribution | Fuite de données | France métropolitaine |
| [Zéro Logement Vacant](#inc-68bce0c36286) | P1 | Administration / Collectivité | Fuite de données | France métropolitaine |
| [Actis Location](#inc-195f06b69c3a) | P1 | Services aux entreprises | Fuite de données | France métropolitaine |
| [Frères Toque](#inc-70b5b8b5751d) | P2 | Hébergement / Tourisme / Restauration | Fuite de données | France métropolitaine |
| [Lingor](#inc-a3c6a92f895d) | P2 | Finance / Assurance | Ransomware | France métropolitaine |
| [Minea](#inc-6816c47ec89b) | P2 | Numérique / Technologie | Fuite de données | France métropolitaine |
| [Qare](#inc-e39645df5e4e) | P2 | Santé | Intrusion | France métropolitaine |
| [Ultra Premium Direct](#inc-f6e4fedc0fe9) | P2 | Agriculture / Agroalimentaire | Fuite de données | France métropolitaine |

<a id="inc-dd17dc78c96c"></a>
## Association des Maires de France — INC-DD17DC78C96C

**P1 — Doublon probable de la fiche AMF du 4 septembre : même organisation, notification BLF confirmée, décisions LLM SAME/DIFFERENT contradictoires et refusées. Secteur Association correct. Résumé et acteur absents ; statut de menace unknown malgré le statut BLF confirmed. La catégorie Fonction disparaît au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | Non présent | — | — | — | — |
| R2 | 2026-09-08 | Association / Syndicat / referenced | Fuite de données / unknown | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R2, secteur : BONJOURLAFUITE : referenced / REFERENCE_EXACT → Association / Syndicat.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-7597af39837701fa / ITM-ea7abde0b5a364e2` (Bio en Hauts-de-France / Association des Maires de France) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-af552eefe974f150 / ITM-ea7abde0b5a364e2` (Association des maires de France / Association des Maires de France) : VALIDATION_REJECTED, organisation SAME, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-b748ef8a5951e965 / ITM-ea7abde0b5a364e2` (Bio en Hauts-de-France / Association des Maires de France) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-fef84eaa6ff9af51 / ITM-ea7abde0b5a364e2` (Association des maires de France / Association des Maires de France) : VALIDATION_REJECTED, organisation SAME, incident SAME, confiance 0.6.

**Qualifications du volet R2**

Résumé : absent

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : aucun élément publié.

Types de données : noms et prénoms [unknown]; Genre [unknown]; Fonction [unknown]; adresses e-mail [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : Fonction.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-ea7abde0b5a364e2` — BONJOURLAFUITE — [Association des Maires de France](https://bonjourlafuite.eu.org/img/amf.png).

<a id="inc-5d2d1691fc39"></a>
## Medikwestindies — INC-5D2D1691FC39

**P1 — France métropolitaine est injustifié : le contexte décrit un site pour étudiants en médecine de Guadeloupe. Secteur à instruire selon l'activité du site, sans déduire Santé des seules données. Capture datée du 3 juin 2017 : signalement récent d'une revendication ancienne, à rendre explicite. Acteur générique l'auteur au lieu d'ANKA Team ; résumé rejeté, impact hypothétique marqué confirmed. Conserver 89 180 enregistrements revendiqués et la nuance mots de passe hachés.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | Non présent | — | — | — | — |
| R2 | 2026-09-08 | Inconnu / unknown | Fuite de données / unknown | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R2, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 2 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-21712d3c95aeb085, index 0 : accepté(s) impact ; rejet(s) activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; summary=EMPTY_OR_REJECTED_BY_VALIDATOR; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=NO_VALID_ACTIVITY_PAIR; fine_location=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-21712d3c95aeb085, index 1 : accepté(s) aucun ; rejet(s) vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR; file_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_datasets=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; data_volumes=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_systems=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, reprise `ITM-21712d3c95aeb085` : SEMANTIC_MISS, champs activity_description, activity_sector_match, affected_counts, affected_datasets, attack_flow, discovered_date, initial_access, summary, threat_candidate, tentatives différées 0.

**Qualifications du volet R2**

Résumé : absent

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Risque accru de phishing et usurpation d'identité en raison de la combinaison d'informations personnelles. | confirmed | FRENCHBREACHES |
| threat_actor | l'auteur | claimed | FRENCHBREACHES |

Volumes : 89 180 enregistrements [claimed].

Types de données : adresses e-mail [claimed]; numéros de téléphone [claimed]; mots de passe [claimed]; noms et prénoms [unknown]; identifiants [unknown]; données personnelles [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 3 entrée(s).

Catégories perdues au rendu : données personnelles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-21712d3c95aeb085` — FRENCHBREACHES — [Medikwestindies](https://frenchbreaches.com/alertes/medikwestindies-mtsio3ufjvj81y6m5ai).

<a id="inc-61993d19e8e2"></a>
## SAD'S Interim — INC-61993D19E8E2

**P1 — Fusion CYBERATTAQUE_ORG/RANSOMWARE_LIVE cohérente ; proposition aberrante de fusion avec Snexi bloquée. Secteur Services aux entreprises et France plausibles. Erreur certaine dans le détail : 5,79 To concerne Berlin, pas SAD’S Interim. Rhysida est présent sans statut revendiqué ; risque de fraude affiché confirmed. Contrats disparaît au rendu ; pas de vecteur ni volume propre à la victime suffisamment établi.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | Non présent | — | — | — | — |
| R2 | 2026-09-08 | Services aux entreprises / reported | Ransomware / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R2, secteur : RANSOMWARE_LIVE : reported / SOURCE_SECTOR_RAW → Services aux entreprises ; CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 2 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-ec4d0cdfab6fa8df, index 9 : accepté(s) summary, impact ; rejet(s) activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=NO_VALID_ACTIVITY_PAIR; fine_location=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-ec4d0cdfab6fa8df, index 10 : accepté(s) aucun ; rejet(s) vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR; file_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_datasets=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; data_volumes=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_systems=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R2, dédup `ITM-ace9f988608c3eec / ITM-80fc2c0b03341130` (Snexi / SAD'S Interim) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-ace9f988608c3eec / ITM-ec4d0cdfab6fa8df` (Snexi / SAD’S Interim) : VALIDATION_REJECTED, organisation SAME, incident SAME, confiance 0.6.
- R2, reprise `ITM-ec4d0cdfab6fa8df` : SEMANTIC_MISS, champs activity_description, activity_sector_match, affected_counts, affected_datasets, attack_flow, initial_access, threat_candidate, tentatives différées 0.

**Qualifications du volet R2**

Résumé : SAD’S Interim victime d'une cyberattaque exposant données sensibles, revendiquée par le groupe Rhysida.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 5,79 To | claimed | CYBERATTAQUE_ORG |
| discovered_date | 2026-09-08 | unknown | RANSOMWARE_LIVE |
| impact | Risque important d'usurpation d'identité et de fraude lié aux données sensibles exposées. | confirmed | CYBERATTAQUE_ORG |
| threat_actor | rhysida | unknown | RANSOMWARE_LIVE |

Volumes : aucun élément publié.

Types de données : données de santé [unknown]; pièces d'identité [confirmed]; données bancaires [claimed]; contrats [confirmed]; factures [claimed].

Systèmes : ERP [claimed].

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : contrats.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-ec4d0cdfab6fa8df` — CYBERATTAQUE_ORG — [SAD’S Interim : une cyberattaque expose passeports, NIR et données de santé](https://www.cyberattaque.org/sads-interim-une-cyberattaque-expose-passeports-nir-et-donnees-de-sante/).
- `ITM-80fc2c0b03341130` — RANSOMWARE_LIVE — [SAD'S Interim revendiqué par rhysida](http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion/archive.php?company=268).

<a id="inc-8a100d3c8d40"></a>
## BumFot — INC-8A100D3C8D40

**P2 — Secteur Numérique / Technologie résolu au premier run ; regroupement des deux sources conservé. Le résumé du second run perd la réserve revendiquée ; impact présent au premier run puis absent. Deux volumes de 1 300 utilisateurs persistent avec scopes distincts mais sans distinction visible. Plusieurs candidats sans rapport consomment la revue dédup.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-07 | Numérique / Technologie / inferred | Fuite de données / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-07 | Numérique / Technologie / inferred | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / SEMANTIC_ACTIVITY_MATCH → Numérique / Technologie ; CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 3 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-386e8b0cef884341, index 4 : accepté(s) summary, activity_description, activity_sector_match, threat_candidate ; rejet(s) impact=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; fine_location=EMPTY_OR_REJECTED_BY_VALIDATOR; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-386e8b0cef884341, index 5 : accepté(s) affected_systems, affected_counts, data_volumes ; rejet(s) file_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_datasets=EMPTY_OR_REJECTED_BY_VALIDATOR; vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-dcea59a6972cab15, index 13 : accepté(s) threat_candidate ; rejet(s) attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=NO_VALID_ACTIVITY_PAIR; impact=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R1, dédup `ITM-041e36c542f6c37f / ITM-386e8b0cef884341` (Frères Toque / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R1, dédup `ITM-041e36c542f6c37f / ITM-dcea59a6972cab15` (Frères Toque / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R1, dédup `ITM-776a3c8116ba0604 / ITM-dcea59a6972cab15` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.
- R1, dédup `ITM-853bff3331f5dba9 / ITM-386e8b0cef884341` (La financière d’Orion / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.75.
- R1, dédup `ITM-a96ac6cb5ff60c2b / ITM-386e8b0cef884341` (La Maison Pour Tous / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.65.
- R1, dédup `ITM-ec6ad7ad1bc83e4d / ITM-386e8b0cef884341` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.75.
- R1, dédup `ITM-ecf737579abef294 / ITM-386e8b0cef884341` (La Maison Des Travaux / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R1, dédup `ITM-ecf737579abef294 / ITM-dcea59a6972cab15` (La Maison Des Travaux / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R1, dédup `ITM-fad363a2093ab678 / ITM-dcea59a6972cab15` (La Maison Pour Tous / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.
- R1, reprise `ITM-386e8b0cef884341` : SEMANTIC_MISS, champs affected_datasets, attack_flow, discovered_date, impact, initial_access, tentatives différées 0.
- R1, reprise `ITM-dcea59a6972cab15` : SEMANTIC_MISS, champs activity_description, activity_sector_match, tentatives différées 0.
- R2, secteur : FRENCHBREACHES : inferred / SEMANTIC_ACTIVITY_MATCH → Numérique / Technologie ; CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 3 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-386e8b0cef884341, index 7 : accepté(s) aucun ; rejet(s) attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; impact=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-386e8b0cef884341, index 8 : accepté(s) aucun ; rejet(s) affected_datasets=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-dcea59a6972cab15, index 15 : accepté(s) aucun ; rejet(s) activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; activity_sector_match=NO_VALID_ACTIVITY_PAIR.
- R2, dédup `ITM-041e36c542f6c37f / ITM-386e8b0cef884341` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-041e36c542f6c37f / ITM-dcea59a6972cab15` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-776a3c8116ba0604 / ITM-dcea59a6972cab15` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.
- R2, dédup `ITM-853bff3331f5dba9 / ITM-386e8b0cef884341` (La financière d’Orion / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R2, dédup `ITM-a96ac6cb5ff60c2b / ITM-386e8b0cef884341` (La Maison Pour Tous / BumFot) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-ec6ad7ad1bc83e4d / ITM-386e8b0cef884341` (Frères Toque / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R2, dédup `ITM-ecf737579abef294 / ITM-386e8b0cef884341` (La Maison Des Travaux / BumFot) : UNKNOWN, organisation UNKNOWN, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-ecf737579abef294 / ITM-dcea59a6972cab15` (La Maison Des Travaux / BumFot) : UNKNOWN, organisation UNKNOWN, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-fad363a2093ab678 / ITM-dcea59a6972cab15` (La Maison Pour Tous / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.

**Qualifications du volet R2**

Résumé : BumFot a subi une cyberattaque exposant les données d'environ 1 300 utilisateurs.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 481 Ko | unknown | FRENCHBREACHES |

Volumes : 1 300 utilisateurs [unknown]; environ 1 300 utilisateurs [unknown].

Types de données : photographies [claimed]; mots de passe [unknown]; adresses e-mail [claimed]; numéros de téléphone [claimed]; noms et prénoms [unknown]; identifiants [unknown].

Systèmes : BumFot.fr [confirmed].

Périmètres : base utilisateurs [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-dcea59a6972cab15` — CYBERATTAQUE_ORG — [BumFot : une cyberattaque expose les données d’environ 1 300 utilisateurs](https://www.cyberattaque.org/bumfot-une-cyberattaque-expose-les-donnees-denviron-1-300-utilisateurs/).
- `ITM-386e8b0cef884341` — FRENCHBREACHES — [BumFot](https://frenchbreaches.com/alertes/bumfot-mtr6jurecstsgtv0ig5).

<a id="inc-995c9f7252c1"></a>
## CC Yvetot Normandie — INC-995C9F7252C1

**P1 — Secteur Administration / Collectivité disponible dans la réponse LLM mais rejeté sur le lien activité/victime. Seine-Maritime accepté dans Fine_Location sans propagation au territoire. Les 250 documents sont extraits en File_Count puis perdus dans Volume documenté. lazymean10 présent dans les claims, mais le scalaire extrait Il est rejeté et aucun acteur n'est affiché. Fuite étayée, mode d'accès justement non renseigné.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | Non présent | — | — | — | — |
| R2 | 2026-09-07 | Inconnu / unknown | Fuite de données / reported | Inconnu | 1 |

**Chaîne de qualification et déduplication**

- R2, secteur : CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 2 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-1673e221850aa327, index 11 : accepté(s) summary, attack_flow, impact, fine_location ; rejet(s) activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=NO_VALID_ACTIVITY_PAIR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-1673e221850aa327, index 12 : accepté(s) affected_datasets, file_counts ; rejet(s) vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; data_volumes=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_systems=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R2, dédup `ITM-3b3b9921859b5cef / ITM-1673e221850aa327` (Storia Mundi / CC Yvetot Normandie) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R2, reprise `ITM-1673e221850aa327` : SEMANTIC_MISS, champs activity_description, activity_sector_match, attack_date, initial_access, tentatives différées 0.

**Qualifications du volet R2**

Résumé : CC Yvetot Normandie a subi une fuite de près de 250 documents administratifs diffusés sur le darkweb.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | Seine-Maritime | unknown | CYBERATTAQUE_ORG |
| impact | Diffusion de documents administratifs internes, comprenant des détails sur les travaux de commissions. | unknown | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : informations administratives [unknown]; documents internes [confirmed]; métadonnées techniques [claimed].

Systèmes : aucun élément publié.

Périmètres : archive [confirmed]; documents de travail internes [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : informations administratives, documents internes, métadonnées techniques.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-1673e221850aa327` — CYBERATTAQUE_ORG — [CC Yvetot Normandie : près de 250 documents administratifs en fuite](https://www.cyberattaque.org/cc-yvetot-normandie-les-documents-administratifs-en-fuite-apres-une-cyberattaque/).

<a id="inc-a3d0a851e662"></a>
## Jinko — INC-A3D0A851E662

**P1 — Secteur Santé et fusion des sources cohérents. Vecteur identifiants compromis non étayé : sa preuve dit expressément que plusieurs causes restent possibles. Résumé trop affirmatif pour certains éléments revendiqués. Trois volumes de comptes/personnes/fichiers à distinguer ; 5 appels de qualification au second run, reliquat encore en attente.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-07 | Santé / inferred | Fuite de données / reported | France métropolitaine | 2 |
| R2 | 2026-09-07 | Santé / inferred | Fuite de données / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / SEMANTIC_ACTIVITY_MATCH → Santé ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 3 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-73d8dbdd9d0635b0, index 0 : accepté(s) summary ; rejet(s) impact=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_actor=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; fine_location=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=NO_VALID_ACTIVITY_PAIR; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-73d8dbdd9d0635b0, index 1 : accepté(s) affected_datasets, data_volumes, file_counts ; rejet(s) affected_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_systems=EMPTY_OR_REJECTED_BY_VALIDATOR; vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-46f2bb70da9e82d5, index 12 : accepté(s) aucun ; rejet(s) impact=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R1, dédup `ITM-050f3ab72fc2e7e3 / ITM-73d8dbdd9d0635b0` (Lingor / Jinko) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.
- R1, dédup `ITM-ed7e34492c1a1059 / ITM-46f2bb70da9e82d5` (Lingor / Jinko) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.
- R1, reprise `ITM-73d8dbdd9d0635b0` : SEMANTIC_MISS, champs activity_description, activity_sector_match, affected_counts, attack_date, attack_flow, discovered_date, impact, initial_access, threat_actor, tentatives différées 0.
- R1, reprise `ITM-46f2bb70da9e82d5` : SEMANTIC_MISS, champs threat_candidate, tentatives différées 0.
- R2, secteur : CYBERATTAQUE_ORG : inferred / SEMANTIC_ACTIVITY_MATCH → Santé ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 5 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-73d8dbdd9d0635b0, index 4 : accepté(s) attack_flow, impact ; rejet(s) activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; activity_sector_match=NO_VALID_ACTIVITY_PAIR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_actor=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-73d8dbdd9d0635b0, index 5 : accepté(s) aucun ; rejet(s) affected_counts=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-46f2bb70da9e82d5, index 13 : accepté(s) summary, attack_flow, impact, activity_description, activity_sector_match ; rejet(s) evolution=EMPTY_OR_REJECTED_BY_VALIDATOR; fine_location=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-46f2bb70da9e82d5, index 14 : accepté(s) affected_datasets ; rejet(s) vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR; file_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; data_volumes=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_systems=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-46f2bb70da9e82d5, index 21 : accepté(s) aucun ; rejet(s) threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R2, dédup `ITM-050f3ab72fc2e7e3 / ITM-73d8dbdd9d0635b0` (Lingor / Jinko) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-ed7e34492c1a1059 / ITM-46f2bb70da9e82d5` (Lingor / Jinko) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.
- R2, reprise `ITM-46f2bb70da9e82d5` : SEMANTIC_MISS, champs affected_counts, attack_date, data_volumes, discovered_date, initial_access, threat_candidate, tentatives différées 0.

**Qualifications du volet R2**

Résumé : Jinko subit une fuite de données de santé affectant plus de 3 500 personnes.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 3,7 Go | claimed | FRENCHBREACHES |
| impact | exposition de données médicales et personnelles sensibles | claimed | FRENCHBREACHES |
| initial_access | compromised_credentials | unknown | CYBERATTAQUE_ORG |
| threat_actor | DaOnlySpark | unknown | CYBERATTAQUE_ORG |

Volumes : 3 552 comptes [unknown]; 3 500 personnes [unknown]; 2 626 fichiers [unknown].

Types de données : données de santé [confirmed]; adresses e-mail [unknown]; numéros de téléphone [unknown]; noms et prénoms [unknown]; dates de naissance [unknown]; informations de séjour [unknown]; identifiants [unknown]; adresses postales [unknown]; données personnelles [unknown].

Systèmes : aucun élément publié.

Périmètres : base de données de patients [confirmed]; base clients [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 3 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : informations de séjour, données personnelles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-46f2bb70da9e82d5` — CYBERATTAQUE_ORG — [Jinko : une cyberattaque expose les données de santé de plus de 3 500 personnes](https://www.cyberattaque.org/jinko-une-cyberattaque-expose-les-donnees-de-sante-de-plus-de-3-500-personnes/).
- `ITM-73d8dbdd9d0635b0` — FRENCHBREACHES — [Jinko](https://frenchbreaches.com/alertes/jinko-mtr8ebuvqi0us4ljpbi).

<a id="inc-ee0e8f96c169"></a>
## Service national universel — INC-EE0E8F96C169

**P1 — Fuite revendiquée de 2026 classée Intrusion/confirmed. Import des 150 000 personnes, dates de naissance et adresses postales du précédent incident de 2023 ; mots de passe ajoutés malgré leur mention dans un démenti. Secteur public non résolu. Vecteur IDOR conservé comme revendiqué, mais vulnérabilité IDOR structurée rejetée. Résumé supprime le conditionnel.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | Non présent | — | — | — | — |
| R2 | 2026-09-07 | Inconnu / unknown | Intrusion / confirmed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R2, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 2 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-eafcb7b7a88e0222, index 2 : accepté(s) summary ; rejet(s) activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; impact=EMPTY_OR_REJECTED_BY_VALIDATOR; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=NO_VALID_ACTIVITY_PAIR; fine_location=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-eafcb7b7a88e0222, index 3 : accepté(s) affected_datasets, affected_counts ; rejet(s) vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR; file_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; data_volumes=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_systems=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, reprise `ITM-eafcb7b7a88e0222` : SEMANTIC_MISS, champs activity_description, activity_sector_match, attack_date, attack_flow, discovered_date, impact, initial_access, threat_candidate, vulnerabilities, tentatives différées 0.

**Qualifications du volet R2**

Résumé : Cyberattaque contre le Service national universel, environ 275 000 comptes compromis.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| initial_access | vulnerability_exploitation | claimed | FRENCHBREACHES |
| threat_actor | LunarisSec | claimed | FRENCHBREACHES |

Volumes : 5 000 comptes [reported]; 270 000 comptes [reported]; 150 000 personnes [unknown].

Types de données : adresses e-mail [unknown]; numéros de téléphone [unknown]; noms et prénoms [unknown]; identifiants [unknown]; adresses postales [unknown]; dates de naissance [unknown]; mots de passe [unknown].

Systèmes : aucun élément publié.

Périmètres : plateforme SNU [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-eafcb7b7a88e0222` — FRENCHBREACHES — [Service national universel (SNU)](https://frenchbreaches.com/alertes/service-national-universel-snu-mtrfy9tvk9n0jcgh2yk).

<a id="inc-ce20778a3019"></a>
## Snexi — INC-CE20778A3019

**P1 — Menace passée de Fuite de données à Intrusion au premier run malgré la violation de données personnelles explicitement enregistrée. Secteur Construction / BTP et France cohérents. Date du 2 septembre disponible dans le résumé mais non portée en date d'attaque structurée. Fausse fusion avec SAD’S Interim proposée puis bloquée au second run.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-07 | Construction / BTP / inferred | Intrusion / confirmed | France métropolitaine | 1 |
| R2 | 2026-09-07 | Construction / BTP / inferred | Intrusion / confirmed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / ACTIVITY_RULE → Construction / BTP.
- R1, extraction : 2 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-ace9f988608c3eec, index 2 : accepté(s) summary, impact, activity_description ; rejet(s) threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; fine_location=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=SECTOR_CONTRADICTS_ACTIVITY_EVIDENCE; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-ace9f988608c3eec, index 3 : accepté(s) affected_datasets ; rejet(s) affected_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_systems=EMPTY_OR_REJECTED_BY_VALIDATOR; file_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; data_volumes=EMPTY_OR_REJECTED_BY_VALIDATOR; vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R1, reprise `ITM-ace9f988608c3eec` : SEMANTIC_MISS, champs activity_sector_match, attack_date, attack_flow, initial_access, tentatives différées 0.
- R2, secteur : FRENCHBREACHES : inferred / ACTIVITY_RULE → Construction / BTP.
- R2, extraction : 2 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-ace9f988608c3eec, index 6 : accepté(s) aucun ; rejet(s) activity_description=CONFIDENCE_REJECTED; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=CONFIDENCE_REJECTED.
  - ITM-ace9f988608c3eec, index 16 : accepté(s) activity_description ; rejet(s) activity_sector_match=SECTOR_CONTRADICTS_ACTIVITY_EVIDENCE.
- R2, dédup `ITM-ace9f988608c3eec / ITM-80fc2c0b03341130` (Snexi / SAD'S Interim) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-ace9f988608c3eec / ITM-ec4d0cdfab6fa8df` (Snexi / SAD’S Interim) : VALIDATION_REJECTED, organisation SAME, incident SAME, confiance 0.6.

**Qualifications du volet R2**

Résumé : SNEXI a subi une cyberattaque le 2 septembre 2026 entraînant une violation de données personnelles.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Violation des données personnelles de plusieurs propriétaires et locataires. | confirmed | FRENCHBREACHES |

Volumes : aucun élément publié.

Types de données : adresses e-mail [unknown]; numéros de téléphone [unknown]; adresses postales [unknown]; noms et prénoms [unknown]; données personnelles [unknown].

Systèmes : aucun élément publié.

Périmètres : données personnelles de propriétaires et locataires [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 4 entrée(s).

Catégories perdues au rendu : données personnelles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-ace9f988608c3eec` — FRENCHBREACHES — [Snexi](https://frenchbreaches.com/alertes/snexi-mtndjyfm1p926jbh30z).

<a id="inc-eec788c594ca"></a>
## Aveyron — INC-EEC788C594CA

**P1 — Faux dédoublonnage : séparé d'OnRecrute après décision DIFFERENT persistée le 7 septembre, alors que les deux sources décrivent la même plateforme, ChimeraZ et les mêmes 23 381 lignes / 20 316 personnes / 465 Mo. Secteur et territoire deviennent inconnus sur ce fragment. Les CV perdent leur complément sectoriel et leur rapprochement avec l'autre fiche.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-06 | Inconnu / unknown | Fuite de données / reported | Inconnu | 1 |
| R2 | 2026-09-06 | Inconnu / unknown | Fuite de données / reported | Inconnu | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 1 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-495f418ca1fb8dad, index 17 : accepté(s) aucun ; rejet(s) initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=NO_VALID_ACTIVITY_PAIR; activity_description=ACTIVITY_VICTIM_BINDING_REJECTED.
- R1, dédup `ITM-495f418ca1fb8dad / ITM-7a872ed42e894347` (Aveyron / OnRecrute.enAveyron.fr) : DIFFERENT, organisation SAME, incident DIFFERENT, confiance 0.85.
- R1, reprise `ITM-495f418ca1fb8dad` : SEMANTIC_MISS, champs activity_description, activity_sector_match, threat_candidate, tentatives différées 0.
- R2, secteur : CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, reprise `ITM-495f418ca1fb8dad` : SEMANTIC_MISS, champs activity_description, activity_sector_match, threat_candidate, tentatives différées 0.

**Qualifications du volet R2**

Résumé : Fuite de données de 23 381 enregistrements d'utilisateurs et 1 500 CV sur une plateforme d'emploi en Aveyron.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 465 Mo | unknown | CYBERATTAQUE_ORG |
| impact | exposition de données personnelles détaillées de candidats à l'emploi | unknown | CYBERATTAQUE_ORG |
| threat_actor | ChimeraZ | unknown | CYBERATTAQUE_ORG |

Volumes : 23 381 enregistrements [claimed]; 20 316 personnes [unknown].

Types de données : noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; identifiants [unknown]; dates de naissance [unknown]; CV [claimed].

Systèmes : OnRecrute.EnAveyron.fr [confirmed].

Périmètres : base utilisateurs [confirmed]; CV [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : CV.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-495f418ca1fb8dad` — CYBERATTAQUE_ORG — [Aveyron : plus de 20 000 profils et 1 500 CV en fuite sur la plateforme emploi du Département](https://www.cyberattaque.org/aveyron-cyberattaque-emplois/).

<a id="inc-0042aa05b202"></a>
## Footsider — INC-0042AA05B202

**P1 — Ransomware injustifié par les preuves publiées : l'ancienne menace de l'item Cyberattaque domine une fuite documentée, même après extraction d'un threat_tentative Fuite de données. Secteur Sport résolu. Les 100 000 utilisateurs commerciaux historiques polluent Volume documenté ; chiffres précis et arrondis se répètent. Réserves sur les volumes et les mineurs à conserver.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-06 | Sport / inferred | Ransomware / reported | France métropolitaine | 2 |
| R2 | 2026-09-06 | Sport / inferred | Ransomware / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; FRENCHBREACHES : inferred / ACTIVITY_RULE → Sport.
- R1, extraction : 3 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-7ddc5f6739f7709d, index 6 : accepté(s) summary, threat_candidate ; rejet(s) impact=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_description=EVIDENCE_NOT_GROUNDED; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; fine_location=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=EVIDENCE_NOT_GROUNDED; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-7ddc5f6739f7709d, index 7 : accepté(s) affected_counts, data_volumes, file_counts ; rejet(s) affected_systems=EMPTY_OR_REJECTED_BY_VALIDATOR; affected_datasets=EMPTY_OR_REJECTED_BY_VALIDATOR; vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-5038ebd6674ce417, index 15 : accepté(s) attack_flow ; rejet(s) threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=NO_VALID_ACTIVITY_PAIR.
- R1, dédup `ITM-0867a5b8ab130b38 / ITM-7ddc5f6739f7709d` (FFTir / Footsider) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.
- R1, dédup `ITM-48e2bee9b75f6d4b / ITM-7ddc5f6739f7709d` (Géofoncier / Footsider) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.
- R1, dédup `ITM-ab8836dc2f58e58e / ITM-5038ebd6674ce417` (Géofoncier / Footsider) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.
- R1, reprise `ITM-7ddc5f6739f7709d` : SEMANTIC_MISS, champs activity_description, activity_sector_match, attack_flow, discovered_date, impact, initial_access, tentatives différées 0.
- R1, reprise `ITM-5038ebd6674ce417` : SEMANTIC_MISS, champs activity_description, activity_sector_match, threat_candidate, tentatives différées 0.
- R2, secteur : CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; FRENCHBREACHES : inferred / ACTIVITY_RULE → Sport.
- R2, extraction : 1 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-7ddc5f6739f7709d, index 17 : accepté(s) aucun ; rejet(s) activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; impact=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=CONFIDENCE_REJECTED; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, reprise `ITM-5038ebd6674ce417` : SEMANTIC_MISS, champs activity_description, activity_sector_match, threat_candidate, tentatives différées 0.

**Qualifications du volet R2**

Résumé : Footsider a subi une cyberattaque exposant les données de 153 000 comptes utilisateurs.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 2,89 Go | unknown | CYBERATTAQUE_ORG |
| impact | exposition de données personnelles sensibles | unknown | CYBERATTAQUE_ORG |
| threat_actor | DaOnlySpark | unknown | CYBERATTAQUE_ORG |

Volumes : 153 667 comptes [unknown]; 144 567 enregistrements [unknown]; 84 fichiers [unknown]; 3 dossiers [unknown]; 153 000 comptes [unknown]; 20 000 enregistrements [unknown]; 1,5 million de lignes [unknown]; 100 000 utilisateurs [unknown].

Types de données : photographies [unknown]; noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; dates de naissance [unknown]; identifiants [unknown].

Systèmes : aucun élément publié.

Périmètres : messages privés, contacts avec les clubs et opportunités de recrutement [reported]; profils de joueurs [confirmed]; messages privés [confirmed]; profils des clubs [confirmed]; données analytiques [confirmed]; identifiants techniques liés aux notifications [confirmed]; messages privés, contacts avec les clubs et opportunités de recrutement [reported].

Vulnérabilités : aucun élément publié.

Déroulé : 2 étape(s) ; chronologie : 5 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : SUMMARY_FACT_CONTRADICTION, THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-5038ebd6674ce417` — CYBERATTAQUE_ORG — [Footsider : une cyberattaque expose les données de 153 000 comptes](https://www.cyberattaque.org/footsider-cyberattaque/).
- `ITM-7ddc5f6739f7709d` — FRENCHBREACHES — [Footsider](https://frenchbreaches.com/alertes/footsider-mtpvjd93ygng6mx0ul).

<a id="inc-d2432b2095fd"></a>
## Les Curistes — INC-D2432B2095FD

**P1 — Secteur devient Inconnu au premier run par conflit Santé / Tourisme entre sources ; abstention défendable en attendant arbitrage d'activité. Proposition LLM Transport rejetée à juste titre au second run. Erreur de rôle certaine : ChimeraZ est affiché à la fois comme attaquant et tiers impliqué. Comptes/messages/personnes et arrondis doivent rester distincts.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-06 | Inconnu / unknown | Fuite de données / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-06 | Inconnu / unknown | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / ACTIVITY_RULE → Hébergement / Tourisme / Restauration ; CYBERATTAQUE_ORG : inferred / SEMANTIC_ACTIVITY_MATCH → Santé.
- R1, extraction : 3 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-5d215664429352e6, index 8 : accepté(s) summary, impact, threat_actor, activity_description ; rejet(s) threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; fine_location=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=SECTOR_CONTRADICTS_ACTIVITY_EVIDENCE; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-5d215664429352e6, index 9 : accepté(s) affected_datasets, affected_counts, data_volumes ; rejet(s) affected_systems=EMPTY_OR_REJECTED_BY_VALIDATOR; file_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-fc70490f5bdaa7b5, index 16 : accepté(s) activity_description, activity_sector_match, threat_candidate ; rejet(s) initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R1, reprise `ITM-5d215664429352e6` : SEMANTIC_MISS, champs activity_sector_match, attack_date, attack_flow, initial_access, tentatives différées 0.
- R2, secteur : FRENCHBREACHES : inferred / ACTIVITY_RULE → Hébergement / Tourisme / Restauration ; CYBERATTAQUE_ORG : inferred / SEMANTIC_ACTIVITY_MATCH → Santé.
- R2, extraction : 1 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-5d215664429352e6, index 18 : accepté(s) activity_description ; rejet(s) attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=SECTOR_CONTRADICTS_ACTIVITY_EVIDENCE.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données chez Les Curistes concernant plus de 86 000 personnes, avec des informations exposées tels que noms et messages privés.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 95 Mo | unknown | CYBERATTAQUE_ORG |
| impact | Exposition des messages et coordonnées de 86 073 personnes. | unknown | CYBERATTAQUE_ORG |
| third_party | ChimeraZ | unknown | CYBERATTAQUE_ORG |
| threat_actor | ChimeraZ | claimed | FRENCHBREACHES |

Volumes : 328 649 enregistrements [unknown]; 86 073 personnes [unknown]; 328 000 enregistrements [unknown]; 80 000 personnes [unknown].

Types de données : noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; informations de séjour [unknown]; identifiants [unknown]; données de santé [unknown]; adresses IP [unknown].

Systèmes : LesCuristes.fr [confirmed].

Périmètres : réservations [unknown]; base clients [confirmed]; messages envoyés par les utilisateurs [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 2 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : informations de séjour.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-fc70490f5bdaa7b5` — CYBERATTAQUE_ORG — [LesCuristes.fr : une cyberattaque expose les messages et coordonnées de 86 000 personnes](https://www.cyberattaque.org/lescuristes-fr-une-cyberattaque-expose-les-messages-et-coordonnees-de-86-000-personnes/).
- `ITM-5d215664429352e6` — FRENCHBREACHES — [Les Curistes](https://frenchbreaches.com/alertes/les-curistes-mtp0o5mfdnfk170tt2f).

<a id="inc-a11ba9a22689"></a>
## OnRecrute.enAveyron.fr — INC-A11BA9A22689

**P1 — Nouvelle identité issue du renommage Aveyron ; doublon certain avec INC-EEC788C594CA créé par la décision DIFFERENT. Secteur public et territoire France cohérents. Volumes revendiqués correctement distingués en lignes/personnes, mais près de 1 500 PDF ne figurent pas dans les volumes. Résumé et statut global trop affirmatifs par rapport aux réserves des faits.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-06 | Administration / Collectivité / inferred | Fuite de données / confirmed | France métropolitaine | 1 |
| R2 | 2026-09-06 | Administration / Collectivité / inferred | Fuite de données / confirmed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / ACTIVITY_RULE → Administration / Collectivité.
- R1, extraction : 2 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-7a872ed42e894347, index 10 : accepté(s) summary, threat_actor, fine_location, activity_description, activity_sector_match ; rejet(s) impact=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; discovered_date=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; evolution=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-7a872ed42e894347, index 11 : accepté(s) affected_systems, affected_datasets, data_volumes, file_counts ; rejet(s) affected_counts=EMPTY_OR_REJECTED_BY_VALIDATOR; vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R1, dédup `ITM-495f418ca1fb8dad / ITM-7a872ed42e894347` (Aveyron / OnRecrute.enAveyron.fr) : DIFFERENT, organisation SAME, incident DIFFERENT, confiance 0.85.
- R1, dédup `ITM-7069a14f66132856 / ITM-7a872ed42e894347` (Jouvet SAS / OnRecrute.enAveyron.fr) : UNKNOWN, organisation UNKNOWN, incident UNKNOWN, confiance 0.5.
- R1, dédup `ITM-9278dd653363ee24 / ITM-7a872ed42e894347` (Jouvet SAS / OnRecrute.enAveyron.fr) : VALIDATION_REJECTED, organisation SAME, incident DIFFERENT, confiance 0.75.
- R1, reprise `ITM-7a872ed42e894347` : SEMANTIC_MISS, champs affected_counts, attack_date, attack_flow, impact, initial_access, threat_candidate, vulnerabilities, tentatives différées 0.
- R2, secteur : FRENCHBREACHES : inferred / ACTIVITY_RULE → Administration / Collectivité.
- R2, extraction : 2 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-7a872ed42e894347, index 19 : accepté(s) aucun ; rejet(s) impact=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_date=EMPTY_OR_REJECTED_BY_VALIDATOR; threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR.
  - ITM-7a872ed42e894347, index 20 : accepté(s) affected_counts ; rejet(s) vulnerabilities=EMPTY_OR_REJECTED_BY_VALIDATOR.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données ayant exposé plus de 20 000 personnes et près de 1 500 documents sur OnRecrute.enAveyron.fr.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 465 Mo | claimed | FRENCHBREACHES |
| fine_location | Aveyron | confirmed | FRENCHBREACHES |
| threat_actor | ChimeraZ | claimed | FRENCHBREACHES |

Volumes : 23 381 enregistrements [claimed]; 20 316 personnes [claimed].

Types de données : noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; identifiants [unknown]; dates de naissance [unknown]; données personnelles [unknown].

Systèmes : OnRecrute.enAveyron.fr [confirmed].

Périmètres : base de données des candidatures et profils [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : données personnelles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-7a872ed42e894347` — FRENCHBREACHES — [Aveyron](https://frenchbreaches.com/alertes/aveyron-mtp0hyfwss6ietkec1q).

<a id="inc-c0c26c209432"></a>
## SPA du Pays de Montbéliard — INC-C0C26C209432

**P2 — Intrusion/indisponibilité cohérente. Secteur Association / Syndicat à instruire ; activité non résolue et en attente. Allondans/Doubs est extrait mais territoire Inconnu. Évolution Le site semble de nouveau accessible marquée confirmed avec une preuve décrivant seulement le travail de rétablissement : preuve inadéquate.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-06 | Inconnu / unknown | Intrusion / confirmed | Inconnu | 1 |
| R2 | 2026-09-06 | Inconnu / unknown | Intrusion / confirmed | Inconnu | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 1 appel(s) source_facts tracé(s), tous success au niveau appel ; les rejets de champs restent distincts.
  - ITM-7a623d24b9173dd1, index 14 : accepté(s) aucun ; rejet(s) threat_candidate=EMPTY_OR_REJECTED_BY_VALIDATOR; attack_flow=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_description=ACTIVITY_VICTIM_BINDING_REJECTED; initial_access=EMPTY_OR_REJECTED_BY_VALIDATOR; activity_sector_match=CONFIDENCE_REJECTED.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R1, reprise `ITM-7a623d24b9173dd1` : SEMANTIC_MISS, champs activity_description, activity_sector_match, tentatives différées 0.
- R2, secteur : CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, reprise `ITM-7a623d24b9173dd1` : SEMANTIC_MISS, champs activity_description, activity_sector_match, tentatives différées 0.

**Qualifications du volet R2**

Résumé : La SPA du Pays de Montbéliard a subi une cyberattaque rendant son site Internet inaccessible.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| evolution | Le site semble de nouveau accessible. | confirmed | CYBERATTAQUE_ORG |
| fine_location | Allondans, Doubs | confirmed | CYBERATTAQUE_ORG |
| impact | SPA du Pays de Montbéliard : une cyberattaque met son site hors ligne | confirmed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : identifiants [unknown].

Systèmes : WordPress [unknown]; spa-montbeliard.fr [reported].

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-7a623d24b9173dd1` — CYBERATTAQUE_ORG — [SPA du Pays de Montbéliard : une cyberattaque met son site hors ligne](https://www.cyberattaque.org/spa-du-pays-de-montbeliard-une-cyberattaque-met-son-site-hors-ligne/).

<a id="inc-f87083f98ea4"></a>
## Jouvet SAS — INC-F87083F98EA4

**P1 — Ransomware Qilin, Construction / BTP et France cohérents. Les 157 victimes affichées correspondent au bilan mensuel de Qilin, pas à Jouvet SAS. Acteur sans statut dans le détail ; impact site de fuite peu informatif. Les comparaisons dédup avec OnRecrute sont sans pertinence ; aucune fusion appliquée.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-05 | Construction / BTP / inferred | Ransomware / reported | France métropolitaine | 2 |
| R2 | 2026-09-05 | Construction / BTP / inferred | Ransomware / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : RANSOMWARE_LIVE : reported / SOURCE_SECTOR_RAW → Industrie / Manufacture ; CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Construction / BTP.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup `ITM-7069a14f66132856 / ITM-7a872ed42e894347` (Jouvet SAS / OnRecrute.enAveyron.fr) : UNKNOWN, organisation UNKNOWN, incident UNKNOWN, confiance 0.5.
- R1, dédup `ITM-9278dd653363ee24 / ITM-7a872ed42e894347` (Jouvet SAS / OnRecrute.enAveyron.fr) : VALIDATION_REJECTED, organisation SAME, incident DIFFERENT, confiance 0.75.
- R2, secteur : RANSOMWARE_LIVE : reported / SOURCE_SECTOR_RAW → Industrie / Manufacture ; CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Construction / BTP.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Le groupe de ransomware Qilin revendique une cyberattaque contre Jouvet SAS.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| discovered_date | 2026-09-05 | unknown | RANSOMWARE_LIVE |
| fine_location | Allonnes, Sarthe | claimed | CYBERATTAQUE_ORG |
| impact | site de fuite | claimed | CYBERATTAQUE_ORG |
| threat_actor | qilin | unknown | RANSOMWARE_LIVE |

Volumes : 157 victimes [claimed].

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 3 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : DATA_TYPES_EMPTY_WITH_PERSONAL_DATA_EVIDENCE.

**Sources de cette fiche**

- `ITM-9278dd653363ee24` — CYBERATTAQUE_ORG — [Jouvet SAS : Qilin revendique une cyberattaque contre l’entreprise sarthoise](https://www.cyberattaque.org/jouvet-sas-qilin-revendique-une-cyberattaque-contre-lentreprise-sarthoise/).
- `ITM-7069a14f66132856` — RANSOMWARE_LIVE — [Jouvet SAS revendiqué par qilin](http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=ee0464c8-913c-4fec-bf54-04737c76b065).

<a id="inc-c59598db9453"></a>
## La Maison Pour Tous — INC-C59598DB9453

**P2 — Fuite revendiquée et localisation cohérentes. Résumé annonce 8 000 locataires mais aucun volume structuré. Construction / BTP mérite vérification fine pour un bailleur ; pas de reclassement certain à partir des seules preuves disponibles. Détail pauvre en statut/source visible.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-05 | Construction / BTP / inferred | Fuite de données / claimed | France métropolitaine | 2 |
| R2 | 2026-09-05 | Construction / BTP / inferred | Fuite de données / claimed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Construction / BTP ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup `ITM-a96ac6cb5ff60c2b / ITM-386e8b0cef884341` (La Maison Pour Tous / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.65.
- R1, dédup `ITM-fad363a2093ab678 / ITM-dcea59a6972cab15` (La Maison Pour Tous / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.
- R2, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Construction / BTP ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-a96ac6cb5ff60c2b / ITM-386e8b0cef884341` (La Maison Pour Tous / BumFot) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-fad363a2093ab678 / ITM-dcea59a6972cab15` (La Maison Pour Tous / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.

**Qualifications du volet R2**

Résumé : Fuite de données de La Maison Pour Tous avec les noms de 8 000 locataires diffusés par le hacker ChimeraZ.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 275 Ko | unknown | CYBERATTAQUE_ORG |
| impact | Révélation des noms de locataires associés à La Maison Pour Tous. | claimed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : identifiants [unknown]; noms [claimed].

Systèmes : aucun élément publié.

Périmètres : fichier des locataires [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-a96ac6cb5ff60c2b` — CYBERATTAQUE_ORG — [La Maison Pour Tous : les noms de 8 000 locataires diffusés dans une fuite](https://www.cyberattaque.org/la-maison-pour-tous-les-noms-de-8-000-locataires-diffuses-cyberattaque/).
- `ITM-fad363a2093ab678` — FRENCHBREACHES — [La Maison Pour Tous](https://frenchbreaches.com/alertes/la-maison-pour-tous-mtokh76jop9gf5sg6qb).

<a id="inc-36a1cf778488"></a>
## PassPass — INC-36A1CF778488

**P1 — Menace rétrogradée en Intrusion malgré les preuves d'une base publiée de 92 178 lignes / 18 861 personnes. Secteur Transport correct et fusion explicitement enregistrée. Doublon de volume 18 861 personnes et catégories de commandes/montants supprimées au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-05 | Transport / Logistique / inferred | Intrusion / reported | France métropolitaine | 2 |
| R2 | 2026-09-05 | Transport / Logistique / inferred | Intrusion / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Transport / Logistique ; FRENCHBREACHES : inferred / ACTIVITY_RULE → Transport / Logistique.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Transport / Logistique ; FRENCHBREACHES : inferred / ACTIVITY_RULE → Transport / Logistique.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Pass Pass expose près de 19 000 usagers après une cyberattaque revendiquée par le hacker ChimeraZ.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 214 Mo | claimed | CYBERATTAQUE_ORG |
| threat_actor | ChimeraZ | claimed | FRENCHBREACHES |

Volumes : 92 178 enregistrements [claimed]; 18 861 personnes [claimed]; environ 18 861 personnes [unknown].

Types de données : informations de commandes [confirmed]; factures [claimed]; noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; facturation [unknown]; montants [unknown]; adresses postales [unknown].

Systèmes : aucun élément publié.

Périmètres : base clients [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 3 entrée(s).

Catégories perdues au rendu : informations de commandes, montants.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-31ca81b910b22756` — CYBERATTAQUE_ORG — [Pass Pass : près de 19 000 usagers exposés, commandes et factures diffusées après une cyberattaque](https://www.cyberattaque.org/pass-pass-pres-de-19-000-usagers-exposes-commandes-et-factures-diffusees-apres-une-cyberattaque/).
- `ITM-909b1b6129a81f63` — FRENCHBREACHES — [PassPass](https://frenchbreaches.com/alertes/passpass-mtokkaq53s0e7hlda1i).

<a id="inc-dc0bcfd579b8"></a>
## Répar'Store — INC-DC0BCFD579B8

**P1 — Doublon de Répar’stores, toujours séparé au second run ; réponse LLM affirme à tort DIFFERENT organisation à 0,5 et la clôture. Secteur devrait bénéficier de l'activité de réparation documentée sur l'autre fiche. Qualification riche presque vide malgré une source détaillée ; 1,8 million de clients reste justement revendiqué.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-05 | Inconnu / unknown | Fuite de données / unknown | France métropolitaine | 1 |
| R2 | 2026-09-05 | Inconnu / unknown | Fuite de données / unknown | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-c471c7f9bb97a447 / ITM-3bd9994596a70cb0` (Répar'Store / Répar'stores) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.

**Qualifications du volet R2**

Résumé : Répar'Store a subi un incident de sécurité ayant compromis des données clients.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : 1,8 million de clients [claimed].

Types de données : factures [claimed].

Systèmes : aucun élément publié.

Périmètres : données clients [unknown].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-c471c7f9bb97a447` — FRENCHBREACHES — [Répar'Store](https://frenchbreaches.com/alertes/r-par-store-mtoa0qd4rlpkduc13t).

<a id="inc-b44c794ab35b"></a>
## Répar’stores — INC-B44C794AB35B

**P1 — Ajout BLF correctement rattaché le 8 septembre et territoire France récupéré, mais le fragment FrenchBreaches reste séparé. Données bancaires affichées alors que la source les exclut ; risque de phishing rangé dans Impact. Commentaires, historique des devis et catégories de commandes perdus au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-05 | Construction / BTP / inferred | Fuite de données / confirmed | Inconnu | 1 |
| R2 | 2026-09-05 | Construction / BTP / inferred | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Construction / BTP.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : BONJOURLAFUITE : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Construction / BTP.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-64af20d611a38d0d / ITM-3bd9994596a70cb0` (Reso / Répar'stores) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-bce6453cf2314d49 / ITM-3bd9994596a70cb0` (Réso / Répar'stores) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-c471c7f9bb97a447 / ITM-3bd9994596a70cb0` (Répar'Store / Répar'stores) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.

**Qualifications du volet R2**

Résumé : Répar’stores : les données clients exposées après une cyberattaque

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | phishing ciblé | reported | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : commentaires [reported]; factures [reported]; noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; adresses postales [unknown]; informations de commandes [unknown]; données bancaires [unknown]; facturation [unknown]; Historique des devis [unknown].

Systèmes : aucun élément publié.

Périmètres : données clients [unknown]; IRIS [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : commentaires, informations de commandes, Historique des devis.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-827f9d9d0933d5cb` — CYBERATTAQUE_ORG — [Répar’stores : les données clients exposées après une cyberattaque](https://www.cyberattaque.org/reparstores-les-donnees-clients-exposees-apres-une-cyberattaque/).
- `ITM-3bd9994596a70cb0` — BONJOURLAFUITE — [Répar'stores](https://bonjourlafuite.eu.org/img/reparstores.png).

<a id="inc-44385edb45c1"></a>
## YouFid — INC-44385EDB45C1

**P2 — Secteur/fuite/localisation plausibles. La preuve décrit 7 880 enregistrements, mais l'impact les transforme en 7 880 personnes et un compteur people double le compteur records. Distinguer lignes et personnes uniques.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-05 | Services aux entreprises / inferred | Fuite de données / claimed | France métropolitaine | 1 |
| R2 | 2026-09-05 | Services aux entreprises / inferred | Fuite de données / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / SEMANTIC_ACTIVITY_MATCH → Services aux entreprises.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : inferred / SEMANTIC_ACTIVITY_MATCH → Services aux entreprises.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données chez YouFid avec 7 880 enregistrements publiés sur un forum cybercriminel.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Publication des données de 7 880 personnes sur un forum. | claimed | FRENCHBREACHES |

Volumes : 7 880 enregistrements [claimed]; 7 880 personnes [unknown].

Types de données : adresses e-mail [unknown]; numéros de téléphone [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-1cbbdf426dbaafd0` — FRENCHBREACHES — [YouFid](https://frenchbreaches.com/alertes/youfid-mtokeunf3fh8e0zgapu).

<a id="inc-3ac6333a7a42"></a>
## Accent Rouge — INC-3AC6333A7A42

**P2 — Secteur Inconnu par conflit Culture / Commerce pour la même description d'aménagement intérieur. Arbitrage d'activité nécessaire ; ne pas forcer un secteur générique. Fuite et France cohérentes. Multiples unités/volumes, résumé et impact à recaler sur leur périmètre ; pertes de catégories au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-04 | Inconnu / unknown | Fuite de données / reported | France métropolitaine | 2 |
| R2 | 2026-09-04 | Inconnu / unknown | Fuite de données / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / SEMANTIC_ACTIVITY_MATCH → Commerce / Distribution ; FRENCHBREACHES : inferred / SEMANTIC_ACTIVITY_MATCH → Culture / Médias / Loisirs.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : inferred / SEMANTIC_ACTIVITY_MATCH → Commerce / Distribution ; FRENCHBREACHES : inferred / SEMANTIC_ACTIVITY_MATCH → Culture / Médias / Loisirs.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Accent Rouge subit une fuite massive de données avec 32 000 fiches clients divulguées.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 1,6 Go | unknown | CYBERATTAQUE_ORG |
| impact | Plus de 32 000 fiches clients et 79 000 adresses diffusées, ainsi que des informations sensibles sur les paiements. | unknown | CYBERATTAQUE_ORG |
| threat_actor | DaOnlySpark | unknown | CYBERATTAQUE_ORG |

Volumes : 8 500 lignes [unknown]; 5 500 enregistrements [unknown]; 22 comptes [unknown]; 32 000 clients [unknown].

Types de données : informations de commandes [unknown]; factures [unknown]; noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; facturation [unknown]; dates de naissance [unknown]; montants [unknown]; identifiants [unknown]; mots de passe [unknown].

Systèmes : ERP [unknown]; ERP Odoo [confirmed]; Stripe [confirmed].

Périmètres : base clients [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : informations de commandes, montants.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-f5851a0dc5d7ce43` — FRENCHBREACHES — [Accent Rouge](https://frenchbreaches.com/alertes/accent-rouge-mtnfwe0yz31800vbok).
- `ITM-6659e35a58279e51` — CYBERATTAQUE_ORG — [Accent Rouge : 32 000 fiches clients diffusées après un piratage de son compte Odoo](https://www.cyberattaque.org/accent-rouge-cyberattaque-odoo/).

<a id="inc-2c5ceae9e3ac"></a>
## Association des maires de France — INC-2C5CEAE9E3AC

**P1 — AMF historique : exfiltration confirmée mais menace Intrusion depuis le premier run. Doublon probable de la nouvelle ligne BLF du 8 septembre. amf.asso.fr est affiché comme localisation précise, à tort. Injection SQL correctement revendiquée ; volumes 114 000 et plus de 100 000 sont des enregistrements, pas des personnes.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-04 | Association / Syndicat / referenced | Intrusion / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-04 | Association / Syndicat / referenced | Intrusion / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Association / Syndicat ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Association / Syndicat.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Association / Syndicat ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Association / Syndicat.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-af552eefe974f150 / ITM-ea7abde0b5a364e2` (Association des maires de France / Association des Maires de France) : VALIDATION_REJECTED, organisation SAME, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-fef84eaa6ff9af51 / ITM-ea7abde0b5a364e2` (Association des maires de France / Association des Maires de France) : VALIDATION_REJECTED, organisation SAME, incident SAME, confiance 0.6.

**Qualifications du volet R2**

Résumé : L'Association des maires de France a subi une fuite de 114 000 enregistrements après une cyberattaque.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | amf.asso.fr | confirmed | FRENCHBREACHES |
| impact | compromission de données d'identité, de contact et de mots de passe en clair | confirmed | CYBERATTAQUE_ORG |
| initial_access | vulnerability_exploitation | claimed | CYBERATTAQUE_ORG |
| threat_actor | Alduin | claimed | CYBERATTAQUE_ORG |

Volumes : 114 000 lignes [unknown]; 100 000 enregistrements [confirmed].

Types de données : identifiants [unknown]; mots de passe [confirmed]; noms et prénoms [unknown]; adresses e-mail [unknown]; données d’identité et de contact, des fonctions professionnelles, des références internes [confirmed].

Systèmes : site amf.asso.fr [reported].

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 3 étape(s) ; chronologie : 4 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-af552eefe974f150` — CYBERATTAQUE_ORG — [Association des maires de France : 114 000 lignes en fuite après une cyberattaque](https://www.cyberattaque.org/association-des-maires-de-france-114-000-lignes-en-fuite-apres-une-cyberattaque/).
- `ITM-fef84eaa6ff9af51` — FRENCHBREACHES — [Association des maires de France](https://frenchbreaches.com/alertes/association-des-maires-de-france-mtmsxq04rjndct88z4p).

<a id="inc-2c5cd2459f83"></a>
## Clinique de Vontes — INC-2C5CD2459F83

**P1 — Doublon de INC-45561E350283 ; deux URL FrenchBreaches portant le même identifiant suffixe. Changement d'Incident_ID au premier run. Résumé parle de patients sans preuve suffisante ; la source complémentaire décrit des profils internes INICEA et n'établit pas une exposition de données de santé de patients. Aucun type de données affiché sur ce fragment.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-04 | Santé / inferred | Fuite de données / claimed | France métropolitaine | 1 |
| R2 | 2026-09-04 | Santé / inferred | Fuite de données / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Santé.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Santé.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données à la Clinique de Vontes concernant 4 111 profils de patients.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | Esvres-sur-Indre, en Indre-et-Loire | claimed | FRENCHBREACHES |
| impact | Publication des données de 4 111 personnes. | claimed | FRENCHBREACHES |

Volumes : 4 111 enregistrements [claimed]; 4 111 personnes [claimed]; 4 100 personnes [unknown].

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-d289be7b54f1bf09` — FRENCHBREACHES — [Clinique de Vontes (INICEA)](https://frenchbreaches.com/alertes/clinique-de-vontes-inicea-mtm6ww9opvv422tgg4).

<a id="inc-45561e350283"></a>
## Clinique de Vontes — INC-45561E350283

**P1 — Doublon Clinique de Vontes conservé ; source FrenchBreaches échangée entre composantes au premier run. Secteur Santé et France corrects. Périmètre INICEA plus large que la clinique à porter dans l'identité/détail ; catégories internes supprimées au rendu et chiffres arrondis redondants.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-04 | Santé / inferred | Fuite de données / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-04 | Santé / inferred | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Santé ; CYBERATTAQUE_ORG : inferred / ORGANISATION_NAME_RULE → Santé.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Santé ; CYBERATTAQUE_ORG : inferred / ORGANISATION_NAME_RULE → Santé.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données affectant 4 111 personnes revendiquer par le hacker ChimeraZ au sein du groupe INICEA.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 2,53 Mo | unknown | CYBERATTAQUE_ORG |
| fine_location | Esvres-sur-Indre | confirmed | CYBERATTAQUE_ORG |
| impact | Exposition de profils utilisateurs et informations d'organisation interne. | confirmed | CYBERATTAQUE_ORG |
| threat_actor | ChimeraZ | claimed | CYBERATTAQUE_ORG |

Volumes : 4 111 personnes [unknown]; 4 111 enregistrements [unknown]; 4 100 personnes [unknown].

Types de données : noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; profils utilisateurs et informations d’organisation interne [claimed].

Systèmes : base interne du groupe INICEA [confirmed].

Périmètres : base clients [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 3 étape(s) ; chronologie : 3 entrée(s).

Catégories perdues au rendu : profils utilisateurs et informations d’organisation interne.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-b37ec6399417fe07` — CYBERATTAQUE_ORG — [Clinique de Vontes (INICEA) : 4 111 personnes exposées dans une fuite de données](https://www.cyberattaque.org/cyberattaque-clinique-de-vontes/).
- `ITM-0849bd689cb5eb4f` — FRENCHBREACHES — [Clinique de Vontes](https://frenchbreaches.com/alertes/clinique-de-vontes-mtm6ww9opvv422tgg4).

<a id="inc-f8485fb8b618"></a>
## Collège Saint-Michel — INC-F8485FB8B618

**P2 — Secteur Éducation et fuite revendiquée plausibles. Distinguer 1 838 lignes, 1 836 personnes et arrondi 1 800 ; types de données absents. Absence de nouvelles traces de qualification sur ces deux runs.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-04 | Éducation / Formation / inferred | Fuite de données / claimed | France métropolitaine | 1 |
| R2 | 2026-09-04 | Éducation / Formation / inferred | Fuite de données / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Éducation / Formation.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Éducation / Formation.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données au Collège Saint-Michel révélant des informations sur 1 836 personnes.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Les informations de 1 836 personnes ont été publiées. | claimed | FRENCHBREACHES |

Volumes : 1 838 lignes [claimed]; 1 836 personnes [claimed]; 1 800 personnes [unknown].

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 2 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-71ecea132bd4a42c` — FRENCHBREACHES — [Collège Saint-Michel](https://frenchbreaches.com/alertes/coll-ge-saint-michel-mtm6uc3fmrq1uwb2e).

<a id="inc-3e1b5fccaedf"></a>
## Préférence Formations — INC-3E1B5FCCAEDF

**P2 — Secteur Éducation, France et fuite cohérents. Volumes 5 381 lignes / 5 265 personnes / 5 200 arrondi ; éviter le cumul implicite et conserver la réserve revendiquée. Acteur présent mais sa preuve n'est pas directement consultable dans sa ligne.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-04 | Éducation / Formation / inferred | Fuite de données / reported | France métropolitaine | 2 |
| R2 | 2026-09-04 | Éducation / Formation / inferred | Fuite de données / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Éducation / Formation ; FRENCHBREACHES : inferred / ACTIVITY_RULE → Éducation / Formation.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Éducation / Formation ; FRENCHBREACHES : inferred / ACTIVITY_RULE → Éducation / Formation.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données de plus de 5 200 personnes touchées chez Préférence Formations.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 375 Ko | unknown | CYBERATTAQUE_ORG |
| impact | Les données de plus de 5 200 personnes sont désormais accessibles à des tiers. | claimed | CYBERATTAQUE_ORG |
| threat_actor | ChimeraZ | claimed | CYBERATTAQUE_ORG |

Volumes : 5 381 lignes [unknown]; 5 265 personnes [claimed]; 5 200 personnes [unknown].

Types de données : adresses e-mail [reported]; noms et prénoms [unknown]; identifiants [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-b1fecc30a0a3fc09` — CYBERATTAQUE_ORG — [Préférence Formations : les données de plus de 5 200 personnes diffusées après une cyberattaque](https://www.cyberattaque.org/preference-formations-les-donnees-de-plus-de-5-200-personnes-diffusees-apres-une-cyberattaque/).
- `ITM-cb101b53adea60f5` — FRENCHBREACHES — [Préférence Formations](https://frenchbreaches.com/alertes/pr-f-rence-formations-mtm701xaas25ttqxse).

<a id="inc-2690c398c621"></a>
## Storia Mundi — INC-2690C398C621

**P2 — Culture / Médias / Loisirs et fuite revendiquée cohérents. Comptes/utilisateurs/clients sont trois périmètres à expliciter ; précision 17 854 versus 17 850. Pas de nouvel arbitrage dédup utile : comparaison Yvetot en ERROR au second run.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-04 | Culture / Médias / Loisirs / inferred | Fuite de données / claimed | France métropolitaine | 2 |
| R2 | 2026-09-04 | Culture / Médias / Loisirs / inferred | Fuite de données / claimed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; CYBERATTAQUE_ORG : inferred / SEMANTIC_ACTIVITY_MATCH → Culture / Médias / Loisirs.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; CYBERATTAQUE_ORG : inferred / SEMANTIC_ACTIVITY_MATCH → Culture / Médias / Loisirs.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-3b3b9921859b5cef / ITM-1673e221850aa327` (Storia Mundi / CC Yvetot Normandie) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.

**Qualifications du volet R2**

Résumé : Storia Mundi a subi une fuite de données impliquant 17 850 profils d'utilisateurs.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Exposition des informations personnelles, des données d'authentification et de paiement. | claimed | CYBERATTAQUE_ORG |
| threat_actor | DaOnlySpark | claimed | CYBERATTAQUE_ORG |

Volumes : 17 854 comptes [unknown]; 17850 users [claimed]; 9 600 clients [claimed].

Types de données : dates de naissance [unknown]; noms et prénoms [unknown]; adresses e-mail [claimed]; adresses postales [unknown]; mots de passe [unknown]; numéros de téléphone [unknown]; identifiants [unknown]; factures [claimed]; facturation [unknown]; informations de paiement [claimed].

Systèmes : aucun élément publié.

Périmètres : base clients [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-50a7a47770dee2e7` — CYBERATTAQUE_ORG — [Storia Mundi piraté : 17 850 profils compromis en fuite sur le darweb](https://www.cyberattaque.org/storia-mundi-pirate-cyberattaque/).
- `ITM-3b3b9921859b5cef` — FRENCHBREACHES — [Storia Mundi](https://frenchbreaches.com/alertes/storia-mundi-mtnbhl7gn987owivuep).

<a id="inc-83ba7d2dcbf4"></a>
## BCTI — INC-83BA7D2DCBF4

**P2 — Construction / BTP, fuite revendiquée et France plausibles. base partielle est classé Évolution alors qu'il s'agit du périmètre ; Impact contient des risques futurs. Montants et informations immobilières disparaissent au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-03 | Construction / BTP / referenced | Fuite de données / claimed | France métropolitaine | 2 |
| R2 | 2026-09-03 | Construction / BTP / referenced | Fuite de données / claimed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Construction / BTP ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Construction / BTP.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Construction / BTP ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Construction / BTP.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données chez BCTI, comprenant des cartes d'identité et des dossiers immobiliers.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 12 Mo | claimed | CYBERATTAQUE_ORG |
| evolution | base partielle | claimed | CYBERATTAQUE_ORG |
| impact | usurpation d’identité et fraude documentaire | claimed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : pièces d'identité [reported]; facturation [unknown]; noms et prénoms [unknown]; identifiants [unknown]; montants [unknown]; cartes nationales d’identité [claimed]; informations sur des biens immobiliers [claimed].

Systèmes : partenaires.bcti.fr [confirmed].

Périmètres : base de données du service BCTI [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : montants, cartes nationales d’identité, informations sur des biens immobiliers.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-e96eac1931369ebd` — CYBERATTAQUE_ORG — [BCTI : cartes d’identité et des dossiers immobiliers en fuite](https://www.cyberattaque.org/cyberattaque-bcti-cartes-didentite-et-des-dossiers-immobiliers-en-fuite/).
- `ITM-49326d4ea5028690` — FRENCHBREACHES — [BCTI](https://frenchbreaches.com/alertes/bcti-mtktuv79ab8qfhxo7bp).

<a id="inc-b7dbf665e661"></a>
## Chambre de Métiers et de l’Artisanat d’Occitanie — INC-B7DBF665E661

**P1 — Doublon fortement étayé de CMA Occitanie : même date, nom développé/acronyme et fuite de 1 029 profils dans les articles. Fiche sans résumé, volumes, acteur ni types ; statut de menace inconnu. Aucune paire de rapprochement dans les journaux des deux runs.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-03 | Administration / Collectivité / referenced | Fuite de données / unknown | France métropolitaine | 1 |
| R2 | 2026-09-03 | Administration / Collectivité / referenced | Fuite de données / unknown | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : absent

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : aucun élément publié.

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-9c16af75e968a0f8` — FRENCHBREACHES — [Chambre de Métiers et de l’Artisanat d’Occitanie](https://frenchbreaches.com/alertes/chambre-de-m-tiers-et-de-l-artisanat-d-occitanie-mtktlb1edwrd1ok63hq).

<a id="inc-52ed884732bc"></a>
## Charbonneaux-Brabant — INC-52ED884732BC

**P2 — Industrie / Manufacture et France cohérents. Résumé transforme 2 863 enregistrements en personnes alors que le compteur détaillé reste records. Fuite revendiquée ; garder le périmètre et les réserves.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-03 | Industrie / Manufacture / inferred | Fuite de données / reported | France métropolitaine | 2 |
| R2 | 2026-09-03 | Industrie / Manufacture / inferred | Fuite de données / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Industrie / Manufacture ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Industrie / Manufacture ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données revendiquée chez Charbonneaux-Brabant affectant 2 863 personnes.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 660 Ko | unknown | CYBERATTAQUE_ORG |
| fine_location | Reims | claimed | CYBERATTAQUE_ORG |
| impact | Publication d'une base de données contenant des informations personnelles. | claimed | FRENCHBREACHES |
| threat_actor | ChimeraZ | claimed | FRENCHBREACHES |

Volumes : 2 863 lignes [unknown].

Types de données : adresses e-mail [claimed]; noms et prénoms [unknown]; identifiants [unknown].

Systèmes : aucun élément publié.

Périmètres : base contenant des profils [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-5be9f3b0cc9efd93` — CYBERATTAQUE_ORG — [Charbonneaux-Brabant : 2 863 profils professionnels exposés dans une fuite de données](https://www.cyberattaque.org/charbonneaux-brabant-2-863-profils-professionnels-exposes-dans-une-fuite-de-donnees/).
- `ITM-9be0e51d6fc67e1c` — FRENCHBREACHES — [Charbonneaux-Brabant](https://frenchbreaches.com/alertes/charbonneaux-brabant-mtktomg03zpucc9qjk7).

<a id="inc-619638da1c52"></a>
## CMA Occitanie — INC-619638DA1C52

**P1 — Doublon fortement étayé de la Chambre de Métiers et de l’Artisanat d’Occitanie, avec perte du territoire présent sur l'autre fragment. Secteur public correct. Acteur ChimeraZ disponible dans le résumé mais absent du champ acteur ; preuve du nombre conservée sans badge.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-03 | Administration / Collectivité / referenced | Fuite de données / reported | Inconnu | 1 |
| R2 | 2026-09-03 | Administration / Collectivité / referenced | Fuite de données / reported | Inconnu | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données touchant CMA Occitanie avec 1 029 profils exposés par le hacker ChimeraZ.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 60 Ko | unknown | CYBERATTAQUE_ORG |
| impact | Exposition de 1 029 profils professionnels. | claimed | CYBERATTAQUE_ORG |

Volumes : 1 029 lignes [unknown].

Types de données : adresses e-mail [claimed]; noms et prénoms [unknown].

Systèmes : aucun élément publié.

Périmètres : base clients [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-1a7a19bfd19ae7f2` — CYBERATTAQUE_ORG — [CMA Occitanie : plus de 1 000 profils professionnels exposés dans une fuite de données](https://www.cyberattaque.org/chambre-de-metiers-et-de-lartisanat-cyberattaque/).

<a id="inc-47cd44fa27b9"></a>
## ColisExpat — INC-47CD44FA27B9

**P1 — Fuite de pièces d'identité et données de compte décrite, mais menace passée à Intrusion. Landmark Global France affiché comme acteur revendicateur alors que son rôle doit être celui de l'organisation/du groupe de la victime. Vecteur libre accès non autorisé ne précise pas le mode d'entrée.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-03 | Transport / Logistique / inferred | Intrusion / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-03 | Transport / Logistique / inferred | Intrusion / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Transport / Logistique ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Transport / Logistique ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : ColisExpat a subi une cyberattaque exposant des pièces d'identité et des données de compte de ses clients.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | L’environnement compromis a été mis hors ligne | confirmed | CYBERATTAQUE_ORG |
| initial_access | accès non autorisé | confirmed | CYBERATTAQUE_ORG |
| threat_actor | Landmark Global France | confirmed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : pièces d'identité [reported]; noms et prénoms [unknown]; adresses e-mail [unknown]; adresses postales [unknown]; mots de passe [unknown]; identifiants [unknown]; données de compte [reported].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : données de compte.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-ba3837c2af95dd26` — CYBERATTAQUE_ORG — [ColisExpat : une cyberattaque expose les pièces d’identité et données de compte](https://www.cyberattaque.org/colisexpat-une-cyberattaque-expose-les-pieces-didentite-et-donnees-de-compte/).
- `ITM-e67866257a323b8b` — FRENCHBREACHES — [ColisExpat](https://frenchbreaches.com/alertes/colisexpat-mtli3y3saqaoiaimmgd).

<a id="inc-693abeb9bf8a"></a>
## Delicity — INC-693ABEB9BF8A

**P1 — Secteur Numérique et fuite cohérents. Acteur revendicateur plateforme est un faux acteur générique. Catégories de commandes et données personnelles supprimées au rendu. Données d'authentification/statuts à vérifier individuellement.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-03 | Numérique / Technologie / referenced | Fuite de données / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-03 | Numérique / Technologie / referenced | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Delicity a confirmé une fuite de données personnelles survenue entre le 9 et le 24 août 2026.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | fuite de données personnelles | confirmed | CYBERATTAQUE_ORG |
| threat_actor | plateforme | claimed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : informations de commandes [confirmed]; mots de passe [confirmed]; noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; identifiants [reported]; données personnelles [unknown].

Systèmes : Metabase [unknown].

Périmètres : réservations [confirmed]; Données des clients, restaurateurs et livreurs [confirmed].

Vulnérabilités : CVE-2026-72898 [unknown].

Déroulé : 0 étape(s) ; chronologie : 3 entrée(s).

Catégories perdues au rendu : informations de commandes, données personnelles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-87d241b7fe2c7429` — CYBERATTAQUE_ORG — [Delicity : les données de clients, restaurateurs et livreurs exposées après une cyberattaque](https://www.cyberattaque.org/delicity-cyberattaque-faille-metabase-expose-les-donnees-de-clients-restaurateurs-et-livreurs/).
- `ITM-5b67e9e70df54ce7` — FRENCHBREACHES — [Delicity](https://frenchbreaches.com/alertes/delicity-mtlhw5asykbr9p4rhu).

<a id="inc-e39201703225"></a>
## Reso — INC-E39201703225

**P2 — Secteur Commerce, fuite revendiquée et acteur caustic cohérents. Tiers fournisseur trop générique ; volumes fichiers multiples et arrondis sans périmètre visible. Comparaisons dédup avec Répar’stores justement distinctes.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-03 | Commerce / Distribution / referenced | Fuite de données / claimed | France métropolitaine | 2 |
| R2 | 2026-09-03 | Commerce / Distribution / referenced | Fuite de données / claimed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-64af20d611a38d0d / ITM-3bd9994596a70cb0` (Reso / Répar'stores) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-bce6453cf2314d49 / ITM-3bd9994596a70cb0` (Réso / Répar'stores) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.

**Qualifications du volet R2**

Résumé : Réso victime d'une fuite massive de données, 675 Go et 530 000 fichiers récupérés par le hacker caustic.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 675 Go | claimed | CYBERATTAQUE_ORG |
| impact | Exfiltration de 675 Go de données internes et 530 000 fichiers revendiqués. | claimed | FRENCHBREACHES |
| third_party | fournisseur | unknown | CYBERATTAQUE_ORG |
| threat_actor | caustic | claimed | CYBERATTAQUE_ORG |

Volumes : 43 000 dossiers [unknown]; 530 000 fichiers [unknown]; 500 000 fichiers [unknown].

Types de données : informations de commandes [unknown]; factures [claimed]; données bancaires [unknown]; données commerciales et techniques [claimed].

Systèmes : aucun élément publié.

Périmètres : base clients [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : informations de commandes, données commerciales et techniques.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-bce6453cf2314d49` — CYBERATTAQUE_ORG — [Réso : plus de 500 000 fichiers internes dans une fuite massive après une cyberattaque](https://www.cyberattaque.org/reso-plus-de-500-000-fichiers-internes-dans-une-fuite-massive-apres-une-cyberattaque/).
- `ITM-64af20d611a38d0d` — FRENCHBREACHES — [Reso](https://frenchbreaches.com/alertes/reso-mtlxxb9d9050x5hmr8q).

<a id="inc-b56c65c3fdac"></a>
## Tisséo — INC-B56C65C3FDAC

**P2 — Secteur Transport / Logistique récupérable : les preuves qualifient explicitement un réseau de transports toulousain, mais NO_ACTIVITY_EVIDENCE persiste. Fuite et France cohérentes. Les données RH et commandes disparaissent au rendu ; bien distinguer 13 446 lignes et 2 877 personnes.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-03 | Inconnu / unknown | Fuite de données / reported | France métropolitaine | 2 |
| R2 | 2026-09-03 | Inconnu / unknown | Fuite de données / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Près de 3 000 personnes exposées après une cyberattaque ciblant Tisséo.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 1,22 Go | claimed | CYBERATTAQUE_ORG |
| fine_location | Toulouse | unknown | CYBERATTAQUE_ORG |
| impact | Fuite de données internes concernant des agents et l'organisation de Tisséo. | unknown | CYBERATTAQUE_ORG |
| threat_actor | ChimeraZ | unknown | CYBERATTAQUE_ORG |

Volumes : 13 446 enregistrements [claimed]; 2 877 personnes [claimed]; 10 000 enregistrements [unknown].

Types de données : noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; données RH [unknown]; informations de commandes [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : données RH, informations de commandes.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-c8cdccbe86f725ef` — CYBERATTAQUE_ORG — [Tisséo : près de 3 000 personnes exposées après une cyberattaque](https://www.cyberattaque.org/cyberattaque-tisseo-toulouse/).
- `ITM-38afbfb13ebade24` — FRENCHBREACHES — [Tisséo](https://frenchbreaches.com/alertes/tiss-o-mtktrusw2xxeaxkehp8).

<a id="inc-f8cddc2dd3b7"></a>
## ZeroGaspi — INC-F8CDDC2DD3B7

**P2 — Commerce, France et fuite revendiquée cohérents. 80 000 clients et 80 000 enregistrements coexistent sans lien de périmètre visible. Catégories de commandes/montants supprimées au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-03 | Commerce / Distribution / inferred | Fuite de données / claimed | France métropolitaine | 2 |
| R2 | 2026-09-03 | Commerce / Distribution / inferred | Fuite de données / claimed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Commerce / Distribution ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Commerce / Distribution ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Une base de 80 000 clients de ZeroGaspi est en vente après une cyberattaque revendiquée par le hacker ksye.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Des informations de 80 000 clients mises en vente. | claimed | FRENCHBREACHES |
| threat_actor | ksye | claimed | CYBERATTAQUE_ORG |

Volumes : 80 000 clients [unknown]; 80 000 enregistrements [unknown].

Types de données : informations de commandes [unknown]; numéros de téléphone [unknown]; montants [unknown]; noms et prénoms [unknown]; adresses e-mail [unknown]; adresses postales [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 2 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : informations de commandes, montants.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-0f0716ce4755d459` — CYBERATTAQUE_ORG — [ZeroGaspi : une base de 80 000 clients en vente après une cyberattaque](https://www.cyberattaque.org/zerogaspi-une-base-de-80-000-clients-en-vente-apres-une-cyberattaque/).
- `ITM-4db2ae12f71a1693` — FRENCHBREACHES — [ZeroGaspi](https://frenchbreaches.com/alertes/zerogaspi-mtly357yaln2xfqzy4).

<a id="inc-6bd2de3819f9"></a>
## Dropbox — INC-6BD2DE3819F9

**P2 — Incident tiers peut être défendable via l'intégration Lenovo décrite, mais la preuve du vecteur tiers des comptes compromis est une fraction, pas un tiers prestataire. Localisation Inconnu à conserver tant que le périmètre géographique n'est pas établi. Deux compteurs de 5 000 comptes redondants.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Numérique / Technologie / referenced | Incident tiers / confirmed | Inconnu | 1 |
| R2 | 2026-09-02 | Numérique / Technologie / referenced | Incident tiers / confirmed | Inconnu | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Environ 5 000 comptes Dropbox compromis entre le 4 et le 21 août 2026 par l'exploitation d'une ancienne intégration avec Lenovo.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| initial_access | third_party | confirmed | CYBERATTAQUE_ORG |

Volumes : 5 000 comptes [confirmed]; environ 5 000 comptes [unknown].

Types de données : identifiants [unknown]; mots de passe [unknown].

Systèmes : Dropbox [confirmed].

Périmètres : comptes utilisateurs Dropbox [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-0c5790b0a532025c` — CYBERATTAQUE_ORG — [Dropbox : 5 000 comptes piratés, des milliers de fichiers en fuite](https://www.cyberattaque.org/dropbox-pirate-5-000-comptes-compromis-des-milliers-de-fichiers-en-fuite/).

<a id="inc-64fe6b5ddb80"></a>
## FNIM — INC-64FE6B5DDB80

**P2 — Secteur Association, fuite et France cohérents. Impact mêle publication et risque de réutilisation. Les catégories de commandes, bases SQL, BIC et données personnelles nécessitent une normalisation conservant les informations utiles.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Association / Syndicat / referenced | Fuite de données / reported | France métropolitaine | 2 |
| R2 | 2026-09-02 | Association / Syndicat / referenced | Fuite de données / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Association / Syndicat ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Association / Syndicat.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Association / Syndicat ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Association / Syndicat.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : La FNIM a subi un piratage avec des données sensibles compromises et des accès bancaires revendiqués.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | diffusion publique de données sensibles entraînant un risque accru de réutilisation | claimed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : facturation [unknown]; informations de commandes [reported]; bases SQL [reported]; adresses e-mail [unknown]; numéros de téléphone [unknown]; identifiants [unknown]; données bancaires [unknown]; BIC / SWIFT [unknown]; données personnelles [unknown].

Systèmes : infrastructure mutualisée [claimed].

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 2 étape(s) ; chronologie : 4 entrée(s).

Catégories perdues au rendu : informations de commandes, bases SQL, BIC / SWIFT, données personnelles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-68e84c61b64115aa` — CYBERATTAQUE_ORG — [FNIM : des bases de données complètes diffusées après une cyberattaque](https://www.cyberattaque.org/fnim-des-bases-de-donnees-completes-diffusees-apres-une-cyberattaque/).
- `ITM-47853f7a53762222` — FRENCHBREACHES — [FNIM](https://frenchbreaches.com/alertes/fnim-mtjy1oawv9ayhxk3qr).

<a id="inc-c4996b1885d9"></a>
## Géofoncier — INC-C4996B1885D9

**P1 — Menace Intrusion malgré une extraction massive et 4,2 millions de lignes revendiquées dans les faits. Secteur Inconnu alors que l'activité foncière est décrite ; taxonomie à arbitrer. L'action extraction massive via un compte authentifié apparaît à tort parmi les types de données, puis est cachée au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Inconnu / unknown | Intrusion / reported | France métropolitaine | 2 |
| R2 | 2026-09-02 | Inconnu / unknown | Intrusion / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup `ITM-48e2bee9b75f6d4b / ITM-7ddc5f6739f7709d` (Géofoncier / Footsider) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.
- R1, dédup `ITM-ab8836dc2f58e58e / ITM-5038ebd6674ce417` (Géofoncier / Footsider) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.
- R2, secteur : CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Le hacker ZeroBytes revendique le piratage de la plateforme Géofoncier.fr spécialisée dans l'information foncière.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | facilite la cartographie de professionnels et le démarchage abusif | unknown | CYBERATTAQUE_ORG |
| threat_actor | ZeroBytes | unknown | CYBERATTAQUE_ORG |

Volumes : 4,2 millions de lignes [claimed]; 4 millions de dossiers [unknown].

Types de données : identifiants [claimed]; numéros de téléphone [unknown]; noms et prénoms [unknown]; métadonnées techniques [unknown]; enregistrements liés à des dossiers ou actes fonciers [claimed]; extraction massive via un compte authentifié [reported].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : compte authentifié [claimed].

Déroulé : 1 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : métadonnées techniques, enregistrements liés à des dossiers ou actes fonciers.

Alertes du produit : SUMMARY_FACT_CONTRADICTION.

**Sources de cette fiche**

- `ITM-48e2bee9b75f6d4b` — CYBERATTAQUE_ORG — [Géofoncier : plus de 4 millions de dossiers fonciers exposés dans une fuite massive](https://www.cyberattaque.org/geofoncier-plus-de-4-millions-de-dossiers-fonciers-exposes-dans-une-fuite-massive/).
- `ITM-ab8836dc2f58e58e` — FRENCHBREACHES — [Géofoncier](https://frenchbreaches.com/alertes/g-ofoncier-mtj8t6co0pczd1uq3z1h).

<a id="inc-b18279aa1f95"></a>
## La Boutique du Volet — INC-B18279AA1F95

**P2 — Secteur Commerce, fuite et France plausibles. Le volet perd les catégories de commandes et données personnelles ; statuts inconnus masqués. Pas de nouveau log LLM sur les deux runs.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Commerce / Distribution / referenced | Fuite de données / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-02 | Commerce / Distribution / referenced | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Une cyberattaque expose les données et l’historique des commandes de clients de La Boutique du Volet.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : aucun élément publié.

Types de données : informations de commandes [unknown]; adresses e-mail [unknown]; numéros de téléphone [confirmed]; noms et prénoms [unknown]; facturation [unknown]; mots de passe [unknown]; données personnelles [unknown].

Systèmes : environnement sécurisé [confirmed].

Périmètres : coordonnées personnelles et historique des commandes [confirmed]; données clients [unknown].

Vulnérabilités : point d’entrée [reported].

Déroulé : 1 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : informations de commandes, données personnelles.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-3ea1b0fde3ccb797` — CYBERATTAQUE_ORG — [La Boutique du Volet : une cyberattaque expose les données et l’historique de commandes de clients](https://www.cyberattaque.org/la-boutique-du-volet-une-cyberattaque-expose-les-donnees-et-lhistorique-de-commandes-de-clients/).
- `ITM-dc819e8df8308283` — FRENCHBREACHES — [La Boutique du Volet](https://frenchbreaches.com/alertes/la-boutique-du-volet-mtkld2kqnn3iulc7t78).

<a id="inc-cfb60e563eb4"></a>
## LiveTrail — INC-CFB60E563EB4

**P1 — Menace passée à Intrusion malgré les coordonnées exposées et la notification BLF. Secteur Numérique correct. Mots de passe hachés réduits au libellé mots de passe, sans conservation visible de cette nuance.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Numérique / Technologie / referenced | Intrusion / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-02 | Numérique / Technologie / referenced | Intrusion / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : LiveTrail a subi une cyberattaque ayant exposé les coordonnées des utilisateurs.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : aucun élément publié.

Types de données : adresses e-mail [unknown]; mots de passe [unknown]; identifiants [unknown].

Systèmes : aucun élément publié.

Périmètres : comptes utilisateurs [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-7cc16874b28f6592` — CYBERATTAQUE_ORG — [LiveTrail : une cyberattaque expose les coordonnées des utilisateurs](https://www.cyberattaque.org/livetrail-une-cyberattaque-expose-les-coordonnees-des-utilisateurs/).
- `ITM-3a41569a8967db5a` — FRENCHBREACHES — [LiveTrail](https://frenchbreaches.com/alertes/livetrail-mtjxhuwerp3v2k4hem9).

<a id="inc-ce9040dc18ab"></a>
## Micromania — INC-CE9040DC18AB

**P1 — Secteur Commerce, fuite et France cohérents. Shipup apparaît à la fois comme tiers et comme acteur revendicateur confirmé : erreur de rôle. Les champs vecteur/impact utilisent aussi des textes libres et des statuts discordants.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Commerce / Distribution / referenced | Fuite de données / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-02 | Commerce / Distribution / referenced | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Micromania confirme une fuite de données personnelles de ses clients via son prestataire Shipup.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | atteinte à la confidentialité des données | claimed | CYBERATTAQUE_ORG |
| initial_access | faille de sécurité affectant un logiciel tiers | claimed | CYBERATTAQUE_ORG |
| third_party | Shipup | confirmed | CYBERATTAQUE_ORG |
| threat_actor | Shipup | confirmed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : informations de commandes [unknown]; adresses e-mail [claimed]; numéros de téléphone [unknown]; noms et prénoms [unknown]; données personnelles [claimed].

Systèmes : Metabase [unknown].

Périmètres : données clients [unknown]; base clients [confirmed].

Vulnérabilités : CVE-2026-72898 [unknown].

Déroulé : 0 étape(s) ; chronologie : 3 entrée(s).

Catégories perdues au rendu : informations de commandes, données personnelles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-2eed670173f2bfd2` — CYBERATTAQUE_ORG — [Micromania : ses données clients exposées après une cyberattaque chez Shipup](https://www.cyberattaque.org/micromania-ses-donnees-clients-exposees-apres-une-cyberattaque-chez-shipup/).
- `ITM-cdce24fe660aba3c` — FRENCHBREACHES — [Micromania](https://frenchbreaches.com/alertes/micromania-mtkqt98z0l4chcj41qpe).

<a id="inc-15a9f3ac6ac8"></a>
## Ministère de la Transition écologique — INC-15A9F3AC6AC8

**P2 — Menace passée de Fuite à Intrusion ; la revendication de données dans le résumé nécessite de réexaminer la menace à partir de l'article. Secteur public/France cohérents. Détail sans volumes, acteur ni types ; aucune nouvelle extraction tracée.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Administration / Collectivité / inferred | Intrusion / confirmed | France métropolitaine | 1 |
| R2 | 2026-09-02 | Administration / Collectivité / inferred | Intrusion / confirmed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Le ministère de la Transition écologique a subi une cyberattaque, entraînant la revendication des données de milliers d'utilisateurs.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : aucun élément publié.

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-3d1f4557ead62cd8` — FRENCHBREACHES — [Ministère de la Transition écologique](https://frenchbreaches.com/alertes/minist-re-de-la-transition-cologique-mtk4bzvizh7z1fmgm7).

<a id="inc-90a8d0197e17"></a>
## Shipup — INC-90A8D0197E17

**P1 — Intrusion depuis le premier run alors que résumé et impact décrivent l'exposition de données clients. Secteur Numérique et tiers technique Metabase cohérents ; conserver le lien de chaîne avec les victimes clientes sans fusionner arbitrairement toutes leurs fiches.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Numérique / Technologie / referenced | Intrusion / reported | France métropolitaine | 2 |
| R2 | 2026-09-02 | Numérique / Technologie / referenced | Intrusion / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Shipup a subi une cyberattaque entraînant l'exposition de données clients via une vulnérabilité dans Metabase.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | des tiers non autorisés ont pu accéder à certaines données clients | confirmed | CYBERATTAQUE_ORG |
| initial_access | vulnerability_exploitation | confirmed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : informations de commandes [unknown]; adresses e-mail [reported]; numéros de téléphone [unknown]; noms et prénoms [unknown].

Systèmes : Metabase [unknown].

Périmètres : données clients [unknown]; informations clients utilisées pour le suivi des commandes [confirmed].

Vulnérabilités : CVE-2026-72898 [unknown].

Déroulé : 1 étape(s) ; chronologie : 3 entrée(s).

Catégories perdues au rendu : informations de commandes.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-ec7dface31b72e5c` — CYBERATTAQUE_ORG — [Shipup touché par la faille Metabase : plusieurs grandes enseignes concernées](https://www.cyberattaque.org/cyberattaque-shipup/).
- `ITM-0889c66115507f6c` — FRENCHBREACHES — [Shipup](https://frenchbreaches.com/alertes/shipup-mtkrgifdha9tj8813fl).

<a id="inc-582e355e2705"></a>
## Stade Montois Omnisports — INC-582E355E2705

**P2 — Intrusion/indisponibilité et secteur Sport cohérents. Mont-de-Marsan est extrait mais ne résout pas le territoire. Les 400 000 fichiers doivent garder leur contexte exact ; catégorie données personnelles cachée au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Sport / referenced | Intrusion / confirmed | Inconnu | 1 |
| R2 | 2026-09-02 | Sport / referenced | Intrusion / confirmed | Inconnu | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Sport.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Sport.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Le Stade Montois Omnisports a subi une cyberattaque importante affectant plusieurs de ses sites et applications internes.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | Mont-de-Marsan | confirmed | CYBERATTAQUE_ORG |

Volumes : 400 000 fichiers [unknown].

Types de données : données personnelles [unknown].

Systèmes : aucun élément publié.

Périmètres : sauvegardes quotidiennes [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : données personnelles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-9efba1fc59a55884` — CYBERATTAQUE_ORG — [Stade Montois Omnisports : une cyberattaque met plusieurs sites hors service](https://www.cyberattaque.org/stade-montois-une-cyberattaque-met-plusieurs-sites-hors-service/).

<a id="inc-df5c519783e8"></a>
## Ville de Libercourt — INC-DF5C519783E8

**P1 — Ransomware Kairos, secteur public et France cohérents. Vecteur phishing injustifié : preuve portant sur un risque futur pour les personnes. Acteur sans badge revendiqué ; 817 Go sont revendiqués. Données RH supprimées au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-02 | Administration / Collectivité / inferred | Ransomware / reported | France métropolitaine | 2 |
| R2 | 2026-09-02 | Administration / Collectivité / inferred | Ransomware / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : inferred / ORGANISATION_NAME_RULE → Administration / Collectivité ; RANSOMWARE_LIVE : inferred / ORGANISATION_NAME_RULE → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : inferred / ORGANISATION_NAME_RULE → Administration / Collectivité ; RANSOMWARE_LIVE : inferred / ORGANISATION_NAME_RULE → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : La Ville de Libercourt victime d'une cyberattaque revendiquée par le groupe Kairos, avec 817 Go de données menacées de publication.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 817 Go | claimed | CYBERATTAQUE_ORG |
| discovered_date | 2026-09-02 | unknown | RANSOMWARE_LIVE |
| fine_location | Libercourt, Pas-de-Calais | claimed | CYBERATTAQUE_ORG |
| impact | usurpation d’identité, phishing ciblé ou fraude | reported | CYBERATTAQUE_ORG |
| initial_access | phishing | claimed | CYBERATTAQUE_ORG |
| threat_actor | kairos | unknown | RANSOMWARE_LIVE |

Volumes : aucun élément publié.

Types de données : pièces d'identité [unknown]; données RH [unknown]; documents sensibles [reported].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : données RH, documents sensibles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-3634a3939669099f` — CYBERATTAQUE_ORG — [Ville de Libercourt : 817 Go de données revendiqués après une cyberattaque](https://www.cyberattaque.org/ville-de-libercourt-817-go-de-donnees-revendiquesapres-une-cyberattaque/).
- `ITM-67466aa3ed46e2ee` — RANSOMWARE_LIVE — [Ville de Libercourt revendiqué par kairos]().

<a id="inc-72fe2288a677"></a>
## Bio en Hauts-de-France — INC-72FE2288A677

**P2 — Agriculture et France cohérents avec le périmètre ; fuite confirmée dans la preuve. Amiens a une preuve indirecte, à lier explicitement à la victime. Aucune fusion avec AMF, ce qui est correct. Données personnelles génériques perdues au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-09-01 | Agriculture / Agroalimentaire / inferred | Fuite de données / confirmed | France métropolitaine | 2 |
| R2 | 2026-09-01 | Agriculture / Agroalimentaire / inferred | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Agriculture / Agroalimentaire.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Agriculture / Agroalimentaire.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-7597af39837701fa / ITM-ea7abde0b5a364e2` (Bio en Hauts-de-France / Association des Maires de France) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-b748ef8a5951e965 / ITM-ea7abde0b5a364e2` (Bio en Hauts-de-France / Association des Maires de France) : DIFFERENT, organisation DIFFERENT, incident UNKNOWN, confiance 0.5.

**Qualifications du volet R2**

Résumé : Cyberattaque contre Bio en Hauts-de-France entraînant le vol de données personnelles et professionnelles.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | Amiens | confirmed | CYBERATTAQUE_ORG |
| impact | Violation de données personnelles et professionnelles. | confirmed | FRENCHBREACHES |

Volumes : aucun élément publié.

Types de données : noms et prénoms [unknown]; dates de naissance [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; adresses postales [unknown]; SIREN / SIRET [unknown]; données personnelles [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : données personnelles.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-b748ef8a5951e965` — CYBERATTAQUE_ORG — [Bio en Hauts-de-France : des données personnelles compromises après une cyberattaque](https://www.cyberattaque.org/bio-en-hauts-de-france-des-donnees-personnelles-compromises-apres-une-cyberattaque/).
- `ITM-7597af39837701fa` — FRENCHBREACHES — [Bio en Hauts-de-France](https://frenchbreaches.com/alertes/bio-en-hauts-de-france-mtiikognot4hbi60ug).

<a id="inc-b0e6bde8801f"></a>
## Herbiolys — INC-B0E6BDE8801F

**P2 — Industrie et France plausibles ; fuite revendiquée mais résumé affirmatif. 1 500 IBAN sont transformés notamment en accounts et données bancaires, en plus de 1,3 million de lignes : unités à corriger. Plusieurs catégories perdues au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-31 | Industrie / Manufacture / referenced | Fuite de données / claimed | France métropolitaine | 2 |
| R2 | 2026-08-31 | Industrie / Manufacture / referenced | Fuite de données / claimed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Industrie / Manufacture ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Industrie / Manufacture.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Industrie / Manufacture ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Industrie / Manufacture.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Herbiolys a subi une fuite de données massive, impliquant 1,3 million de lignes et 1 500 IBAN.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Des données sensibles, y compris des informations bancaires et personnelles, ont été exposées. | claimed | CYBERATTAQUE_ORG |
| threat_actor | Sophia | claimed | CYBERATTAQUE_ORG |

Volumes : 1500 accounts [unknown]; 1,3 million de lignes [claimed]; 1 500 IBAN uniques [claimed].

Types de données : données bancaires [claimed]; informations de commandes [unknown]; noms et prénoms [unknown]; dates de naissance [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; adresses postales [unknown]; mots de passe [unknown]; montants [unknown]; identifiants [unknown].

Systèmes : aucun élément publié.

Périmètres : données clients [unknown]; base clients [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 2 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : informations de commandes, montants.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-03fb3005e50cb68f` — CYBERATTAQUE_ORG — [Herbiolys piraté : 1,3 million de lignes et 1 500 IBAN dans une fuite massive](https://www.cyberattaque.org/herbiolys-cyberattaque-million-de-lignes-et-1-500-iban-dans-une-fuite-massive/).
- `ITM-408c12a81073fa4d` — FRENCHBREACHES — [Herbiolys](https://frenchbreaches.com/alertes/herbiolys-mthbl4mtoe9zgl49kjj).

<a id="inc-c64e07b15b3f"></a>
## La financière d’Orion — INC-C64E07B15B3F

**P2 — Correction utile Phishing / fraude vers Fuite au premier run. Finance et territoire France cohérents ; le rôle du conseiller/partenaire doit rester distinct de la victime. Vecteur ordinateur d’un conseiller non normalisé ; types financiers absents malgré le résumé. Paire avec BumFot en ERROR au second run.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-31 | Finance / Assurance / referenced | Fuite de données / reported | France métropolitaine | 1 |
| R2 | 2026-08-31 | Finance / Assurance / referenced | Fuite de données / reported | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Finance / Assurance.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup `ITM-853bff3331f5dba9 / ITM-386e8b0cef884341` (La financière d’Orion / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.75.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Finance / Assurance.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-853bff3331f5dba9 / ITM-386e8b0cef884341` (La financière d’Orion / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.

**Qualifications du volet R2**

Résumé : La financière d’Orion : 20 Go de données clients volés après le piratage d’un partenaire

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 20 Go | unknown | CYBERATTAQUE_ORG |
| impact | des données financières et patrimoniales accessibles à son utilisateur | claimed | CYBERATTAQUE_ORG |
| initial_access | ordinateur d’un conseiller | reported | CYBERATTAQUE_ORG |
| threat_actor | Nova | claimed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : identifiants [unknown].

Systèmes : aucun élément publié.

Périmètres : données clients [unknown].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-853bff3331f5dba9` — CYBERATTAQUE_ORG — [La financière d’Orion : 20 Go de données clients volés après le piratage d’un partenaire](https://www.cyberattaque.org/la-financiere-dorion-20-go-de-donnees-clients-voles-apres-le-piratage-dun-partenaire/).

<a id="inc-26e2a421ad48"></a>
## LebonSiege — INC-26E2A421AD48

**P2 — Commerce / Distribution récupérable si le lien entre LebonSiege et le site de vente en ligne est validé ; preuve actuelle trop courte. Secteur inconnu n'est pas résolu. Quatre compteurs voisins de 1 000 comptes/clients persistent ; impact décrit un risque de phishing.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-31 | Inconnu / unknown | Fuite de données / claimed | France métropolitaine | 2 |
| R2 | 2026-08-31 | Inconnu / unknown | Fuite de données / claimed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : unknown / ACTIVITY_EVIDENCE_REJECTED → Inconnu ; CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : unknown / ACTIVITY_EVIDENCE_REJECTED → Inconnu ; CYBERATTAQUE_ORG : unknown / NO_ACTIVITY_EVIDENCE → Inconnu.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données revendiquée chez LebonSiege, affectant potentiellement plus de 1 000 clients.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Les données exposées peuvent être utilisées pour des campagnes de phishing. | claimed | CYBERATTAQUE_ORG |
| threat_actor | Sophia | claimed | FRENCHBREACHES |

Volumes : 1 000 clients [claimed]; 1 000 comptes [claimed]; près de 1 000 clients [reported]; environ 1 000 comptes [unknown].

Types de données : numéros de téléphone [unknown]; adresses e-mail [reported]; adresses postales [unknown]; mots de passe [unknown]; noms et prénoms [unknown]; dates de naissance [unknown]; SIREN / SIRET [unknown]; informations de commandes [unknown]; informations sur comptes employés [reported].

Systèmes : LeBonSiège.fr [reported].

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 3 entrée(s).

Catégories perdues au rendu : informations de commandes, informations sur comptes employés.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-ad6e9de3e09cb125` — CYBERATTAQUE_ORG — [Le Bon Siège : près de 1 000 clients exposés avec adresses et téléphones](https://www.cyberattaque.org/lebonsiege-pres-de-1-000-clients-exposes-avec-adresses-et-telephones/).
- `ITM-37b09b9c01f3697d` — FRENCHBREACHES — [LebonSiege](https://frenchbreaches.com/alertes/lebonsiege-mth9to627fhnlxkuofp).

<a id="inc-d4ec64dbba06"></a>
## Timetonic — INC-D4EC64DBBA06

**P2 — Numérique, France et fuite via Metabase cohérents. Le compteur 67 fichiers doit être confronté à son contexte ; vecteur/impact restent unknown sans badge. Pas de nouvelle qualification dans les deux traces.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-31 | Numérique / Technologie / referenced | Fuite de données / reported | France métropolitaine | 1 |
| R2 | 2026-08-31 | Numérique / Technologie / referenced | Fuite de données / reported | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données chez TimeTonic impliquant l'exploitation d'une vulnérabilité de Metabase.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | des données ont été extraites puis publiées sur un forum spécialisé | unknown | FRENCHBREACHES |
| initial_access | vulnerability_exploitation | unknown | FRENCHBREACHES |

Volumes : 67 fichiers [claimed].

Types de données : aucun élément publié.

Systèmes : Metabase [unknown].

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-9d9815a5f2d59dfb` — FRENCHBREACHES — [Timetonic](https://frenchbreaches.com/alertes/timetonic-mt922eg42yopbt0z9va).

<a id="inc-c25397468c49"></a>
## Carte De Pêche — INC-C25397468C49

**P2 — Association, fuite et France cohérents. Le résumé mentionne des mineurs, mais l'indicateur de personnes vulnérables doit être contrôlé séparément des seuls types de données. Acteur sans statut ; 500 personnes à distinguer d'un éventuel échantillon.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Association / Syndicat / confirmed | Fuite de données / reported | France métropolitaine | 2 |
| R2 | 2026-08-30 | Association / Syndicat / confirmed | Fuite de données / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Association / Syndicat ; CYBERATTAQUE_ORG : confirmed / EXISTING_SECTOR → Association / Syndicat.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Association / Syndicat ; CYBERATTAQUE_ORG : confirmed / EXISTING_SECTOR → Association / Syndicat.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : CarteDePeche.fr : les données d’adhérents, dont des mineurs diffusées

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| threat_actor | Alduin | unknown | CYBERATTAQUE_ORG |

Volumes : 500 personnes [claimed].

Types de données : dates de naissance [unknown]; noms et prénoms [unknown]; adresses postales [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; SIREN / SIRET [unknown]; données personnelles [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : données personnelles.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-d1a4fce90cb663c6` — CYBERATTAQUE_ORG — [CarteDePeche.fr : les données d’adhérents, dont des mineurs diffusées](https://www.cyberattaque.org/cartedepeche-fr-les-donnees-dadherents-dont-des-mineurs-diffusees/).
- `ITM-90c715832f8f1e2e` — FRENCHBREACHES — [Carte De Pêche](https://frenchbreaches.com/alertes/carte-de-p-che-mtfr2p7gwirp63lb8q).

<a id="inc-82f1b88b7cc2"></a>
## CGT Éduc’Action — INC-82F1B88B7CC2

**Observation — Passage à Intrusion justifié par l'indisponibilité et la modification des sites décrites. Association et France cohérents. Ne pas déduire une fuite du seul défaut de source ; absence de données exposées structurées cohérente avec les preuves consultées.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Association / Syndicat / confirmed | Intrusion / confirmed | France métropolitaine | 2 |
| R2 | 2026-08-30 | Association / Syndicat / confirmed | Intrusion / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; CYBERATTAQUE_ORG : confirmed / EXISTING_SECTOR → Association / Syndicat.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : unknown / NO_ACTIVITY_EVIDENCE → Inconnu ; CYBERATTAQUE_ORG : confirmed / EXISTING_SECTOR → Association / Syndicat.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : CGT Éduc’Action Créteil victime d'une cyberattaque ayant provoqué l'indisponibilité de ses sites pendant plusieurs jours.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | Créteil | confirmed | CYBERATTAQUE_ORG |
| impact | Le piratage a entraîné une indisponibilité de plusieurs jours et la modification de contenus déjà publiés. | confirmed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-790d2923d5ed5cfa` — CYBERATTAQUE_ORG — [CGT Éduc’Action Créteil : deux sites piratés avant la rentrée](https://www.cyberattaque.org/cgt-educaction-creteil-deux-sites-pirates-avant-la-rentree/).
- `ITM-ae43ef50305a9615` — FRENCHBREACHES — [CGT Éduc’Action](https://frenchbreaches.com/alertes/cgt-duc-action-mth3fyv8l1c6dt5aovh).

<a id="inc-cfaaec3e334a"></a>
## Courir — INC-CFAAEC3E334A

**P2 — Intrusion peut être cohérente avec une compromission interne revendiquée ; la confirmation globale et le périmètre des données restent à vérifier. Secteur Commerce/France plausibles, LAPSUS revendiqué. Ne pas traiter automatiquement le changement de menace comme une erreur.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Commerce / Distribution / referenced | Intrusion / confirmed | France métropolitaine | 2 |
| R2 | 2026-08-30 | Commerce / Distribution / referenced | Intrusion / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Courir : une compromission massive de l’infrastructure interne après une cyberattaque

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| threat_actor | LAPSUS | claimed | FRENCHBREACHES |

Volumes : aucun élément publié.

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-73fbb34e125a5084` — CYBERATTAQUE_ORG — [Courir : une compromission massive de l’infrastructure interne après une cyberattaque](https://www.cyberattaque.org/courir-une-compromission-massive-de-linfrastructure-interne-apres-une-cyberattaque/).
- `ITM-74e3745e686a64b5` — FRENCHBREACHES — [Courir](https://frenchbreaches.com/alertes/courir-mtg0ctb51irigfs0gts).

<a id="inc-d63cee9e9005"></a>
## FFTir — INC-D63CEE9E9005

**P1 — Secteur Sport et territoire France corrigé au premier run. Vecteur exploitation de vulnérabilité marqué confirmed alors que la preuve dit que l'attaquant ignore l'existence d'une injection SQL ou d'autres failles. Qualification du vecteur à retirer/requalifier.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Sport / referenced | Fuite de données / confirmed | France métropolitaine | 1 |
| R2 | 2026-08-30 | Sport / referenced | Fuite de données / confirmed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Sport.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup `ITM-0867a5b8ab130b38 / ITM-7ddc5f6739f7709d` (FFTir / Footsider) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Sport.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : FFTir : les données de 300 000 licenciés mis en vente par un hacker

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| initial_access | vulnerability_exploitation | confirmed | CYBERATTAQUE_ORG |
| threat_actor | Vagrantly | claimed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : dates de naissance [unknown]; noms et prénoms [unknown]; adresses e-mail [unknown]; identifiants [unknown]; factures [claimed]; mots de passe [unknown]; numéros de téléphone [unknown]; adresses postales [unknown]; données bancaires [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-0867a5b8ab130b38` — CYBERATTAQUE_ORG — [FFTir : les données de 300 000 licenciés mis en vente par un hacker](https://www.cyberattaque.org/fftir-les-donnees-de-300-000-licencies-mis-en-vente-par-un-hacker/).

<a id="inc-4a2f32292a93"></a>
## SDIS de la Moselle — INC-4A2F32292A93

**P2 — Secteur public/France et fuite revendiquée cohérents. Volume 6 434 personnes sans statut ; types de données absents. Aucune nouvelle trace de qualification.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Administration / Collectivité / confirmed | Fuite de données / claimed | France métropolitaine | 1 |
| R2 | 2026-08-30 | Administration / Collectivité / confirmed | Fuite de données / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Cyberattaque revendiquée contre le SDIS de la Moselle impliquant la fuite de données de 6 434 personnes.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | Moselle | claimed | FRENCHBREACHES |

Volumes : 6 434 personnes [unknown].

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-ac58cd9639615c55` — FRENCHBREACHES — [SDIS de la Moselle](https://frenchbreaches.com/alertes/sdis-de-la-moselle-mtezsxcrwb76ft4xd69).

<a id="inc-fc866dcd1981"></a>
## SDIS de la Somme — INC-FC866DCD1981

**Observation — Passage à Intrusion cohérent avec la revendication d'accès administrateur ; secteur public et France cohérents. La catégorie montants nécessite une preuve d'exposition et disparaît au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Administration / Collectivité / confirmed | Intrusion / claimed | France métropolitaine | 1 |
| R2 | 2026-08-30 | Administration / Collectivité / confirmed | Intrusion / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Compromission des accès administrateur du SDIS de la Somme revendiquée sur un forum cybercriminel.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Les accès administrateur ont été compromis. | claimed | FRENCHBREACHES |

Volumes : aucun élément publié.

Types de données : montants [claimed].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : montants.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-129989f0c862b9cd` — FRENCHBREACHES — [SDIS de la Somme](https://frenchbreaches.com/alertes/sdis-de-la-somme-mtezxlwpehjyx3v67q7).

<a id="inc-bd3012e03337"></a>
## SDIS de l’Essonne — INC-BD3012E03337

**Observation — Passage à Intrusion cohérent avec les accès administrateur revendiqués. Secteur public et France cohérents. Fiche pauvre en faits, à conserver comme revendication et sans inventer de volumes ou de vecteur.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Administration / Collectivité / confirmed | Intrusion / claimed | France métropolitaine | 1 |
| R2 | 2026-08-30 | Administration / Collectivité / confirmed | Intrusion / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Une cyberattaque a été revendiquée contre le SDIS de l’Essonne avec une compromission d'accès administrateur.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : aucun élément publié.

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-75d5a18e7852e12d` — FRENCHBREACHES — [SDIS de l’Essonne](https://frenchbreaches.com/alertes/sdis-de-l-essonne-mtezzdc6zwkkibexpe8).

<a id="inc-8b71255fd2c5"></a>
## SDIS des Bouches-du-Rhône — INC-8B71255FD2C5

**P2 — Secteur public, France et fuite revendiquée cohérents. 3 699 personnes et résumé arrondi ; statut du compteur inconnu masqué. Types absents, sans nouvelle trace sur les deux runs.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Administration / Collectivité / confirmed | Fuite de données / claimed | France métropolitaine | 1 |
| R2 | 2026-08-30 | Administration / Collectivité / confirmed | Fuite de données / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données revendiquée contre le SDIS des Bouches-du-Rhône, affectant potentiellement près de 3 700 personnes.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Une base de données a été récupérée et diffusée. | claimed | FRENCHBREACHES |

Volumes : 3 699 personnes [unknown].

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-7660a36ebd2eaa57` — FRENCHBREACHES — [SDIS des Bouches-du-Rhône](https://frenchbreaches.com/alertes/sdis-des-bouches-du-rh-ne-mtez1nua8138brrfb7i).

<a id="inc-7ea20e0eebb7"></a>
## SDIS des Vosges — INC-7EA20E0EEBB7

**P2 — Secteur public/France et fuite revendiquée cohérents. 3 067 personnes sans badge de preuve ; acteur et types manquants. Pas de défaut de fusion établi.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Administration / Collectivité / confirmed | Fuite de données / claimed | France métropolitaine | 1 |
| R2 | 2026-08-30 | Administration / Collectivité / confirmed | Fuite de données / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Cyberattaque revendiquée contre le SDIS des Vosges avec une fuite de données touchant 3 067 personnes.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | Vosges | claimed | FRENCHBREACHES |

Volumes : 3 067 personnes [unknown].

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-7a51bf1a54f771d3` — FRENCHBREACHES — [SDIS des Vosges](https://frenchbreaches.com/alertes/sdis-des-vosges-mtezvi2a2rg01mrtvrp).

<a id="inc-c6401641511b"></a>
## SDIS du Bas-Rhin — INC-C6401641511B

**P2 — Secteur public/France et fuite revendiquée cohérents. 3 584 personnes sans statut ; résumé moins prudent que le statut global. Types absents.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Administration / Collectivité / confirmed | Fuite de données / claimed | France métropolitaine | 1 |
| R2 | 2026-08-30 | Administration / Collectivité / confirmed | Fuite de données / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données au SDIS du Bas-Rhin avec 3 584 personnes potentiellement concernées.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | Bas-Rhin | claimed | FRENCHBREACHES |

Volumes : 3 584 personnes [unknown].

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-d776be6f7bde12f9` — FRENCHBREACHES — [SDIS du Bas-Rhin](https://frenchbreaches.com/alertes/sdis-du-bas-rhin-mtezqd7tc7tk1exr3is).

<a id="inc-d910ad541b6b"></a>
## SDIS du Gard — INC-D910AD541B6B

**P2 — Menace passée à Intrusion tandis que le résumé évoque plus de 3 100 personnes : nature exacte à vérifier, pas de conclusion automatique. Secteur public/France cohérents. Aucun volume ou type structuré.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-30 | Administration / Collectivité / confirmed | Intrusion / claimed | France métropolitaine | 1 |
| R2 | 2026-08-30 | Administration / Collectivité / confirmed | Intrusion / claimed | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Cyberattaque revendiquée contre le SDIS du Gard, touchant plus de 3 100 personnes.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : aucun élément publié.

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-608546810aba3569` — FRENCHBREACHES — [SDIS du Gard](https://frenchbreaches.com/alertes/sdis-du-gard-mteyy43opeesk6j4mr).

<a id="inc-d9a0c6dbd358"></a>
## Easypara — INC-D9A0C6DBD358

**P2 — Commerce/France et fuite via prestataire cohérents. Tiers enregistré Shipp, alors que l'article public actuel nomme Shipup : vérifier l'ancien contenu puis corriger l'identité. Évolution vulnérabilité corrigée sans statut. Catégories de commandes perdues au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-29 | Commerce / Distribution / referenced | Fuite de données / reported | France métropolitaine | 2 |
| R2 | 2026-08-29 | Commerce / Distribution / referenced | Fuite de données / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Une faille Metabase chez le prestataire Shipp expose les coordonnées de certains clients d'Easypara.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| evolution | vulnérabilité corrigée | unknown | CYBERATTAQUE_ORG |
| third_party | Shipp | unknown | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : informations de commandes [unknown]; adresses e-mail [reported]; numéros de téléphone [reported]; noms et prénoms [reported]; données personnelles [unknown].

Systèmes : Metabase [unknown].

Périmètres : données clients [unknown].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : informations de commandes, données personnelles.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-c4c6d095612ff2f2` — CYBERATTAQUE_ORG — [Easypara : une faille Metabase chez son prestataire expose les coordonnées de certains clients](https://www.cyberattaque.org/easypara-une-faille-metabase-chez-son-prestataire-expose-les-coordonnees-de-certains-clients/).
- `ITM-fdbdd6afa926ce98` — FRENCHBREACHES — [Easypara](https://frenchbreaches.com/alertes/easypara-mtejoktuc67v6di63t4).

<a id="inc-eb3ac8cb9892"></a>
## La Maison Des Travaux — INC-EB3AC8CB9892

**P2 — Revendication Qilin conservée, mais acteur sans badge et résumé absent. Secteur Commerce / Distribution à examiner selon le rôle réel de courtage en travaux, sans correction automatique. Fiche très pauvre ; candidats BumFot sans rapport en attente.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-29 | Commerce / Distribution / reported | Ransomware / reported | France métropolitaine | 1 |
| R2 | 2026-08-29 | Commerce / Distribution / reported | Ransomware / reported | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : RANSOMWARE_LIVE : reported / SOURCE_SECTOR_RAW → Commerce / Distribution.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup `ITM-ecf737579abef294 / ITM-386e8b0cef884341` (La Maison Des Travaux / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R1, dédup `ITM-ecf737579abef294 / ITM-dcea59a6972cab15` (La Maison Des Travaux / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R2, secteur : RANSOMWARE_LIVE : reported / SOURCE_SECTOR_RAW → Commerce / Distribution.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-ecf737579abef294 / ITM-386e8b0cef884341` (La Maison Des Travaux / BumFot) : UNKNOWN, organisation UNKNOWN, incident UNKNOWN, confiance 0.5.
- R2, dédup `ITM-ecf737579abef294 / ITM-dcea59a6972cab15` (La Maison Des Travaux / BumFot) : UNKNOWN, organisation UNKNOWN, incident UNKNOWN, confiance 0.5.

**Qualifications du volet R2**

Résumé : absent

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| discovered_date | 2026-08-29 | unknown | RANSOMWARE_LIVE |
| threat_actor | qilin | unknown | RANSOMWARE_LIVE |

Volumes : aucun élément publié.

Types de données : aucun élément publié.

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-ecf737579abef294` — RANSOMWARE_LIVE — [La Maison Des Travaux revendiqué par qilin](http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/site/blog?uuid=fcb05123-2685-418f-8dd5-4c29a26ce6cb).

<a id="inc-39643434bf76"></a>
## La Ville de Tarnos — INC-39643434BF76

**P2 — Secteur public/France et demande de rançon étayés. Distinguer rançon/extorsion et chiffrement, qui n'est pas démontré par cette seule preuve. Vol de données seulement possible ; catégories sans statut et risque de suraffirmation des indicateurs.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-29 | Administration / Collectivité / confirmed | Ransomware / confirmed | France métropolitaine | 2 |
| R2 | 2026-08-29 | Administration / Collectivité / confirmed | Ransomware / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Administration / Collectivité ; CYBERATTAQUE_ORG : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : inferred / ORGANISATION_NAME_RULE → Administration / Collectivité ; CYBERATTAQUE_ORG : confirmed / EXISTING_SECTOR → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : La Ville de Tarnos a été victime d'une cyberattaque avec demande de rançon et possible vol de données personnelles.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| fine_location | Tarnos, Landes | confirmed | CYBERATTAQUE_ORG |
| impact | demande de rançon | unknown | FRENCHBREACHES |

Volumes : aucun élément publié.

Types de données : adresses e-mail [unknown]; numéros de téléphone [unknown]; données personnelles [unknown].

Systèmes : serveur de messagerie [confirmed].

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : données personnelles.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-2d8408666ad4a2ab` — CYBERATTAQUE_ORG — [Tarnos : une rançon réclamée à la mairie pour récupérer ses données sensibles](https://www.cyberattaque.org/mairie-tarnos-rancon-cyberattaque/).
- `ITM-6e2c2cd9e5c3ed70` — FRENCHBREACHES — [La Ville de Tarnos](https://frenchbreaches.com/alertes/la-ville-de-tarnos-mtf0splyuy8ncg1qzd).

<a id="inc-92b98e38166e"></a>
## LCommerce — INC-92B98E38166E

**P2 — Commerce, fuite et France provenant de BLF ; aucun résumé, acteur, volume ou vecteur. Statut de menace unknown malgré un signal BLF confirmé. Types présents mais sans badges ; pas de qualification LLM, source hors cible sémantique.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-29 | Commerce / Distribution / referenced | Fuite de données / unknown | France métropolitaine | 1 |
| R2 | 2026-08-29 | Commerce / Distribution / referenced | Fuite de données / unknown | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : BONJOURLAFUITE : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : BONJOURLAFUITE : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : absent

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : aucun élément publié.

Types de données : noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-e91886c964872bf8` — BONJOURLAFUITE — [LCommerce](https://bonjourlafuite.eu.org/img/lcommerce.png).

<a id="inc-3c5b9e546782"></a>
## Marie Blachère — INC-3C5B9E546782

**P2 — Fuite de données salariés et France cohérentes. Acteur l’auteur de la publication trop générique, risque de fraude affiché confirmed. Données RH et contrats perdus au rendu. Secteur Commerce à apprécier selon l'activité retenue dans la taxonomie.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-29 | Commerce / Distribution / referenced | Fuite de données / reported | France métropolitaine | 2 |
| R2 | 2026-08-29 | Commerce / Distribution / referenced | Fuite de données / reported | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Commerce / Distribution ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Commerce / Distribution.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Une base de données de Marie Blachère contenant des données sensibles de salariés a été mise en vente sur un forum cybercriminel.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Risque élevé d'usurpation d'identité et de fraude. | confirmed | CYBERATTAQUE_ORG |
| threat_actor | l’auteur de la publication | unknown | FRENCHBREACHES |

Volumes : aucun élément publié.

Types de données : données RH [claimed]; contrats [unknown]; noms et prénoms [unknown]; numéros de sécurité sociale [unknown].

Systèmes : aucun élément publié.

Périmètres : base RH d'employés [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : données RH, contrats.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-bcdc630a43bb7e0a` — CYBERATTAQUE_ORG — [Marie Blachère : les données RH d’employés revendiqués dans une fuite](https://www.cyberattaque.org/marie-blachere-les-donnees-rh-demployes-revendiques-dans-une-fuite/).
- `ITM-014806ad25b64a9f` — FRENCHBREACHES — [Marie Blachère](https://frenchbreaches.com/alertes/marie-blach-re-mtemu3hpnhmwfkgvnyf).

<a id="inc-68bce0c36286"></a>
## Zéro Logement Vacant — INC-68BCE0C36286

**P1 — Secteur public/France cohérents. Vecteur exploitation de vulnérabilité contredit par sa preuve négative ; déroulé confirmé à tort pour des déclarations d'attaquant. Résumé affirme 48 millions de personnes sans réserve suffisante. Plusieurs volumes hétérogènes et échantillons non distingués.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-29 | Administration / Collectivité / referenced | Fuite de données / confirmed | France métropolitaine | 2 |
| R2 | 2026-08-29 | Administration / Collectivité / referenced | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Administration / Collectivité ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Administration / Collectivité.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Administration / Collectivité ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Administration / Collectivité.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Zéro Logement Vacant a subi une fuite massive de données, exposant 48 millions de personnes.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | exposition de données sensibles, facilitant des actions de phishing, d’usurpation ou de fraude. | confirmed | CYBERATTAQUE_ORG |
| initial_access | vulnerability_exploitation | claimed | CYBERATTAQUE_ORG |
| threat_actor | ZeroBytes | claimed | CYBERATTAQUE_ORG |

Volumes : 148 929 194 lignes [claimed]; 500 lignes [unknown]; 66,9 millions de lignes [unknown]; 47,9 millions de personnes [claimed]; 82 millions de lignes [unknown].

Types de données : identifiants [unknown]; dates de naissance [confirmed]; adresses postales [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; mots de passe [unknown]; SIREN / SIRET [unknown].

Systèmes : Metabase [claimed].

Périmètres : fichiers DGFiP et DataFoncier [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 2 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-ac5aea25b29b9175` — CYBERATTAQUE_ORG — [Zéro Logement Vacant : 48 millions de personnes exposées dans une fuite massive](https://www.cyberattaque.org/zero-logement-vacant-48-millions-de-personnes-exposees-dans-une-fuite-massive/).
- `ITM-a51172ec15657a8a` — FRENCHBREACHES — [Zéro Logement Vacant (Gouv)](https://frenchbreaches.com/alertes/z-ro-logement-vacant-gouv-mtdj0b0p5ycvbr6ajlw).

<a id="inc-195f06b69c3a"></a>
## Actis Location — INC-195F06B69C3A

**P1 — Secteur Services aux entreprises et France plausibles. Vecteur phishing marqué confirmed à partir d'un risque futur de phishing/fraude, pas de la cause de l'attaque. Fuite documentée ; contrats, montants, comptabilité et commandes perdus au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-28 | Services aux entreprises / referenced | Fuite de données / claimed | France métropolitaine | 2 |
| R2 | 2026-08-28 | Services aux entreprises / referenced | Fuite de données / claimed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Services aux entreprises ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Services aux entreprises.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Services aux entreprises ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Services aux entreprises.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Actis Location subit une fuite de 666 155 fichiers, représentant 464 Go de données, après une cyberattaque.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 464 Go | unknown | CYBERATTAQUE_ORG |
| impact | Exposition de données personnelles et commerciales sensibles | confirmed | CYBERATTAQUE_ORG |
| initial_access | phishing | confirmed | CYBERATTAQUE_ORG |
| threat_actor | ChimeraZ | claimed | CYBERATTAQUE_ORG |

Volumes : 666 155 fichiers [unknown].

Types de données : données bancaires [unknown]; factures [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; noms et prénoms [unknown]; adresses postales [unknown]; contrats [unknown]; montants [unknown]; identifiants [unknown]; mots de passe [unknown]; données comptables [unknown].

Systèmes : aucun élément publié.

Périmètres : aucun élément publié.

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : contrats, montants, données comptables.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-4cc8816fbf2bf2c7` — CYBERATTAQUE_ORG — [Actis Location : 464 Go de factures, devis et RIB de clients exposés après une cyberattaque](https://www.cyberattaque.org/actis-location-factures-devis-et-rib-de-clients-exposes-apres-une-cyberattaque/).
- `ITM-df47b6d6c045ee30` — FRENCHBREACHES — [Actis Location (BlgCloud)](https://frenchbreaches.com/alertes/actis-location-blgcloud-mtck051io55urdgqnxe).

<a id="inc-70b5b8b5751d"></a>
## Frères Toque — INC-70B5B8B5751D

**P2 — Secteur restauration, fuite et France cohérents ; regroupement des sources conservé. Nombreuses comparaisons LLM avec BumFot sans lien, certaines en ERROR. Impact sans badge et catégories de commandes/données personnelles perdues au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-28 | Hébergement / Tourisme / Restauration / referenced | Fuite de données / reported | France métropolitaine | 3 |
| R2 | 2026-08-28 | Hébergement / Tourisme / Restauration / referenced | Fuite de données / reported | France métropolitaine | 3 |

**Chaîne de qualification et déduplication**

- R1, secteur : BONJOURLAFUITE : referenced / REFERENCE_EXACT → Hébergement / Tourisme / Restauration ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Hébergement / Tourisme / Restauration ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Hébergement / Tourisme / Restauration.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup `ITM-041e36c542f6c37f / ITM-386e8b0cef884341` (Frères Toque / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R1, dédup `ITM-041e36c542f6c37f / ITM-dcea59a6972cab15` (Frères Toque / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.
- R1, dédup `ITM-776a3c8116ba0604 / ITM-dcea59a6972cab15` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.
- R1, dédup `ITM-ec6ad7ad1bc83e4d / ITM-386e8b0cef884341` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.75.
- R2, secteur : BONJOURLAFUITE : referenced / REFERENCE_EXACT → Hébergement / Tourisme / Restauration ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Hébergement / Tourisme / Restauration ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Hébergement / Tourisme / Restauration.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-041e36c542f6c37f / ITM-386e8b0cef884341` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-041e36c542f6c37f / ITM-dcea59a6972cab15` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-776a3c8116ba0604 / ITM-dcea59a6972cab15` (Frères Toque / BumFot) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.7.
- R2, dédup `ITM-ec6ad7ad1bc83e4d / ITM-386e8b0cef884341` (Frères Toque / BumFot) : ERROR, organisation UNKNOWN, incident UNKNOWN, confiance 0.0.

**Qualifications du volet R2**

Résumé : Frères Toque victime d'un incident de sécurité compromettant des données personnelles de clients.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | compromission de données personnelles de clients | unknown | FRENCHBREACHES |

Volumes : aucun élément publié.

Types de données : informations de commandes [unknown]; noms et prénoms [unknown]; adresses e-mail [reported]; numéros de téléphone [unknown]; adresses postales [unknown]; données personnelles [unknown]; Adresse [unknown].

Systèmes : aucun élément publié.

Périmètres : données clients [unknown]; noms [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : informations de commandes, données personnelles.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-041e36c542f6c37f` — BONJOURLAFUITE — [Frères Toque](https://bonjourlafuite.eu.org/img/freres-toque.png).
- `ITM-ec6ad7ad1bc83e4d` — CYBERATTAQUE_ORG — [Frères Toque : données clients et historiques de commandes exposés après une cyberattaque](https://www.cyberattaque.org/freres-toque-donnees-clients-et-historiques-de-commandes-exposes-apres-une-cyberattaque/).
- `ITM-776a3c8116ba0604` — FRENCHBREACHES — [Frères Toque](https://frenchbreaches.com/alertes/fr-res-toque-mtejkm4gb9g1viudmhf).

<a id="inc-a3c6a92f895d"></a>
## Lingor — INC-A3C6A92F895D

**P2 — Finance/France plausibles. Ransomware confirmé doit être confronté à une preuve technique propre, le résumé seul ne l'établit pas. Pas de champ acteur/vecteur/volume. Comparaisons avec Jinko justement distinctes ; données de commandes/montants perdues au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-28 | Finance / Assurance / referenced | Ransomware / confirmed | France métropolitaine | 2 |
| R2 | 2026-08-28 | Finance / Assurance / referenced | Ransomware / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Finance / Assurance ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Finance / Assurance.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup `ITM-050f3ab72fc2e7e3 / ITM-73d8dbdd9d0635b0` (Lingor / Jinko) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.
- R1, dédup `ITM-ed7e34492c1a1059 / ITM-46f2bb70da9e82d5` (Lingor / Jinko) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Finance / Assurance ; FRENCHBREACHES : referenced / REFERENCE_EXACT → Finance / Assurance.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup `ITM-050f3ab72fc2e7e3 / ITM-73d8dbdd9d0635b0` (Lingor / Jinko) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.5.
- R2, dédup `ITM-ed7e34492c1a1059 / ITM-46f2bb70da9e82d5` (Lingor / Jinko) : DIFFERENT, organisation DIFFERENT, incident DIFFERENT, confiance 0.8.

**Qualifications du volet R2**

Résumé : Lingor a subi une cyberattaque ayant potentiellement exposé des données sensibles de ses clients.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| — | Aucun scalaire supplémentaire | — | — |

Volumes : aucun élément publié.

Types de données : données bancaires [unknown]; pièces d'identité [unknown]; informations de commandes [unknown]; facturation [unknown]; noms et prénoms [unknown]; adresses e-mail [unknown]; numéros de téléphone [unknown]; montants [unknown].

Systèmes : aucun élément publié.

Périmètres : base de données clients [confirmed]; dossiers de rachat [confirmed]; données clients [unknown].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : informations de commandes, montants.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-050f3ab72fc2e7e3` — CYBERATTAQUE_ORG — [Lingor : des données sensibles de clients potentiellement exposées après une cyberattaque](https://www.cyberattaque.org/lingor-des-donnees-sensibles-de-clients-potentiellement-exposees-apres-une-cyberattaque/).
- `ITM-ed7e34492c1a1059` — FRENCHBREACHES — [Lingor](https://frenchbreaches.com/alertes/lingor-mtcnn1mg1ipiqk7j53o).

<a id="inc-6816c47ec89b"></a>
## Minea — INC-6816C47EC89B

**P2 — Numérique/France et fuite revendiquée cohérents. Distinguer 533 162 profils/e-mails et 81,6 millions d'événements ; l'arrondi 81 millions répète le même ordre de grandeur. Résumé doit préserver le statut revendiqué.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-28 | Numérique / Technologie / referenced | Fuite de données / claimed | France métropolitaine | 2 |
| R2 | 2026-08-28 | Numérique / Technologie / referenced | Fuite de données / claimed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : referenced / REFERENCE_EXACT → Numérique / Technologie ; CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Numérique / Technologie.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Minea a subi une fuite massive de 533 162 profils et 81,6 millions d'activités.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| data_volume | 105 Go | unknown | CYBERATTAQUE_ORG |
| impact | Exposition de 533 162 profils et plus de 81 millions d'enregistrements d'activité. | claimed | FRENCHBREACHES |
| threat_actor | BoneT4p2ndAcc | claimed | CYBERATTAQUE_ORG |

Volumes : 81,6 millions d’enregistrements [claimed]; 81 millions d'enregistrements [claimed]; 533 162 profils dédupliqués  et autant d’adresses e-mail uniques [unknown].

Types de données : adresses e-mail [unknown]; identifiants [unknown]; adresses IP [unknown].

Systèmes : aucun élément publié.

Périmètres : base clients [confirmed]; activités [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 2 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-2dabd2e0f9227fb6` — CYBERATTAQUE_ORG — [Minea : 533 000 profils et 81,6 millions d’activités exposés dans une fuite massive](https://www.cyberattaque.org/minea-533-000-profils-et-816-millions-dactivites-exposes-dans-une-fuite-massive/).
- `ITM-1219cba905b728f5` — FRENCHBREACHES — [Minea](https://frenchbreaches.com/alertes/minea-mtdex0abbtr1kt0c8gd).

<a id="inc-e39645df5e4e"></a>
## Qare — INC-E39645DF5E4E

**P2 — Santé et territoire France récupéré au premier run. Intrusion accompagnée d'images accessibles : menace à apprécier en conservant le caractère revendiqué. Photos d'enfants affirmées dans le résumé à partir d'une preuve JPEG trop générale ; contrôler sujet, réserve et indicateur de vulnérabilité.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-28 | Santé / referenced | Intrusion / reported | France métropolitaine | 1 |
| R2 | 2026-08-28 | Santé / referenced | Intrusion / reported | France métropolitaine | 1 |

**Chaîne de qualification et déduplication**

- R1, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Santé.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : CYBERATTAQUE_ORG : referenced / REFERENCE_EXACT → Santé.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Intrusion dans Qare, plateforme de téléconsultation, entraînant l'exposition de photos d'enfants.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Exposition de données sensibles, y compris des photos d'enfants. | unknown | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : photographies [claimed]; noms et prénoms [unknown].

Systèmes : aucun élément publié.

Périmètres : données structurées [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 0 étape(s) ; chronologie : 0 entrée(s).

Catégories perdues au rendu : aucune détectée.

Alertes du produit : aucune.

**Sources de cette fiche**

- `ITM-dbaa1b5710c8ec69` — CYBERATTAQUE_ORG — [Qare : une intrusion inquiétante signalée par un hacker, des photos d’enfants exposées](https://www.cyberattaque.org/qare-une-intrusion-inquietante-signalee-par-un-hacker-des-photos-denfants-exposees/).

<a id="inc-f6e4fedc0fe9"></a>
## Ultra Premium Direct — INC-F6E4FEDC0FE9

**P2 — Secteur Agriculture / Agroalimentaire, France et fuite via Klark.ai plausibles. La preuve faille de sécurité chez le prestataire ne documente pas à elle seule une vulnérabilité exploitée précise. Commandes et données personnelles perdues au rendu.**

| État | Date de publication retenue | Secteur / statut | Menace / statut | Territoire | Observations |
|---|---|---|---|---|---|
| R1 | 2026-08-28 | Agriculture / Agroalimentaire / inferred | Fuite de données / confirmed | France métropolitaine | 2 |
| R2 | 2026-08-28 | Agriculture / Agroalimentaire / inferred | Fuite de données / confirmed | France métropolitaine | 2 |

**Chaîne de qualification et déduplication**

- R1, secteur : FRENCHBREACHES : inferred / ACTIVITY_RULE → Agriculture / Agroalimentaire ; CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Agriculture / Agroalimentaire.
- R1, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R1, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.
- R2, secteur : FRENCHBREACHES : inferred / ACTIVITY_RULE → Agriculture / Agroalimentaire ; CYBERATTAQUE_ORG : inferred / ACTIVITY_RULE → Agriculture / Agroalimentaire.
- R2, extraction : 0 appel(s) source_facts tracé(s), faits historiques, cache ou extraction déterministe ; pas de nouvel appel source_facts tracé.
- R2, dédup : aucune paire LLM dans le journal de ce run ; regroupement déterministe/historique conservé.

**Qualifications du volet R2**

Résumé : Fuite de données personnelles chez Ultra Premium Direct suite à une cyberattaque sur un prestataire technique.

| Champ | Valeur publiée | Statut conservé | Source |
|---|---|---|---|
| impact | Des informations clients exposées. | confirmed | FRENCHBREACHES |
| initial_access | vulnerability_exploitation | confirmed | CYBERATTAQUE_ORG |
| third_party | Klark.ai | confirmed | CYBERATTAQUE_ORG |

Volumes : aucun élément publié.

Types de données : numéros de téléphone [unknown]; noms et prénoms [unknown]; adresses e-mail [unknown]; informations de commandes [unknown]; données personnelles [unknown].

Systèmes : Klark.ai [confirmed].

Périmètres : données clients [unknown]; données clients d’Ultra Premium Direct [confirmed].

Vulnérabilités : aucun élément publié.

Déroulé : 1 étape(s) ; chronologie : 1 entrée(s).

Catégories perdues au rendu : informations de commandes, données personnelles.

Alertes du produit : THREAT_CONFLICT_RESOLVED.

**Sources de cette fiche**

- `ITM-548df1d58425f71a` — CYBERATTAQUE_ORG — [Ultra Premium Direct : les données clients extraites après le piratage d’un prestataire](https://www.cyberattaque.org/ultra-premium-direct-les-donnees-clients-extraites-apres-le-piratage-dun-prestataire/).
- `ITM-389a991087b537a5` — FRENCHBREACHES — [Ultra Premium Direct](https://frenchbreaches.com/alertes/ultra-premium-direct-mtckovbzd1f2t3n126h).
