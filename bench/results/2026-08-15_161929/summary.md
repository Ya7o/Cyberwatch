# Baseline fraîche — qualification LLM

Run GitHub Actions : `31884301311`
Job : `95011231267`
Commit benchmarké : `18366cca995306404208bf735c11a2916ca1ff07`
As of : `2026-08-15T16:19:29.391739+04:00`
Fenêtre : `2026-01-01` → `2026-08-15`
Modèle : `gpt-5-nano`
Prompt : `2026-08-15.1`
Échantillon : 30 derniers items normalisés par source, 4 sources, `VEILLE_LLM` exclue.

## Collecte

| Source | Sample | Dates du sample | Statut | Raw | Valides |
|---|---:|---|---|---:|---:|
| FRENCHBREACHES | 30 | 2026-08-07 → 2026-08-15 | OK | 100 | 100 |
| BONJOURLAFUITE | 30 | 2026-06-18 → 2026-08-13 | OK | 517 | 315 |
| CYBERATTAQUE_ORG | 30 | 2026-08-07 → 2026-08-15 | OK | 409 | 391 |
| RANSOMWARE_LIVE | 30 | 2026-07-09 → 2026-08-12 | OK | 175 | 175 |

## T0 → T1

| Source | Champ | N | Inconnu T0 | % T0 | Qualifiés LLM | Inconnu T1 | % T1 | Transformation des inconnus |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| FRENCHBREACHES | Sector | 30 | 22 | 73.3% | 3 | 19 | 63.3% | 13.6% |
| FRENCHBREACHES | Location | 30 | 30 | 100.0% | 0 | 30 | 100.0% | 0.0% |
| BONJOURLAFUITE | Sector | 30 | 23 | 76.7% | 4 | 19 | 63.3% | 17.4% |
| BONJOURLAFUITE | Location | 30 | 30 | 100.0% | 0 | 30 | 100.0% | 0.0% |
| CYBERATTAQUE_ORG | Sector | 30 | 0 | 0.0% | 0 | 0 | 0.0% | n/a |
| CYBERATTAQUE_ORG | Location | 30 | 30 | 100.0% | 0 | 30 | 100.0% | 0.0% |
| RANSOMWARE_LIVE | Sector | 30 | 13 | 43.3% | 1 | 12 | 40.0% | 7.7% |
| RANSOMWARE_LIVE | Location | 30 | 0 | 0.0% | 0 | 0 | 0.0% | n/a |
| **TOTAL** | **Sector** | **120** | **58** | **48.3%** | **8** | **50** | **41.7%** | **13.8%** |
| **TOTAL** | **Location** | **120** | **90** | **75.0%** | **0** | **90** | **75.0%** | **0.0%** |

Sur les deux champs cumulés, 148 cellules étaient `Inconnu` à T0 et 140 le restent à T1 : 8/148 transformées, soit 5.4%.

## Usage LLM

- Candidats : 103
- Appels tentés : 103
- Appels réussis : 102
- Appels invalides/échoués : 1
- Succès technique : 99.0%
- Tokens : 81 068
- Coût estimé : `$0.006617`
- Durée LLM : 125.9 s
- Items effectivement modifiés : 8

## Revue métier des 8 changements

La colonne `Verdict` juge la valeur sectorielle produite, avec vérification externe officielle lorsque nécessaire. La colonne `Evidence_prompt` juge séparément si le contexte fourni au modèle suffisait à justifier sa décision selon le contrat actuel « texte fourni uniquement ».

| Source | Organisation | T0 | T1 | Verdict sémantique | Evidence_prompt |
|---|---|---|---|---|---|
| FRENCHBREACHES | Scalingo | Inconnu | Numérique / Technologie | Correct | Suffisante |
| FRENCHBREACHES | Gédimat | Inconnu | Services aux entreprises | Incorrect | Insuffisante |
| FRENCHBREACHES | Bureau Vallée | Inconnu | Commerce / Distribution | Correct | Suffisante |
| BONJOURLAFUITE | Intermarché | Inconnu | Commerce / Distribution | Correct | Insuffisante : le contexte brut ne décrit pas l'activité |
| BONJOURLAFUITE | Bloctel | Inconnu | Numérique / Technologie | Incorrect | Insuffisante |
| BONJOURLAFUITE | LaSanté.net | Inconnu | Santé | Correct | Faible : surtout inféré du nom |
| BONJOURLAFUITE | Magasins U | Inconnu | Commerce / Distribution | Correct | Faible : surtout inféré du nom |
| RANSOMWARE_LIVE | Savills France | Inconnu | Numérique / Technologie | Incorrect | Insuffisante |

Precision sémantique observée sur les valeurs injectées : **5/8 = 62.5%**.
Sous le contrat strict du prompt (preuve dans le contexte, pas de connaissance générale), la conformité probante est inférieure à cette precision sémantique.

## Conclusion baseline

- Le mécanisme API/Structured Output est fonctionnel : 102/103 appels valides.
- Le gain automatique sur le secteur est réel mais faible : 58 inconnus → 50, soit 13.8% des secteurs inconnus transformés.
- Le gain localisation est nul : 90 inconnus → 90.
- La precision métier des 8 secteurs injectés n'est pas suffisante pour considérer le réglage courant comme fiable : 3 erreurs observées sur 8 transformations.
- Le prochain axe doit être la qualité/preuve de qualification, pas l'augmentation aveugle du nombre de valeurs remplies.
