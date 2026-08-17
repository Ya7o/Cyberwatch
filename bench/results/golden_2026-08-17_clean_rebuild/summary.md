# Golden qualification — clean rebuild vs 3 LLM JSON

- Golden cases: **100**
- Clean rebuild run: **31995251021**

## Scores

| Source | Matched | Secteur accuracy | Menace accuracy | Localisation accuracy |
|---|---:|---:|---:|---:|
| CYBERWATCH_DB | 87/100 | 52.9% | 75.9% | 63.2% |
| FRENCHBREACHES_LLM_JSON | 60/100 | 65.0% | 76.7% | 100.0% |
| CYBERATTAQUE_ORG_LLM_JSON | 66/100 | 69.7% | 60.6% | 89.4% |
| VEILLE_LLM_REUNION_MAYOTTE_JSON | 1/100 | 100.0% | 100.0% | 100.0% |

## Delta LLM vs DB sur cas communs

| Challenger | Champ | Cas communs | Delta accuracy | Gains | Régressions |
|---|---|---:|---:|---:|---:|
| FRENCHBREACHES_LLM_JSON | Secteur | 58 | +6.9 pp | 14 | 10 |
| FRENCHBREACHES_LLM_JSON | Menace | 58 | +3.4 pp | 5 | 3 |
| FRENCHBREACHES_LLM_JSON | Localisation | 58 | +29.3 pp | 17 | 0 |
| CYBERATTAQUE_ORG_LLM_JSON | Secteur | 66 | +21.2 pp | 24 | 10 |
| CYBERATTAQUE_ORG_LLM_JSON | Menace | 66 | -10.6 pp | 11 | 18 |
| CYBERATTAQUE_ORG_LLM_JSON | Localisation | 66 | +34.8 pp | 26 | 3 |
| VEILLE_LLM_REUNION_MAYOTTE_JSON | Secteur | 1 | +0.0 pp | 0 | 0 |
| VEILLE_LLM_REUNION_MAYOTTE_JSON | Menace | 1 | +0.0 pp | 0 | 0 |
| VEILLE_LLM_REUNION_MAYOTTE_JSON | Localisation | 1 | +0.0 pp | 0 | 0 |
