# Audit de clôture — enrichissement incident

Head audité: `e22173230d57adcd1e948c3da6a2e502d3ab917b`

Verdict automatique périmètre: **NOT CLOSABLE**

## Couverture

| Source | Rows | Summary | Initial access | Attack flow | Impact |
|---|---:|---:|---:|---:|---:|
| CYBERATTAQUE_ORG | 384 | 1 | 0 | 63 | 28 |
| FRENCHBREACHES | 100 | 0 | 0 | 8 | 12 |

## Contrôles

- SourceFacts orphelins: 0
- Item_ID dupliqués dans SourceFacts: 0
- Initial_Access hors taxonomie: 0
- Attack flow malformés: 0
- Attack flow sans preuve: 0
- Candidats langage hypothétique dans attack flow: 10
- Candidats remédiation dans attack flow: 1
- Gaps projection dashboard: {'fact_missing_entirely': 1}
- Tests ciblés rc=4; check rc=0; repeat rc=0; global quality rc=1

## Verdict

- Hard failures: ['dashboard_projection_gap', 'targeted_tests_failed']
- Points à revue: ['attack_flow_hedged_language', 'attack_flow_possible_remediation', 'global_quality_gate_outside_scope']
