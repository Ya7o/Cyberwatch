# Rich Facts platform

Rich Facts is the evidence-first semantic layer shared by editorial sources.

## Rules

- collectors own fetching and cleanup only;
- deterministic extraction is preferred;
- semantic/LLM extraction is optional and never canonical by itself;
- every accepted semantic claim must carry literal evidence from the article;
- numbers in a claim must be supported by its evidence;
- `confirmed`, `reported`, `claimed`, `hypothesis`, `denied`, `negated` and `unknown` remain distinct;
- multi-source disagreement is preserved in `divergences`; legacy scalar fields are projections only;
- historical claims are retained in chronological `history` rather than overwritten.

## Rollout

Cyberattaque.org is the reference implementation. FrenchBreaches uses the same generic deterministic model through a source adapter. Future editorial sources should implement collection/cleanup only and attach the shared rich-facts layer.
