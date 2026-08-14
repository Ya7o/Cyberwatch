# Corrections déterministes de qualité — 2026-08-14

## Périmètre et méthode

Cette passe reste locale, déterministe et sans réseau : aucun resolver de base,
fuzzy matching, LLM ou alias global `ARS` n'est utilisé. Le chemin
Cyberattaque.org reste : `NEGATED → MULTI → DIRECT → NO_VICTIM`.

La baseline `65c56a8` contenait 1 578 items / 1 157 incidents. L'état publié
avant cette passe (`52e3c19`) contenait 1 577 items / 1 156 incidents. Le
candidat reconstruit avec un cutoff figé au 2026-08-14 contient 1 576 items /
1 155 incidents : l'article Cyberattaque.org 276 n'est plus matérialisé comme
une organisation `ARS` unique.

## Corrections appliquées

- **ARS 276** — Le titre et le corps citent explicitement `130 hôpitaux` et
  `AP-HP` en plus des ARS. Cette combinaison précise est classée `MULTI`; le
  mot `ARS` seul ne suffit jamais.
- **Fédérations sportives** — Les formes `Fédération Française de …` et
  `Fédération Française d'…` sont reconnues comme sportives. Le marqueur
  générique `fédération` ne revient pas : la Fédération Hospitalière de France
  et la Fédération Française des Sapeurs-Pompiers ne deviennent pas sportives.
- **Négation DMP** — Les démentis forts déjà validés sont aussi pris en compte
  dans `content.rendered`, afin de rejeter l'article réel 1555 lorsque
  l'attribution n'est pas techniquement confirmée.

## Deltas secteur observés

13 lignes changent de secteur, toutes vers `Sport` : Fédération Française
d'Aéronautique, d'Aïkido/Aïkibudo, d'Escrime, d'Équitation, d'Études et Sports
Sous-Marins, d'ULM et d'Athlétisme (sur les sources BonjourLaFuite,
Cyberattaque.org et FrenchBreaches). Il s'agit exclusivement de restaurations
de fédérations sportives; aucune fédération hospitalière ou de sapeurs-pompiers
n'est concernée.

## Menaces inconnues : mesure uniquement

L'audit offline recense 30 candidats au mécanisme existant de backfill, dont
Nosho, AlumnForce, Pulsy, France Services et Lancy FC. Il n'est **pas branché**
dans ce correctif : la liste complète est volontairement conservée dans la
sortie de `scripts/audit_data_quality.py` pour revue explicite, et aucun
marqueur large n'est ajouté.

## Reproductibilité et validation

`scripts/audit_data_quality.py --check` vérifie que l'audit reste identique
après mélange déterministe des lignes. Le benchmark Cyberattaque.org HEAD-only
est offline et reproductible :

- 408 articles;
- 368 correspondances exactes, 40 divergences;
- 4 `NEGATED`, 7 `MULTI`, 390 `DIRECT`, 7 `NO_VICTIM`;
- SHA-256 :
  `3739255615469fb837c21434afb06ef673bceffc914bd2cd64b8e14288572c9d`
  sur deux matérialisations consécutives.

## Provenance

`snapshot.json:Code_Commit` est obtenu par `git rev-parse HEAD` au moment du
CREATE (ou `GITHUB_SHA` en CI). La publication suit donc deux commits : le
commit de code est créé avant le CREATE, puis le commit de données contient le
snapshot produit par ce code. Le champ désigne ainsi le code réellement
exécuté, et non le commit ultérieur qui versionne les CSV.
