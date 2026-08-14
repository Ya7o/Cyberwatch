# Cyberwatch V0

Cyberwatch applique une chaîne déterministe : **collecte → normalisation →
qualification canonique offline → déduplication → quality gates → hashes →
snapshot/dashboard**. Les sept sources actives sont BonjourLaFuite,
Cyberattaque.org, FrenchBreaches, Kwezi Numérique, Mayotte Hebdo Numérique,
Journal de Mayotte et Ransomware.live. La 1ère Mayotte n'est pas activée dans
la couverture locale du Lot 1.

La qualité est vérifiée offline par :
`python scripts/audit_data_quality.py --items data/items.csv --check --check-regression`.

**Dashboard : https://ya7o.github.io/Cyberwatch/**

## Bootstrap et exploitation

Les seules sources actives sont `BONJOURLAFUITE`, `FRENCHBREACHES`,
`CYBERATTAQUE_ORG`, `RANSOMWARE_LIVE` et `KWEZI_NUMERIQUE`.

Une base neuve suit obligatoirement cette séquence :

```bash
python -m cyberwatch create
python -m cyberwatch check
python -m cyberwatch test-repeat
python -m cyberwatch test-live-repeat
python -m cyberwatch baseline
python -m cyberwatch build-site
```

`maj` est uniquement une mise à jour d'un corpus existant : elle refuse de
démarrer sans `snapshot.json`, `items.csv` et `incidents.csv` cohérents. La CI
code utilise `python -m cyberwatch check --allow-uninitialized` et accepte donc
une base totalement neuve, mais jamais des fichiers partiels.

Les états sont explicites : **base non initialisée** (aucun snapshot ni CSV),
**base valide** (provenance et hashes cohérents), **base incohérente** (fichiers
partiels ou divergents), **run BROKEN** (journal de diagnostic sans remplacement
du snapshot), et **baseline** (snapshot également validé par Live Repeat).

Un `CREATE` BROKEN ne publie pas de snapshot. Une fois la baseline créée, la
collecte quotidienne de 08:00 heure Réunion peut lancer `python -m cyberwatch maj`.
Le full scan hebdomadaire ne sera réintroduit qu'avec les couches Watch.

### Initialisation officielle

La voie GitHub Actions officielle est **Initialize Baseline**. Elle fige un même
`AS_OF` et, si fourni, un même `start`, puis exécute sans publication intermédiaire :

`CREATE → check → test-repeat → test-live-repeat → baseline → build-site → publication`.

`data/live_repeat.json` est la preuve de la dernière répétabilité LIVE. Une
baseline est refusée sans preuve `PASS` correspondant exactement au snapshot
(commit, sources actives, fenêtre et hashes). Un snapshot est donc un corpus
techniquement valide ; une baseline est ce snapshot validé comme référence.
Une MAJ remplace le snapshot, mais ne réécrit jamais la baseline.

Le workflow **Collecte** reste dédié à `MAJ`. Un `CREATE` manuel depuis ce
workflow peut aider au diagnostic, mais il ne publie pas de première base sans
baseline : utiliser **Initialize Baseline**.

> Cette base ne prétend pas représenter toutes les cyberattaques réelles. Elle vise
> la liste la plus large possible des incidents *publiquement listés*, avec une
> **couverture mesurable** et un protocole **reproductible**.

---

## État de la source

`OK` signifie qu'au moins un item BonjourLaFuite (date + organisation) a été
reconnu. `FAIL` signifie que la page est inaccessible ou qu'aucun item n'a été
reconnu. Un item hors fenêtre compte dans `Items_seen`, mais pas dans
`Items_in_window` ni forcément dans `Items_collected`.

## Ce qui tourne tout seul

| Quand | Quoi |
|---|---|
| Chaque exécution | BonjourLaFuite uniquement |

Chaque run met à jour `data/`, régénère `docs/data/` et publie un commit. Le
dashboard se rafraîchit sans intervention. Le récapitulatif de chaque run est
visible dans l'onglet **Actions**.

---

## Le point le plus important : lire un statut

Un chiffre bas ne veut pas dire la même chose selon la façon dont il a été obtenu.
Trois champs sont donc publiés pour chaque source :

| Statut | Signification | Un `0` veut dire |
|---|---|---|
| `OK` | Protocole exécuté intégralement | **aucun incident** — zéro vérifié |
| `PARTIAL` | Protocole interrompu, avec sa couverture chiffrée (« 68 % ») | information incomplète |
| `FAIL` | Énumération impossible | information indisponible |
| `SKIPPED` | Hors périmètre de ce run — **pas une erreur** | sans objet |
| `NOT_COVERED` | Source attendue inactive ou absente du dernier run | angle mort visible |

Le dashboard grise les zéros non fiables et liste les angles morts de chaque run.
Détail complet dans [`METHODOLOGY.md`](METHODOLOGY.md).

---

## Utilisation en local

```bash
pip install -r requirements.txt

python -m cyberwatch create            # construire la base (année en cours)
python -m cyberwatch maj               # mettre à jour (fenêtre glissante 30 jours)
python -m cyberwatch replay            # reconstruire INCIDENTS sans réseau
python -m cyberwatch test-repeat       # test de répétabilité
python -m cyberwatch check             # contrôles mono-source et hashes
python -m cyberwatch build-site        # régénérer les données du dashboard

python -m http.server                  # consulter le dashboard en local
```

Figer un cutoff : `--as-of 2026-08-12T19:07:00+04:00`.

---

## Organisation du dépôt

```
cyberwatch/          le pipeline
  normalize.py       clés, taxonomie des menaces, secteurs, localisations
  identity.py        identifiants SHA256, tri canonique, empreintes
  dedup.py           composantes d'incident à 14 jours
  status.py          modèle de statuts et agrégation du run
  collectors/        WordPress · RSS · JSON-LD · flux médias · ransomware.live
  sources.py         référentiel des 18 sources
  watchlists.py      41 communes et entités critiques par territoire
index.html           le dashboard, servi à la racine par GitHub Pages
assets/              style, script et données du dashboard (sans dépendance)
data/                la base, six CSV versionnés
tests/               219 tests hors ligne
```

---

## Sources

18 sources réparties en cinq couches : archives et agrégateurs nationaux
(FrenchBreaches, BonjourLaFuite, Cyberattaque.org, ransomware.live), média local
(Kwezi), CERT régional (Maurice), surveillance nominative de 110 entités via les
flux des médias de chaque territoire, et veille régionale.

Cinq sources sont **inactives**, chacune avec son motif daté et son critère de
réactivation : CIRT-MG et CERT-SC ne publient plus de liste énumérable, deux
médias réunionnais refusent toute lecture automatisée, et Hackmageddon n'a jamais
été activée. Elles restent affichées en `SKIPPED` sur le dashboard avec leur
raison — désactiver n'est pas masquer.

Chaque source déclare son URL, son protocole et son test de succès dans
`data/sources.csv`, recopiés depuis `cyberwatch/sources.py`.

---

## Garanties de reproductibilité

- **`REPLAY`** reconstruit `INCIDENTS` depuis `ITEMS` sans réseau : à `ITEMS`
  identique, `Incidents_Hash` identique.
- **`test-repeat`** vérifie quatre égalités en construisant deux fois depuis des
  ordres d'entrée différents.
- Les deux tournent dans la CI à chaque push.

---

## Installation sur un nouveau dépôt

1. Activer GitHub Pages : *Settings → Pages → Source : Deploy from a branch*,
   branche par défaut, **dossier `/` (racine)**. Le dashboard est `index.html`
   à la racine, de sorte que l'URL de Pages soit directement celle du
   dashboard, sans sous-dossier. Le `.nojekyll` évite que Jekyll ne retouche
   un site déjà statique.
2. Lancer une première collecte : *Actions → Collecte → Run workflow*.

Le dépôt doit être public pour bénéficier de Pages et des minutes Actions
gratuites.
# Fiabilité du snapshot

`test-repeat` vérifie hors réseau que le même jeu `ITEMS` produit les mêmes
`INCIDENTS`. `test-live-repeat` effectue deux CREATE isolés avec un cutoff figé
et compare statuts, unités, compteurs et hashes, sans écrire de fichier.

`data/snapshot.json` est la provenance du snapshot publié : opération, run,
fenêtre, compteurs, hashes et commit producteur. `check` relit les CSV et
échoue si cette provenance ne correspond plus. Un run BROKEN reste journalisé,
mais ne remplace jamais cette provenance. `data/baseline.json` est créé par
`python -m cyberwatch baseline` après validation.

Les métriques sont figées : `Items_seen` est reconnu avant filtres,
`Items_in_window` est son sous-ensemble temporel, `Items_collected` est
matérialisé dans Cyberwatch, et `Units_*` mesure le protocole technique.
