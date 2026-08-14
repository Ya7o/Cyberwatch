# Cyberwatch V0

V0 valide une chaîne de collecte volontairement simple et déterministe :
**BonjourLaFuite → ITEMS → normalisation → déduplication → INCIDENTS → dashboard**.
BonjourLaFuite est la seule source active ; les autres collecteurs sont conservés,
mais désactivés.

**Dashboard : https://ya7o.github.io/Cyberwatch/**

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
