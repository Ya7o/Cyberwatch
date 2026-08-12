# Cyberwatch — Observatoire des incidents cyber France / Océan Indien

Pipeline automatique qui collecte les incidents cyber **publiquement listés** en
France métropolitaine, à La Réunion, Mayotte, Maurice, Madagascar, aux Seychelles
et aux Comores, construit une base déterministe reproductible, et publie un
dashboard statique sur GitHub Pages.

**Dashboard : https://ya7o.github.io/Cyberwatch/**

> Cette base ne prétend pas représenter toutes les cyberattaques réelles. Elle vise
> la liste la plus large possible des incidents *publiquement listés*, avec une
> **couverture mesurable** et un protocole **reproductible**.

---

## Ce qui tourne tout seul

| Quand | Quoi |
|---|---|
| Tous les jours à 8 h (heure Réunion) | Sources directes et ransomware.live — ~30 requêtes, 1 à 2 min |
| Le lundi | Balayage complet, couches de veille comprises — ~270 requêtes |

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

python -m cyberwatch diagnose          # sonder les sources, mesurer le coût réel
python -m cyberwatch create            # construire la base (année en cours)
python -m cyberwatch maj               # mettre à jour (fenêtre glissante 14 jours)
python -m cyberwatch replay            # reconstruire INCIDENTS sans réseau
python -m cyberwatch test-repeat       # test de répétabilité
python -m cyberwatch build-site        # régénérer les données du dashboard

python -m http.server --directory docs # consulter le dashboard en local
```

Restreindre le périmètre : `--layers core,local_media` · `--layers watch` · `--layers all`.
Figer un cutoff : `--as-of 2026-08-12T19:07:00+04:00`.

---

## Organisation du dépôt

```
cyberwatch/          le pipeline
  normalize.py       clés, taxonomie des menaces, secteurs, localisations
  identity.py        identifiants SHA256, tri canonique, empreintes
  dedup.py           composantes d'incident à 14 jours
  status.py          modèle de statuts et agrégation du run
  collectors/        WordPress · RSS · JSON-LD · Google News · ransomware.live
  sources.py         référentiel des 19 sources
  watchlists.py      41 communes et entités critiques par territoire
data/                la base, six CSV versionnés
docs/                le dashboard (HTML/CSS/JS, sans dépendance)
tests/               152 tests hors ligne
```

---

## Sources

19 sources réparties en cinq couches : archives et agrégateurs nationaux
(FrenchBreaches, BonjourLaFuite, Cyberattaque.org, ransomware.live), médias locaux
(Zinfos974, LINFO, Kwezi), CERT régionaux (Maurice, Madagascar, Seychelles),
surveillance nominative de 110 entités, et veille régionale par territoire.

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
   branche par défaut, dossier `/docs`.
2. Lancer une première collecte : *Actions → Collecte → Run workflow*.

Le dépôt doit être public pour bénéficier de Pages et des minutes Actions
gratuites.
