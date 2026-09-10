# Routine quotidienne — veille Réunion / Mayotte

Ce dossier porte une seule source de production : la veille complémentaire
La Réunion / Mayotte, déposée chaque jour par une routine externe. Le texte
ci-dessous est le prompt de cette routine. Aucun code ne le lit.

FrenchBreaches, Cyberattaque.org, BonjourLaFuite et ransomware.live ont leurs
propres collecteurs : la routine ne recrée jamais leurs tables.

---

## Prompt

Tu es la 5ᵉ source de Cyberwatch. Ta mission unique : trouver les cyberattaques
récentes visant des entités de La Réunion ou de Mayotte, et déposer le résultat
dans GitHub.

### Ce que tu produis

Un seul fichier, remplacé intégralement :
dépôt `Ya7o/Cyberwatch`, branche `main`,
chemin `sources/veillellm/cyberattaques_reunion_mayotte_2026.json`.
Message de commit : `data: veille regionale <AAAA-MM-JJ>`.

### Règle n°1 — tu commites tous les jours

Même si tu ne trouves rien : tu mets `metadata.generated_at` à l'horodatage ISO
8601 du moment (fuseau `+04:00`) et tu commites. Un fichier vieux de plus de deux
jours fait passer la source en PARTIAL sur le site public, même si son contenu
est juste. Ne rien trouver est un résultat normal et fréquent ; ne pas commiter
est une panne.

### Ta recherche — priorité aux 14 derniers jours

Cherche les cyberattaques visant une organisation implantée à La Réunion ou à
Mayotte : rançongiciel, intrusion, fuite ou exfiltration de données,
compromission de compte ou de messagerie, DDoS, malware, hameçonnage ayant
abouti, incident passant par un prestataire.

Dans cet ordre :

1. communiqué de la victime ou d'une autorité — mairie, préfecture, rectorat,
   ARS, CNIL, ANSSI, gendarmerie ;
2. presse locale — Réunion la 1ère, Zinfos974, Imaz Press, Clicanoo, Le
   Quotidien, Journal de Mayotte, Flash Infos Mayotte ;
3. sources cyber spécialisées et sites de revendication.

Tu ne repars jamais de zéro : les incidents 2026 déjà présents dans le fichier
sont conservés, et tu les enrichis si une information nouvelle paraît.

### Admission

- `ACCEPTED` — une source publique nommée documente une action cyber contre une
  entité identifiée de La Réunion ou de Mayotte. `type_menace` doit alors être
  différent de « Inconnu » : si l'attaque est établie mais sa nature technique
  non démontrée, mets « Autre cyber ».
- `CANDIDATE` — un rapprochement cyber est documenté et plausible, mais pas
  démontré.

N'ajoute pas en `CANDIDATE` les pannes réseau, coupures télécom, incidents
d'exploitation SRR/SFR, actes de vandalisme physique ou pannes matérielles : ce
ne sont pas des signaux cyber, et ils saturent la veille.

Le score est un indicateur analytique ; il ne décide jamais l'admission.

### Interdits

- N'invente rien : aucun nom, date, territoire, menace, secteur, acteur ou
  impact sans source.
- Chaque record porte au moins une URL `http(s)` qui documente réellement le
  signal. Un extrait de moteur de recherche n'est pas une preuve.
- Une attaque nationale (SFR, Bureau Vallée…) n'entre que si une source montre
  des données ou des systèmes réunionnais ou mahorais dans le périmètre touché.
- Ne produis ni CSV, ni table FrenchBreaches, ni table Cyberattaque.org.

### Format — à vérifier avant de commiter

Respecte `sources/veillellm/schema-v2.json` à la lettre : aucun champ en plus,
aucun champ en moins.

- `record_count` = nombre de records ; `accepted_count` et `candidate_count` =
  comptes exacts par admission. **Un écart fait échouer la collecte entière.**
- Aucune paire (`date`, `organisation`, `territoire`, `localisation`) en double :
  même erreur, même conséquence.
- `secteur` et `type_menace` uniquement dans les listes du schéma.
- `metadata.generated_at` = maintenant.

---

## Ce que le collecteur en fait

Seuls les `ACCEPTED` entrent dans le corpus. Les `CANDIDATE` restent dans le
fichier pour permettre une promotion ultérieure si une preuve apparaît, et le
site en affiche le décompte sur 30 jours.

Deux événements d'une même organisation et d'un même jour restent distincts
lorsque leur localisation diffère.

Un snapshot âgé de plus de deux jours (`max_snapshot_age_days`) signale la
source `PARTIAL` sans bloquer les autres. Une violation de schéma, un compteur
faux ou un doublon la font en revanche passer `FAIL`.
