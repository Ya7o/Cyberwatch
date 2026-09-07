# Référentiel organisationnel

`organisation_families.csv` contient les familles dont le nom ou le sigle est suffisamment auto-descriptif pour constituer une preuve déterministe de secteur.

Principes :

- correspondances ancrées sur le nom complet, un alias exact ou un sigle contrôlé ;
- aucun simple mot de marque n'est admis ;
- chaque famille porte une provenance et un niveau d'autorité ;
- les identifiants entreprise/NAF continuent d'être absorbés par le registre entreprise existant ;
- les entités exactes validées manuellement restent prioritaires ;
- une famille institutionnelle certaine évite un appel LLM et produit une preuve auditée.

Le fichier est volontairement versionné dans le dépôt : la collecte quotidienne ne dépend pas de la disponibilité temps réel d'un annuaire externe. Les mises à jour peuvent être construites à partir de l'Annuaire de l'administration française, de SIRENE/recherche-entreprises et des référentiels métiers officiels, puis revues avant publication.
