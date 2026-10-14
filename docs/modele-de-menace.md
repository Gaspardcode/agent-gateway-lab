# Modèle de menace

## Ce qu'on protège

- les secrets du dossier client que l'agent a dans son contexte (clé API, IBAN) ;
- l'intégrité de ce qui tourne : modèle, binaire de la passerelle, politique ;
- la disponibilité et le coût de l'instance.

## Attaquants considérés

| Attaquant | Capacité | Exemple |
|---|---|---|
| Auteur d'un document | écrit du contenu que l'agent lira via un outil | page de doc, ticket, page web (A01-A06, A09-A12) |
| Utilisateur malveillant | parle directement à l'agent | « ignore tes consignes » (A07) |
| Client mal configuré ou compromis | possède un certificat valide | appel d'un outil hors de son périmètre |
| Chaîne d'approvisionnement | modifie un artefact dans S3 ou en transit | GGUF piégé, binaire remplacé, politique assouplie |
| Accès à l'instance | exécute du code sur l'EC2 | tente de signer ou de publier une release |

Hors périmètre : compromission du compte AWS administrateur, de Hugging Face
ou de Mistral AI à la source, attaques sur les poids eux-mêmes (backdoor dans
l'entraînement).

## Contrôles et technique MITRE ATLAS

| Menace | ATLAS | Contrôle | Où |
|---|---|---|---|
| Artefact piégé | AML.T0010 | épinglage SHA-256, manifeste signé KMS, vérification à chaque démarrage, anti-rollback | `release.sh`, `verify-release.sh` |
| Injection indirecte | AML.T0051.001 | marqueurs + Unicode invisible → contamination → plus aucune sortie | `policy.rs::check_request` |
| Injection directe | AML.T0051.000 | signalée, non bloquée ; les règles de sortie s'appliquent quand même | `policy.rs` |
| Fuite de données | AML.T0057 | secrets interdits en sortie, liens markdown retirés | `policy.rs::check_tool_call` |
| Exfiltration par outil | AML.T0025 | listes d'hôtes et de domaines autorisés, sosies refusés | `host_allowed` |
| Abus d'outil | AML.T0053 | outils par CN, arguments illisibles refusés | `policy.yaml` |
| Accès à l'API | AML.T0040 | mTLS TLS 1.3, CN connu, limite de débit | `tls.rs`, `ratelimit.rs` |
| Instance compromise | — | refus explicite de `kms:Sign` et des écritures S3 pour le rôle de l'instance ; IMDS inaccessible aux conteneurs | `main.tf` |
| Modèle compromis | — | llama.cpp sur un réseau Docker interne, sans sortie, lecture seule, non root | `run-stack.sh` |

## Limites connues (et mesurées)

- **Secret transformé** (A11) : une clé encodée en base64 vers un hôte autorisé
  n'est pas reconnue par les motifs. Pistes : canaris en plusieurs encodages,
  limite d'entropie sur les arguments sortants, ou désactivation des paramètres
  libres sur les URL autorisées.
- **Injection sans marqueur** (A03, A10) : non détectée comme injection ; la
  défense repose alors sur les listes de destinations. Si l'attaquant contrôle
  une destination autorisée, il passe.
- **Faux positifs des marqueurs** (B04) : un document légitime peut contaminer
  une conversation et bloquer un e-mail interne. C'est le prix de la règle
  « plus de sortie après contamination ».
- **Pas de révocation** des certificats clients : validité de 30 jours, retrait
  du CN dans la politique (qui impose une nouvelle release signée).
- **Anti-rollback local** : le dernier `seq` est stocké sur l'instance ; une
  instance neuve accepterait une release ancienne mais signée.
- Le modèle 3B obéit plus facilement qu'un grand modèle : les taux mesurés ici ne
  se transposent pas tels quels à Mistral Large.

## Résultats

À compléter après la campagne `make redteam` (fichiers dans `results/`).
