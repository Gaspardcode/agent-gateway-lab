# agent-gateway-lab

> Faire tourner un modèle Mistral chez soi, lui donner des outils, et l'empêcher
> d'obéir à un document piégé. Mesuré, pas promis.

Un agent de support s'appuie sur **Ministral 3 3B** (poids ouverts officiels de
Mistral AI, Apache 2.0), auto-hébergé sur AWS. Il cherche dans une doc, appelle
des URL et envoie des e-mails. Un attaquant qui glisse des consignes dans un
document (injection indirecte) peut lui faire exfiltrer la clé API du client.

Ce dépôt construit la défense et mesure son effet :

1. **Chaîne d'approvisionnement** : modèle épinglé par révision et SHA-256, images
   par digest, et un manifeste de release **signé par une clé KMS asymétrique**.
   L'instance ne peut que vérifier, jamais signer. La vérification a lieu à chaque
   démarrage ; si elle échoue, rien ne démarre et une alarme se déclenche.
2. **Passerelle Rust** entre l'agent et le modèle : mTLS (identité = CN du
   certificat), politique d'outils par client, liste d'hôtes et de destinataires
   autorisés, secrets interdits en sortie, **contamination** (après une injection
   dans un résultat d'outil, plus aucune sortie), liens markdown d'exfiltration retirés.
3. **Red team** : 12 attaques et 6 cas légitimes, rejoués avec la même passerelle
   en `observe` (modèle seul) puis en `enforce`. On compte les attaques réussies
   **et** les faux positifs.
4. **Détection** : audit JSON → CloudWatch Logs → filtres de métriques → alarmes,
   règles Sigma lisibles, correspondance MITRE ATLAS.

## Architecture

```
 serveur (homelab)                          AWS eu-north-1, VPC 10.30.0.0/16
 ┌───────────────────┐                     ┌──────────────────────────────────────────────┐
 │ redteam/run.py    │  SSM port-forward   │ EC2 m7i-flex.large · AUCUN port entrant      │
 │ agent/agent.py    │ ──────────────────▶ │  127.0.0.1:8443                              │
 │ certificats .pki/ │   (pas de SSH,      │  ┌────────────────┐   réseau Docker interne  │
 └───────────────────┘    pas d'IP)        │  │ agent-gateway  │──▶ ┌──────────────────┐  │
         │                                 │  │ mTLS, politique│    │ llama.cpp        │  │
         │ release.sh publish              │  └───────┬────────┘    │ Ministral 3 3B   │  │
         ▼                                 │          │ audit JSON  │ sans aucune sortie│ │
 ┌──────────────────┐  kms:Sign (admin)    │          ▼             └──────────────────┘  │
 │ S3 releases/     │◀──────────────────── │  CloudWatch Logs ─▶ filtres ─▶ alarmes ─▶ SNS │
 │ models/<sha>.gguf│ ──── lecture seule ─▶│  agl-boot.service : kms:Verify + SHA-256     │
 └──────────────────┘                      │  arrêt auto après 60 min d'inactivité        │
                                           └──────────────────────────────────────────────┘
```

## Résultats

Voir `results/` (un fichier par campagne) et la section du même nom dans
[docs/modele-de-menace.md](docs/modele-de-menace.md). Les limites connues sont
mesurées par des scénarios dédiés (A11 : secret encodé en base64 sans marqueur ;
B04 : faux positif sur un document légitime).

## Se connecter

Voir **[docs/connexion.md](docs/connexion.md)** : login AWS, tunnel SSM, certificat client, premières requêtes, dépannage.

## Déployer

```bash
aws login --remote --profile lab-admin       # session de 12 h
make lint test                               # fmt, validate, trivy, tests Rust
make plan && make apply                      # relire le plan avant apply
./scripts/pki.sh init && make tls            # CA + certificats, serveur dans SSM
make release && git status                   # arbre propre exigé pour publier
make publish                     # signature KMS + envoi S3
make tunnel                                  # dans un autre terminal
make redteam                                 # environ 30 min sur 2 vCPU
make stop                                    # ou attendre l'arrêt automatique
```

## Choix assumés

| Choix | Pourquoi |
|---|---|
| Modèle 3B quantifié sur CPU | Le free plan n'autorise pas les GPU. Le sujet est la sécurité de l'intégration, pas la qualité du modèle. Un petit modèle obéit d'ailleurs plus facilement aux injections : bon terrain de test. |
| GGUF officiel `mistralai/` plutôt que conversion maison | Moins d'étapes à faire confiance ; pas de pickle, aucun code exécuté au chargement. |
| KMS pour signer plutôt que Sigstore | Natif AWS, séparation sign/verify par IAM, journalisé dans CloudTrail. Sigstore/OpenSSF model-signing est la suite logique pour une distribution publique. |
| Passerelle sans état | L'API OpenAI renvoie toute la conversation : la contamination se recalcule à chaque requête, pas de base à protéger. |
| Pas de streaming | La réponse doit être inspectée en entier avant d'être rendue. |
| Les marqueurs d'injection ne bloquent pas seuls | Ce sont des signaux (faux positifs mesurés). Ce qui bloque, ce sont les règles de sortie : destinations, secrets, contamination. |
| SSM au lieu de SSH ou d'un ALB | Zéro port entrant, accès tracé dans CloudTrail. |

## Arborescence

```
gateway/      passerelle Rust (src/policy.rs = le cœur), policy.yaml, tests
agent/        agent minimal au format OpenAI tool calling, outils simulés
redteam/      scénarios et campagne observe/enforce
scripts/      release signée, vérification au démarrage, lancement durci, PKI
terraform/    VPC, EC2, S3, KMS, IAM, CloudWatch (détection.tf)
detection/    règles Sigma (source lisible des filtres CloudWatch)
model/        épinglage du modèle et des images
docs/         modèle de menace, résultats
```
