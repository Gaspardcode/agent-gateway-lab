# Se connecter à la plateforme

La plateforme n'a **aucun port ouvert sur Internet**. Pas d'IP à retenir, pas
de SSH. On y accède en deux étapes :

1. **AWS** (`aws login`) prouve qui tu es auprès d'AWS ;
2. **le tunnel SSM** amène la passerelle sur `https://localhost:8443` du serveur ;
3. **ton certificat client** (mTLS) prouve qui tu es auprès de la passerelle.

```
laptop ──ssh──▶ serveur <SERVEUR> ──tunnel SSM──▶ instance AWS :8443 ──▶ passerelle ──▶ modèle
                 (certificats .pki/)                (aucun port entrant)
```

Toutes les commandes se lancent **sur le serveur**, dans `~/agent-gateway-lab`.

---

## 0. Une seule fois : préparer le terminal

```bash
ssh <SERVEUR>
cd ~/agent-gateway-lab
export PATH=$HOME/.local/bin:$PATH     # aws et session-manager-plugin
```

## 1. Se connecter à AWS

```bash
aws login --remote --profile lab-admin --region eu-north-1
```

Ça affiche une URL : l'ouvrir dans le navigateur du laptop, se connecter, recopier
le code. La session dure **12 h** et se renouvelle seule pendant 90 jours.

Vérifier :
```bash
aws sts get-caller-identity --profile lab-admin      # doit afficher AccountFullAccessRole
```

## 2. Démarrer l'instance

Elle s'arrête toute seule après 60 min sans activité (pour le coût).

```bash
make status        # running / stopped
make start         # si stopped ; compter 2-3 min (vérification de la release + chargement du modèle)
```

## 3. Ouvrir le tunnel

Dans un **terminal dédié**, à laisser ouvert :
```bash
make tunnel
```
Attendre `Waiting for connections...`. La passerelle est alors sur
`https://localhost:8443` **du serveur**.

## 4. Parler au modèle

Question simple :
```bash
make ask Q="Bonjour, qui es-tu ?"
```

Avec curl (c'est ce que fait `make ask`) :
```bash
curl --cacert .pki/ca.crt --cert .pki/agent-support.crt --key .pki/agent-support.key \
  https://localhost:8443/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"messages": [{"role": "user", "content": "Bonjour"}], "max_tokens": 200}'
```

Les en-têtes de réponse `x-gateway-decision` (allow, block, redact...) et
`x-request-id` permettent de retrouver la requête dans les journaux.

Depuis un programme : c'est l'API OpenAI. Exemple en Python, sans dépendance,
dans `agent/agent.py` (classe `Gateway`).

### Les identités disponibles

| Certificat (`.pki/`) | Outils autorisés | Mode |
|---|---|---|
| `agent-support` | search_docs, http_get, send_email | enforce (bloque) |
| `redteam-observe` | les mêmes | observe (journalise sans bloquer) |
| `lecture-seule` | search_docs | enforce |

Sans certificat, la connexion TLS est refusée. Avec un certificat d'un CN absent
de `gateway/policy.yaml`, la réponse est `403`.

## 5. Depuis le laptop (facultatif)

Le tunnel écoute sur le serveur. Pour l'utiliser depuis le laptop, relayer le port :
```bash
ssh -N -L 8443:localhost:8443 <SERVEUR>
```
puis copier `ca.crt` et un couple `.crt`/`.key` depuis `~/agent-gateway-lab/.pki/`
(par `scp`, jamais par mail ou chat : la clé est l'identité).

## 6. Voir ce qui se passe

```bash
make logs          # audit JSON de la passerelle en direct + démarrages
make shell         # shell sur l'instance (SSM), par ex. :
                   #   sudo systemctl status agl-boot
                   #   sudo docker ps ; sudo docker logs llama --tail 20
```

Console AWS (région Stockholm) :
- **CloudWatch → Logs Insights** → requêtes enregistrées `agl/...`
  (décisions par client, chaînes d'attaque, latence, démarrages) ;
- **CloudWatch → Alarms** : `agl-*` (exfiltration, injection, échec de vérification...).

## 7. Lancer la red team

Tunnel ouvert, puis :
```bash
make redteam       # environ 30 min ; résultats dans results/run-<date>.md
```

## 8. Finir

```bash
make stop          # ou laisser l'arrêt automatique (60 min)
```
Fermer le terminal du tunnel (Ctrl-C).

---

## Maintenance

| Besoin | Commande |
|---|---|
| Certificat client expiré (30 jours) | `./scripts/pki.sh client agent-support` |
| Certificat serveur expiré | `./scripts/pki.sh server && make tls`, puis redémarrer l'instance |
| Nouveau client | `./scripts/pki.sh client <cn>`, l'ajouter dans `gateway/policy.yaml`, puis nouvelle release |
| Nouvelle release | commit, `make release`, `make publish V=<version>`, puis `make stop start` |
| Tout supprimer | `make destroy` |

## Dépannage

| Symptôme | Cause probable | Que faire |
|---|---|---|
| `Your session has expired` | session AWS de plus de 12 h | refaire l'étape 1 |
| `SessionManagerPlugin is not found` | PATH | `export PATH=$HOME/.local/bin:$PATH` |
| `TargetNotConnected` au tunnel | instance arrêtée ou en démarrage | `make status`, `make start`, attendre 2 min |
| `curl: (35)` / `(56)` erreur TLS | mauvais certificat ou expiré | `openssl x509 -enddate -noout -in .pki/agent-support.crt` |
| `connection refused` sur 8443 | tunnel fermé, ou pile pas encore prête | relancer `make tunnel` ; `make logs` doit montrer `release_verified` puis `startup` |
| `403 client inconnu` | CN absent de la politique | vérifier `gateway/policy.yaml` |
| `429` | limite de débit du client | attendre une minute |
| réponse très lente | CPU 2 vCPU, environ 10 tokens/s | réduire `max_tokens` |
| alarme `ReleaseVerificationFailed` | release modifiée ou non signée | `make logs`, ligne `release_verification_failed` : le détail dit quoi |
