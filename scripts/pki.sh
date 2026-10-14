#!/usr/bin/env bash
# PKI du lab : une CA ECDSA P-256 (1 an), un certificat serveur et des
# certificats clients courts (30 jours). Pas de CRL : la révocation, c'est
# l'expiration courte et le retrait du CN dans policy.yaml.
# Usage : pki.sh init | pki.sh client <cn> | pki.sh server | pki.sh push
# `push` envoie CA + certificat serveur + clé dans SSM Parameter Store (SecureString).
set -euo pipefail

DIR=${PKI_DIR:-"$(dirname "$0")/../.pki"}
PREFIX=${SSM_PREFIX:-/agl/tls}
mkdir -p "$DIR" && chmod 700 "$DIR"
DIR=$(realpath "$DIR")
cd "$DIR"

leaf() { # leaf <nom> <cn> <eku> [san]
  local name=$1 cn=$2 eku=$3 san=${4:-}
  openssl ecparam -name prime256v1 -genkey -noout -out "$name.key" 2>/dev/null
  chmod 600 "$name.key"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=$eku"
    [[ -n $san ]] && echo "subjectAltName=$san"
  } > "$name.ext"
  openssl req -new -key "$name.key" -subj "/O=agent-gateway-lab/CN=$cn" -out "$name.csr"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 30 -sha256 -extfile "$name.ext" -out "$name.crt" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
  echo "$name.crt (CN=$cn) jusqu'au $(openssl x509 -enddate -noout -in "$name.crt" | cut -d= -f2)"
}

case ${1:-} in
  init)
    [[ -f ca.key ]] && { echo "CA déjà présente dans $DIR"; exit 1; }
    openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
    chmod 600 ca.key
    openssl req -x509 -new -key ca.key -sha256 -days 365 -subj "/O=agent-gateway-lab/CN=agl-ca" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
    leaf server agent-gateway serverAuth "DNS:localhost,IP:127.0.0.1"
    for cn in agent-support redteam-observe lecture-seule; do leaf "$cn" "$cn" clientAuth; done
    ;;
  client) leaf "${2:?cn}" "$2" clientAuth ;;
  server) leaf server agent-gateway serverAuth "DNS:localhost,IP:127.0.0.1" ;;
  push)
    for f in ca.crt server.crt server.key; do
      aws ssm put-parameter --name "$PREFIX/$f" --type SecureString --overwrite \
        --value "file://$DIR/$f" >/dev/null
      echo "SSM $PREFIX/$f"
    done
    ;;
  *) sed -n '2,7p' "$0"; exit 1 ;;
esac
