#!/usr/bin/env bash
# Lance la pile depuis une release DÉJÀ VÉRIFIÉE (voir verify-release.sh) :
#   - llama : réseau Docker interne, aucune sortie possible, système de fichiers en lecture seule ;
#   - agent-gateway : seul point d'entrée, publié sur 127.0.0.1:8443, relié au réseau interne.
# Usage : run-stack.sh <dossier_release> <dossier_tls>
# Variables : THREADS, CTX, LOG_GROUP (si défini : pilote awslogs vers CloudWatch).
set -euo pipefail

REL=$(realpath "${1:?dossier de release vérifiée}")
TLS=$(realpath "${2:?dossier TLS (ca.crt, server.crt, server.key)}")
THREADS=${THREADS:-$(nproc)}
CTX=${CTX:-8192}
M="$REL/manifest.json"

llama_image=$(jq -er '.images.llama' "$M")
runtime_image=$(jq -er '.images.gateway_runtime' "$M")
model=$(jq -er '.artifacts[] | select(.kind == "model") | .name' "$M")
for img in "$llama_image" "$runtime_image"; do
  [[ $img == *@sha256:* ]] || { echo "image non épinglée par digest : $img" >&2; exit 1; }
done

log_opts() {
  if [[ -n ${LOG_GROUP:-} ]]; then
    echo "--log-driver awslogs --log-opt awslogs-group=$LOG_GROUP --log-opt awslogs-stream=$1" \
      "${AWS_REGION:+--log-opt awslogs-region=$AWS_REGION}"
  fi
}

docker network inspect agl-internal >/dev/null 2>&1 || docker network create --internal agl-internal >/dev/null
docker network inspect agl-edge >/dev/null 2>&1 || docker network create agl-edge >/dev/null
docker rm -f llama agent-gateway >/dev/null 2>&1 || true

# shellcheck disable=SC2046
docker run -d --name llama --restart unless-stopped \
  --network agl-internal --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges --user 65532:65532 \
  --memory 6g --pids-limit 256 \
  $(log_opts llama) \
  -v "$REL/$model:/models/model.gguf:ro" \
  "$llama_image" \
  -m /models/model.gguf --host 0.0.0.0 --port 8080 \
  --jinja -c "$CTX" -t "$THREADS" --cache-ram 512 --no-slots >/dev/null

# shellcheck disable=SC2046
docker create --name agent-gateway --restart unless-stopped \
  --network agl-edge -p 127.0.0.1:8443:8443 --read-only \
  --cap-drop ALL --security-opt no-new-privileges --user 65532:65532 \
  --memory 256m --pids-limit 128 \
  $(log_opts gateway) \
  -e GATEWAY_LISTEN=0.0.0.0:8443 \
  -v "$REL/agent-gateway:/agent-gateway:ro" \
  -v "$REL/policy.yaml:/etc/agent-gateway/policy.yaml:ro" \
  -v "$TLS:/etc/agent-gateway/tls:ro" \
  "$runtime_image" /agent-gateway >/dev/null
docker network connect agl-internal agent-gateway
docker start agent-gateway >/dev/null

for _ in $(seq 1 120); do
  if docker logs llama 2>&1 | grep -q "server is listening"; then
    echo "pile prête : https://localhost:8443 (mTLS)"
    exit 0
  fi
  sleep 2
done
echo "llama ne démarre pas, voir : docker logs llama" >&2
exit 1
