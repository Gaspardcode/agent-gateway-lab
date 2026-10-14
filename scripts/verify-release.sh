#!/usr/bin/env bash
# Exécuté au démarrage de l'instance (agl-boot.service), avant tout conteneur.
# 1. lit le pointeur releases/current ;  2. vérifie la signature KMS du manifeste ;
# 3. refuse un retour à une release plus ancienne (anti-rollback local) ;
# 4. télécharge chaque artefact et contrôle son SHA-256 ;  5. lance la pile.
# Tout échec est envoyé dans CloudWatch (flux « boot ») et rien ne démarre.
set -euo pipefail

: "${RELEASE_BUCKET:?}" "${KMS_KEY:?}" "${LOG_GROUP:?}" "${AWS_REGION:?}"
BASE=/opt/agl
STATE=/var/lib/agl
TLS=/etc/agent-gateway/tls
SSM_PREFIX=${SSM_PREFIX:-/agl/tls}
mkdir -p "$BASE/releases" "$BASE/models" "$STATE" "$TLS"

event() { # event <nom> <détail> : une ligne JSON dans le flux « boot »
  local msg
  msg=$(jq -cn --arg e "$1" --arg d "$2" --arg h "$(hostname)" '{event: $e, detail: $d, host: $h}')
  echo "$msg"
  aws logs create-log-stream --log-group-name "$LOG_GROUP" --log-stream-name boot 2>/dev/null || true
  aws logs put-log-events --log-group-name "$LOG_GROUP" --log-stream-name boot \
    --log-events "$(jq -cn --arg m "$msg" --argjson t "$(date +%s%3N)" '[{timestamp: $t, message: $m}]')" \
    >/dev/null || true
}
fail() { event release_verification_failed "$1"; exit 1; }

# Pas encore de release : état normal au premier démarrage, pas une alerte.
ver=$(aws s3 cp "s3://$RELEASE_BUCKET/releases/current" - 2>/dev/null | tr -d '[:space:]') \
  || { event release_pending "aucune release publiée"; exit 1; }
[[ $ver =~ ^[0-9]{8}-[0-9]{6}$ ]] || fail "version invalide : $ver"
dir="$BASE/releases/$ver"
mkdir -p "$dir"
aws s3 cp "s3://$RELEASE_BUCKET/releases/$ver/manifest.json" "$dir/manifest.json" --only-show-errors
aws s3 cp "s3://$RELEASE_BUCKET/releases/$ver/manifest.sig" "$dir/manifest.sig" --only-show-errors

valid=$(aws kms verify --key-id "$KMS_KEY" --message "fileb://$dir/manifest.json" --message-type RAW \
  --signing-algorithm ECDSA_SHA_256 --signature "fileb://$dir/manifest.sig" \
  --query SignatureValid --output text 2>/dev/null) || valid=false
[[ $valid == True || $valid == true ]] || fail "signature KMS invalide pour $ver"
[[ $(jq -r .version "$dir/manifest.json") == "$ver" ]] || fail "le manifeste ne correspond pas au pointeur"

seq=$(jq -er .seq "$dir/manifest.json")
last=$(cat "$STATE/last-seq" 2>/dev/null || echo 0)
(( seq >= last )) || fail "rollback refusé : seq $seq < $last"

for a in $(jq -c '.artifacts[]' "$dir/manifest.json"); do
  name=$(jq -r .name <<<"$a"); s3=$(jq -r .s3_key <<<"$a"); want=$(jq -r .sha256 <<<"$a")
  if [[ $(jq -r .kind <<<"$a") == model ]]; then
    cached="$BASE/models/$want.gguf"
    [[ -f $cached ]] || aws s3 cp "s3://$RELEASE_BUCKET/$s3" "$cached" --only-show-errors
    ln -f "$cached" "$dir/$name"
  else
    aws s3 cp "s3://$RELEASE_BUCKET/$s3" "$dir/$name" --only-show-errors
  fi
  got=$(sha256sum "$dir/$name" | cut -d' ' -f1)
  [[ $got == "$want" ]] || { rm -f "$dir/$name" "${cached:-}"; fail "SHA-256 différent pour $name"; }
done
chmod 0755 "$dir/agent-gateway"
chmod 0644 "$dir"/*.gguf "$dir/policy.yaml"
echo "$seq" > "$STATE/last-seq"

for f in ca.crt server.crt server.key; do
  aws ssm get-parameter --name "$SSM_PREFIX/$f" --with-decryption --query Parameter.Value --output text > "$TLS/$f" \
    || fail "paramètre SSM $SSM_PREFIX/$f absent"
done
chown -R 65532:65532 "$TLS" && chmod 0500 "$TLS" && chmod 0400 "$TLS"/*

for img in $(jq -r '.images[]' "$dir/manifest.json"); do docker pull -q "$img" >/dev/null; done
event release_verified "$ver"
LOG_GROUP=$LOG_GROUP /opt/agl/bin/run-stack.sh "$dir" "$TLS"
