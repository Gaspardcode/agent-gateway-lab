#!/usr/bin/env bash
# Chaîne d'approvisionnement : tout ce qui tourne sur l'instance est décrit
# dans un manifeste (hash du modèle, du binaire, de la politique, digest des
# images) et ce manifeste est signé par une clé KMS asymétrique. L'instance
# ne peut que vérifier (kms:Verify) ; seul l'admin peut signer (kms:Sign).
#
#   release.sh build              construit dist/<version>/ (hors ligne, sans AWS)
#   release.sh publish <version>  signe le manifeste avec KMS et envoie tout dans S3
#
# Variables pour publish : RELEASE_BUCKET, KMS_KEY (alias/agl-release par défaut).
set -euo pipefail

ROOT=$(realpath "$(dirname "$0")/..")
SRC="$ROOT/model/source.json"
CACHE="$ROOT/.cache/models"
AWS=${AWS:-aws}

sha() { sha256sum "$1" | cut -d' ' -f1; }

fetch_model() {
  local file rev repo want
  file=$(jq -er .file "$SRC"); rev=$(jq -er .revision "$SRC")
  repo=$(jq -er .repo "$SRC"); want=$(jq -er .sha256 "$SRC")
  mkdir -p "$CACHE"
  if [[ ! -f $CACHE/$file ]]; then
    curl -fL --retry 3 -o "$CACHE/$file.part" "https://huggingface.co/$repo/resolve/$rev/$file"
    mv "$CACHE/$file.part" "$CACHE/$file"
  fi
  [[ $(sha "$CACHE/$file") == "$want" ]] || { echo "SHA-256 du modèle différent de l'épinglage" >&2; exit 1; }
  # GGUF uniquement : pas de pickle, pas de code exécuté au chargement.
  [[ $(head -c4 "$CACHE/$file") == GGUF ]] || { echo "pas un fichier GGUF" >&2; exit 1; }
}

build_gateway() {
  docker run --rm -v agw-cargo:/usr/local/cargo/registry -v "$ROOT/gateway":/src -w /src \
    -e CARGO_TARGET_DIR=/src/target rust:1-bookworm sh -ec '
      apt-get update -qq >/dev/null && apt-get install -y -qq musl-tools >/dev/null
      rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1
      cargo test --release --quiet
      cargo build --release --locked --target x86_64-unknown-linux-musl --quiet
      chown -R '"$(id -u):$(id -g)"' target Cargo.lock'
}

cmd_build() {
  local seq ver out file
  seq=$(date -u +%s); ver=$(date -u +%Y%m%d-%H%M%S)
  out="$ROOT/dist/$ver"
  fetch_model
  build_gateway
  mkdir -p "$out"
  file=$(jq -er .file "$SRC")
  ln -f "$CACHE/$file" "$out/$file" 2>/dev/null || cp "$CACHE/$file" "$out/$file"
  install -m 0755 "$ROOT/gateway/target/x86_64-unknown-linux-musl/release/agent-gateway" "$out/agent-gateway"
  install -m 0644 "$ROOT/gateway/policy.yaml" "$out/policy.yaml"

  jq -n --arg ver "$ver" --argjson seq "$seq" \
    --arg commit "$(git -C "$ROOT" rev-parse --verify -q HEAD || echo none)" \
    --arg dirty "$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null | wc -l)" \
    --slurpfile src "$SRC" \
    --arg msha "$(sha "$out/$file")" --arg msize "$(stat -c%s "$out/$file")" \
    --arg gsha "$(sha "$out/agent-gateway")" --arg gsize "$(stat -c%s "$out/agent-gateway")" \
    --arg psha "$(sha "$out/policy.yaml")" --arg psize "$(stat -c%s "$out/policy.yaml")" \
    '{
      version: $ver, seq: $seq, source_commit: $commit, uncommitted_changes: ($dirty|tonumber),
      model_source: {repo: $src[0].repo, revision: $src[0].revision, license: $src[0].license},
      images: {llama: $src[0].images.llama, gateway_runtime: $src[0].images.gateway_runtime},
      artifacts: [
        {kind: "model",   name: $src[0].file,    sha256: $msha, size: ($msize|tonumber), s3_key: ("models/" + $msha + ".gguf")},
        {kind: "gateway", name: "agent-gateway", sha256: $gsha, size: ($gsize|tonumber), s3_key: ("releases/" + $ver + "/agent-gateway")},
        {kind: "policy",  name: "policy.yaml",   sha256: $psha, size: ($psize|tonumber), s3_key: ("releases/" + $ver + "/policy.yaml")}
      ]
    }' > "$out/manifest.json"
  echo "release construite : $out"
  jq -c '{version, seq, source_commit, uncommitted_changes}' "$out/manifest.json"
}

cmd_publish() {
  local ver=${1:?version} out bucket key a
  out="$ROOT/dist/$ver"; bucket=${RELEASE_BUCKET:?RELEASE_BUCKET}; key=${KMS_KEY:-alias/agl-release}
  [[ -f $out/manifest.json ]] || { echo "pas de manifeste dans $out" >&2; exit 1; }
  if [[ $(jq .uncommitted_changes "$out/manifest.json") != 0 ]]; then
    echo "refus : la release a été construite avec des modifications non commitées" >&2; exit 1
  fi
  $AWS kms sign --key-id "$key" --message "fileb://$out/manifest.json" --message-type RAW \
    --signing-algorithm ECDSA_SHA_256 --query Signature --output text | base64 -d > "$out/manifest.sig"
  for a in $(jq -c '.artifacts[]' "$out/manifest.json"); do
    local name s3 sha
    name=$(jq -r .name <<<"$a"); s3=$(jq -r .s3_key <<<"$a"); sha=$(jq -r .sha256 <<<"$a")
    if $AWS s3api head-object --bucket "$bucket" --key "$s3" >/dev/null 2>&1; then
      echo "déjà présent : $s3"; continue
    fi
    $AWS s3 cp "$out/$name" "s3://$bucket/$s3" --only-show-errors --metadata "sha256=$sha"
    echo "envoyé : $s3"
  done
  $AWS s3 cp "$out/manifest.json" "s3://$bucket/releases/$ver/manifest.json" --only-show-errors
  $AWS s3 cp "$out/manifest.sig" "s3://$bucket/releases/$ver/manifest.sig" --only-show-errors
  # Pointeur publié en dernier : une release incomplète n'est jamais « courante ».
  printf '%s\n' "$ver" | $AWS s3 cp - "s3://$bucket/releases/current" --only-show-errors
  echo "release $ver publiée et signée (clé $key)"
}

case ${1:-} in
  build) cmd_build ;;
  publish) shift; cmd_publish "$@" ;;
  *) sed -n '2,11p' "$0"; exit 1 ;;
esac
