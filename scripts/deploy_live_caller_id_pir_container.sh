#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${ROOT_DIR}/wrangler.live-caller-id-pir.toml"
IMAGE_NAME="callshield-live-caller-id-pir"
TAG="${1:-}"

if [[ -z "${TAG}" ]]; then
  GIT_SHA="$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo local)"
  TAG="$(date -u +%Y%m%d%H%M%S)-${GIT_SHA}"
fi

LOCAL_IMAGE="${IMAGE_NAME}:${TAG}"

cd "${ROOT_DIR}"

echo "Building ${LOCAL_IMAGE} for linux/amd64..."
docker build \
  --platform linux/amd64 \
  -f Dockerfile.live-caller-id-pir \
  -t "${LOCAL_IMAGE}" \
  .

echo "Pushing ${LOCAL_IMAGE} to Cloudflare managed registry..."
wrangler containers push "${LOCAL_IMAGE}" --config "${CONFIG_FILE}"

echo
echo "Push complete for local image: ${LOCAL_IMAGE}"
echo "Use the registry.cloudflare.com image reference printed by Wrangler in ${CONFIG_FILE}."
