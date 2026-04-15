#!/usr/bin/env bash
# Executed on the server by GitHub Actions via SSH.
# Pulls the new image tag and restarts the compose stack.

set -euo pipefail

APP_DIR="/opt/institutionscan"
IMAGE_TAG="${1:-latest}"
APP_IMAGE="ghcr.io/lucasterix/insitution_scan:${IMAGE_TAG}"

cd "$APP_DIR"

export APP_IMAGE

echo "==> Logging in to GHCR"
if [[ -n "${GHCR_TOKEN:-}" && -n "${GHCR_USER:-}" ]]; then
  echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
fi

echo "==> Pulling image: $APP_IMAGE"
docker compose -f docker-compose.prod.yml pull app worker

echo "==> Restarting stack"
docker compose -f docker-compose.prod.yml up -d --remove-orphans

echo "==> Pruning old images"
docker image prune -f

echo "==> Deploy done. Current containers:"
docker compose -f docker-compose.prod.yml ps
