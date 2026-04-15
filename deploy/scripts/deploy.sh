#!/usr/bin/env bash
# Executed on the server by GitHub Actions via SSH.
# Pulls the new image tag and restarts the compose stack.

set -euo pipefail

APP_DIR="/opt/institutionscan"
IMAGE_TAG="${1:-latest}"
APP_IMAGE="ghcr.io/lucasterix/insitution_scan:${IMAGE_TAG}"

cd "$APP_DIR"

# Persist APP_IMAGE into .env so ad-hoc `docker compose` commands on the host
# (e.g. `docker compose -f docker-compose.prod.yml ps`) pick up the current tag.
touch .env
if grep -q '^APP_IMAGE=' .env; then
  sed -i "s|^APP_IMAGE=.*|APP_IMAGE=${APP_IMAGE}|" .env
else
  echo "APP_IMAGE=${APP_IMAGE}" >> .env
fi

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
