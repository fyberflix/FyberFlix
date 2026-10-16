#!/usr/bin/env bash
# Build and push pinned images to Docker Hub.
# Usage: DOCKERHUB_USER=yourname bash scripts/release.sh 0.1.0     (run `docker login` first)
# Optional: PLATFORMS=linux/amd64,linux/arm64
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:?usage: release.sh VERSION (e.g. 0.1.0)}"
USER_="${DOCKERHUB_USER:?set DOCKERHUB_USER}"
PLATFORMS="${PLATFORMS:-linux/amd64}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION must look like 1.2.3"; exit 1; }
build() { # name dockerfile context [target]
  local img="docker.io/$USER_/fyberflix-$1:$VERSION"
  echo "== $img"
  docker buildx build --platform "$PLATFORMS" -f "$2" ${4:+--target "$4"} -t "$img" --push "$3"
  docker buildx imagetools inspect "$img" | grep -m1 Digest | sed "s#^#   #"
}
build gateway         services/gateway/Dockerfile  services/gateway
build auth            services/auth/Dockerfile     services/auth
build face            services/face/Dockerfile     services/face
build risk            services/risk/Dockerfile     services/risk
build content-api     services/content/Dockerfile  .  api
build content-worker  services/content/Dockerfile  .  worker
echo "Done. Use: REGISTRY=docker.io/$USER_ VERSION=$VERSION docker compose -f deploy/docker-compose.release.yml up -d"
