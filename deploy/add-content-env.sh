#!/usr/bin/env sh
# Adds storage/content settings to deploy/.env (once). Never prints secrets.
set -eu
cd "$(dirname "$0")"
[ -f .env ] || { echo "run: sh deploy/gen-env.sh first"; exit 1; }
if grep -q '^S3_ACCESS_KEY=' .env; then echo "content settings already present"; exit 0; fi
umask 077
cat >> .env <<ENV
COMPOSE_FILE=docker-compose.yml:docker-compose.content.yml
MINIO_ROOT_USER=fyberadmin
MINIO_ROOT_PASSWORD=$(openssl rand -hex 24)
S3_ACCESS_KEY=fyberapp
S3_SECRET_KEY=$(openssl rand -hex 24)
ENV
echo "content settings added to deploy/.env"
