#!/usr/bin/env sh
# Creates deploy/.env with fresh random secrets. Never commit the result.
set -eu
cd "$(dirname "$0")"
[ -e .env ] && { echo ".env already exists; refusing to overwrite"; exit 1; }
umask 077
cat > .env <<ENV
POSTGRES_PASSWORD=$(openssl rand -hex 24)
FACE_KEYS=k1:$(openssl rand -base64 32)
FACE_ACTIVE_KEY=k1
FACE_SERVICE_TOKEN=$(openssl rand -hex 32)
AUTH_JWT_SEED=$(openssl rand -base64 32)
AUTH_JWT_KID=k1
PUBLIC_BASE_URL=http://localhost:8080
ENV
echo "created deploy/.env"
