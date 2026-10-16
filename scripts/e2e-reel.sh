#!/usr/bin/env bash
# End-to-end reel test WITHOUT a camera (Windows Git Bash friendly; no python needed).
# Usage: bash scripts/e2e-reel.sh path/to/video.mp4      (stack must be running)
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
FILE="${1:?usage: e2e-reel.sh video.mp4}"
GW="${GATEWAY:-http://localhost:8080}"
SEED=$(grep '^AUTH_JWT_SEED=' deploy/.env | cut -d= -f2- | tr -d '\r')
KID=$(grep '^AUTH_JWT_KID=' deploy/.env | cut -d= -f2- | tr -d '\r')
TOKEN=$(docker run --rm -e AUTH_JWT_SEED="$SEED" -e AUTH_JWT_KID="$KID" -v "$PWD/tools/devtoken":/src -w /src golang:1.24-alpine3.22 go run . | tr -d '\r\n')
SIZE=$(wc -c < "$FILE" | tr -d ' ')
pick() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1; }

echo "1/4 creating upload ($SIZE bytes)"
RES=$(curl -fsS -X POST "$GW/v1/videos" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"kind\":\"reel\",\"caption\":\"e2e test\",\"content_type\":\"video/mp4\",\"size\":$SIZE}")
ID=$(echo "$RES" | pick video_id)
URL=$(echo "$RES" | pick url | sed 's/\\u0026/\&/g')
[ -n "$ID" ] && [ -n "$URL" ] || { echo "unexpected response: $RES"; exit 1; }

echo "2/4 uploading directly to storage"
curl -fsS -X PUT -H 'Content-Type: video/mp4' --data-binary @"$FILE" "$URL" >/dev/null

echo "3/4 completing"
curl -fsS -X POST "$GW/v1/videos/$ID/complete" -H "Authorization: Bearer $TOKEN"; echo

S=""
for i in $(seq 1 60); do
  V=$(curl -fsS "$GW/v1/videos/$ID" -H "Authorization: Bearer $TOKEN")
  S=$(echo "$V" | pick status)
  echo "   status: $S"
  [ "$S" = ready ] && break
  [ "$S" = failed ] && { echo "$V"; exit 1; }
  sleep 3
done
[ "$S" = ready ] || { echo "timed out"; exit 1; }
HLS=$(echo "$V" | pick hls_url)
echo "4/4 playlist at $HLS"
curl -fsS "$HLS"
echo "OK  -> open this in VLC: $HLS"
