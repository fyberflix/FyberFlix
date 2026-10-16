#!/usr/bin/env bash
# End-to-end reel test WITHOUT a camera: fake dev user -> upload -> transcode -> playlist.
# Usage: bash scripts/e2e-reel.sh path/to/video.mp4      (stack must be running)
set -euo pipefail
cd "$(dirname "$0")/.."
FILE="${1:?usage: e2e-reel.sh video.mp4}"
GW="${GATEWAY:-http://localhost:8080}"
SEED=$(grep '^AUTH_JWT_SEED=' deploy/.env | cut -d= -f2-)
KID=$(grep '^AUTH_JWT_KID=' deploy/.env | cut -d= -f2-)
TOKEN=$(docker run --rm -e AUTH_JWT_SEED="$SEED" -e AUTH_JWT_KID="$KID" -v "$PWD/tools/devtoken":/src -w /src golang:1.24-alpine3.22 go run .)
SIZE=$(wc -c < "$FILE" | tr -d ' ')
echo "1/4 creating upload ($SIZE bytes)"
RES=$(curl -fsS -X POST "$GW/v1/videos" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"kind\":\"reel\",\"caption\":\"e2e test\",\"content_type\":\"video/mp4\",\"size\":$SIZE}")
ID=$(echo "$RES" | python3 -c 'import sys,json;print(json.load(sys.stdin)["video_id"])')
URL=$(echo "$RES" | python3 -c 'import sys,json;print(json.load(sys.stdin)["upload"]["url"])')
echo "2/4 uploading directly to storage"
curl -fsS -X PUT -H 'Content-Type: video/mp4' --data-binary @"$FILE" "$URL" >/dev/null
echo "3/4 completing"
curl -fsS -X POST "$GW/v1/videos/$ID/complete" -H "Authorization: Bearer $TOKEN"; echo
for i in $(seq 1 60); do
  V=$(curl -fsS "$GW/v1/videos/$ID" -H "Authorization: Bearer $TOKEN")
  S=$(echo "$V" | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])')
  echo "   status: $S"
  [ "$S" = ready ] && break
  [ "$S" = failed ] && { echo "$V"; exit 1; }
  sleep 3
done
[ "$S" = ready ] || { echo "timed out"; exit 1; }
HLS=$(echo "$V" | python3 -c 'import sys,json;print(json.load(sys.stdin)["hls_url"])')
echo "4/4 playlist at $HLS"
curl -fsS "$HLS"
echo "OK  -> open in VLC / Safari: $HLS"
