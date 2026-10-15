#!/usr/bin/env bash
# FyberFlix smoke test: run AFTER `docker compose up -d --build` is healthy.
#   bash scripts/smoke.sh                  (talks to http://127.0.0.1:8080)
#   BASE=https://FyberFlix.zeaipc.in bash scripts/smoke.sh
# It creates ONE throw-away signup session (expires on its own). It does not
# create a real account: that needs a live camera. Never prints secrets.
set -u
cd "$(dirname "$0")/.." || exit 2
BASE=${BASE:-http://127.0.0.1:8080}
COMPOSE="docker compose -f deploy/docker-compose.yml"
if [ -t 1 ]; then R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'; else R=; G=; Y=; B=; N=; fi
FAILS=0; PASSES=0
ok()  { PASSES=$((PASSES+1)); echo "  ${G}✔${N} $*"; }
bad() { FAILS=$((FAILS+1));   echo "  ${R}✘ FAIL${N} $*"; }
sect(){ echo; echo "${B}== $* ==${N}"; }
command -v curl >/dev/null || { echo "curl is required"; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required (JSON parsing)"; exit 2; }

BODY=""; CODE=""
# req METHOD PATH [JSON] [BEARER]
req() {
  local m=$1 p=$2 d=${3:-} t=${4:-}
  local args=(-s -m 20 -o /tmp/.fyber_smoke_body -w '%{http_code}' -X "$m")
  [ -n "$t" ] && args+=(-H "Authorization: Bearer $t")
  [ -n "$d" ] && args+=(-H 'Content-Type: application/json' -d "$d")
  CODE=$(curl "${args[@]}" "$BASE$p" 2>/dev/null); BODY=$(cat /tmp/.fyber_smoke_body 2>/dev/null)
}
jget() { printf '%s' "$BODY" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
    for k in sys.argv[1].split("."):
        d=d[int(k)] if isinstance(d,list) else d[k]
    print(d if not isinstance(d,(list,dict)) else json.dumps(d))
except Exception: pass' "$1"; }
expect_code() { # label wanted_codes(space-separated)
  for c in $2; do [ "$CODE" = "$c" ] && { ok "$1 (HTTP $CODE)"; return 0; }; done
  bad "$1: expected HTTP $2, got $CODE. Body: $(printf '%s' "$BODY" | head -c 300)"; return 1
}

sect "1. Gateway is up ($BASE)"
up=0
for i in $(seq 1 60); do
  req GET /healthz; [ "$CODE" = "200" ] && { up=1; break; }
  sleep 2
done
if [ $up = 1 ]; then ok "GET /healthz = 200"; else
  bad "gateway not answering on $BASE after 120 s"
  echo "      look at logs:  docker compose -f deploy/docker-compose.yml ps ; docker compose -f deploy/docker-compose.yml logs --tail=80 gateway auth face"
  exit 1
fi
req GET /.well-known/jwks.json
expect_code "JWKS endpoint answers" 200 && { [ -n "$(jget keys.0.kty)" ] && ok "JWKS has a signing key (kty=$(jget keys.0.kty))" || bad "JWKS has no keys"; }

sect "2. Security edges"
req GET /v1/me; expect_code "GET /v1/me without a token is refused" "401 403"
req GET /v1/staff/users/lookup; expect_code "staff API is not reachable from outside STAFF_CIDRS" "401 403 404"
req POST /v1/signup/number '{"number":"123456789"}' "not-a-real-token"; expect_code "forged signup session token is refused" "401 403"
req GET /v1/profiles/nobody-here-xyz; expect_code "unknown profile is 404" 404

sect "3. Signup flow up to the camera step"
req POST /v1/signup/sessions
if expect_code "start signup session" "200 201"; then
  TOK=$(jget session_token); NOFF=$(jget number_offers | python3 -c 'import sys,json
try: print(len(json.load(sys.stdin)))
except Exception: print(0)')
  [ -n "$TOK" ] && ok "got a session token" || bad "no session_token in response"
  [ "$NOFF" = "10" ] && ok "10 FyberFlix number options offered" || bad "expected 10 number options, got $NOFF"
  NUM=$(jget number_offers.0)
  printf '%s' "$NUM" | grep -qE '^[0-9]{9}$' && ok "offered number is 9 digits" || bad "offered number is not 9 digits: '$NUM'"

  req POST /v1/signup/number "{\"number\":\"$NUM\"}" "$TOK"; expect_code "choose number $NUM" 200

  for nm in ZEAIPC Zikriyon ZikriyonOS ZikriyonAI; do
    req GET "/v1/signup/cable-name/check?name=$nm" "" "$TOK"
    if [ "$CODE" = "200" ] && [ "$(jget available)" = "False" ]; then ok "reserved name '$nm' is NOT available"; else bad "reserved name '$nm' should be unavailable: HTTP $CODE $(printf '%s' "$BODY" | head -c 200)"; fi
  done
  req GET "/v1/signup/cable-name/check?name=ab" "" "$TOK"
  [ "$(jget available)" = "False" ] && ok "too-short name 'ab' rejected" || bad "name 'ab' should be rejected"

  NAME="smoke-$(date +%s)"
  req GET "/v1/signup/cable-name/check?name=$NAME" "" "$TOK"
  [ "$CODE" = "200" ] && [ "$(jget available)" = "True" ] && ok "fresh name '$NAME' is available" || bad "fresh name should be available: HTTP $CODE $BODY"
  req POST /v1/signup/cable-name "{\"name\":\"$NAME\"}" "$TOK"; expect_code "choose Fyber Cable name" 200

  req POST /v1/signup/face/challenge "" "$TOK"
  if [ "$CODE" = "403" ] && printf '%s' "$BODY" | grep -q consent_required; then ok "face step is blocked until biometric consent (DPDP gate)"; else bad "face challenge before consent should be 403 consent_required, got $CODE"; fi

  req POST /v1/signup/consent '{"biometric_consent":true,"terms_version":"smoke-test"}' "$TOK"; expect_code "record biometric consent" 200

  req POST /v1/signup/face/challenge "" "$TOK"
  if expect_code "face challenge issued (auth -> face -> redis all connected)" 200; then
    [ -n "$(jget challenge_id)" ] && ok "challenge has an id and steps: $(jget steps)" || bad "challenge response has no challenge_id"
  fi
fi

sect "4. Databases (via docker compose)"
if docker info >/dev/null 2>&1; then
  for db in fyberflix_auth fyberflix_face; do
    n=$($COMPOSE exec -T postgres psql -U fyber -d "$db" -tAc "select count(*) from information_schema.tables where table_schema='public'" 2>/dev/null | tr -d '[:space:]')
    [ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null && ok "$db has $n tables (migrations applied)" || bad "$db has no tables: migrations did not run (docker compose logs migrate-auth migrate-face)"
  done
  v=$($COMPOSE exec -T postgres psql -U fyber -d fyberflix_auth -tAc "select version||' dirty='||dirty from schema_migrations" 2>/dev/null | tr -d '[:space:]')
  case "$v" in *dirty=f*|*dirty=false*) ok "auth migration state clean (version ${v%%dirty*})" ;; "") bad "cannot read schema_migrations" ;; *) bad "auth migrations are DIRTY: $v" ;; esac
  for s in postgres redis face risk auth gateway; do
    st=$($COMPOSE ps --format '{{.Service}} {{.State}}' 2>/dev/null | awk -v s="$s" '$1==s{print $2}')
    [ "$st" = "running" ] && ok "container '$s' is running" || bad "container '$s' state: '${st:-not found}'"
  done
else
  echo "  (docker not usable here: database and container checks skipped)"
fi

echo
echo "${B}Result:${N} ${G}$PASSES passed${N}, ${R}$FAILS failures${N}"
if [ $FAILS -gt 0 ]; then echo "${R}Smoke test failed. Send me the FAIL lines plus:  docker compose -f deploy/docker-compose.yml logs --tail=60${N}"; exit 1; fi
echo "${G}Backend wiring works end to end up to the camera step.${N}"
echo "Not covered here: a real face enrol/verify needs a camera client (web app, next build step)."
