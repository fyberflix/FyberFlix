#!/usr/bin/env bash
# FyberFlix preflight: checks everything it can BEFORE you start the stack.
# Run from anywhere:   bash scripts/preflight.sh
# Flags:  --no-go  --no-python  --no-docker  --no-net   (skip that group)
#         --fast   (same as --no-go --no-python --no-net)
# Exit code: 0 = no failures (warnings allowed), 1 = at least one failure.
# It never prints secret values.
set -u
cd "$(dirname "$0")/.." || exit 2

DO_GO=1; DO_PY=1; DO_DOCKER=1; DO_NET=1
for a in "$@"; do
  case "$a" in
    --no-go) DO_GO=0 ;;
    --no-python) DO_PY=0 ;;
    --no-docker) DO_DOCKER=0 ;;
    --no-net) DO_NET=0 ;;
    --fast) DO_GO=0; DO_PY=0; DO_NET=0 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown flag: $a"; exit 2 ;;
  esac
done

if [ -t 1 ]; then R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'; else R=; G=; Y=; B=; N=; fi
FAILS=0; WARNS=0; PASSES=0
ok()   { PASSES=$((PASSES+1)); echo "  ${G}✔${N} $*"; }
bad()  { FAILS=$((FAILS+1));   echo "  ${R}✘ FAIL${N} $*"; }
warn() { WARNS=$((WARNS+1));   echo "  ${Y}! WARN${N} $*"; }
note() { echo "      $*"; }
sect() { echo; echo "${B}== $* ==${N}"; }
have() { command -v "$1" >/dev/null 2>&1; }
indent() { sed 's/^/      /' | head -n "${1:-25}"; }
TMO=""; have timeout && TMO="timeout 900"

PY=python3; [ -x .venv/bin/python ] && PY="$PWD/.venv/bin/python"

SRC_GLOBS=(-name '*.go' -o -name '*.py' -o -name '*.sql' -o -name '*.yml' -o -name '*.yaml' -o -name '*.sh' -o -name '*.toml' -o -name 'Dockerfile' -o -name 'go.mod')
PRUNE=(-name .git -o -name .venv -o -name node_modules -o -name __pycache__ -o -name models)

# ---------------------------------------------------------------- 1. tools
sect "1. Tools on this machine"
for t in git openssl curl; do have "$t" && ok "$t found" || bad "$t is missing (install it)"; done
if [ $DO_DOCKER = 1 ]; then
  if have docker; then
    ok "docker found"
    if docker compose version >/dev/null 2>&1; then ok "docker compose v2 found"; else bad "docker compose v2 plugin missing"; fi
    if docker info >/dev/null 2>&1; then ok "docker daemon is running"; else bad "docker is installed but the daemon is not running / no permission"; fi
  else
    bad "docker is missing. FyberFlix runs in Docker: use GitHub Codespaces or a Linux PC (Android/Termux cannot run Docker)"
  fi
fi
if [ $DO_GO = 1 ]; then
  if have go; then
    gv=$(go env GOVERSION 2>/dev/null | sed 's/^go//')
    minor=$(echo "$gv" | cut -d. -f2)
    if [ "${minor:-0}" -ge 24 ] 2>/dev/null; then ok "go $gv"; else warn "go $gv found, project wants >= 1.24 (go will try to download a newer toolchain)"; fi
  else warn "go not installed: Go tests skipped (Docker still builds Go for you). Use --no-go to silence"; DO_GO=0; fi
fi
if [ $DO_PY = 1 ]; then
  if have "$PY"; then ok "python $($PY -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])')"; else warn "python3 not installed: Python checks skipped"; DO_PY=0; fi
fi

# ---------------------------------------------------------------- 2. file tree
sect "2. Every file is present and not empty"
REQ=(
 .gitignore
 deploy/docker-compose.yml deploy/gen-env.sh deploy/postgres-init/01-databases.sql
 libs/authz/go.mod libs/authz/authz.go libs/authz/authz_test.go
 services/gateway/go.mod services/gateway/Dockerfile services/gateway/cmd/gateway/main.go
 services/gateway/internal/gateway/config.go services/gateway/internal/gateway/gateway.go
 services/gateway/internal/gateway/limiter.go services/gateway/internal/gateway/gateway_test.go
 services/auth/go.mod services/auth/Dockerfile services/auth/cmd/auth/main.go
 services/auth/internal/config/config.go services/auth/internal/config/account.go services/auth/internal/config/risk.go
 services/auth/internal/identity/cablename.go services/auth/internal/identity/number.go services/auth/internal/identity/identity_test.go
 services/auth/internal/token/token.go services/auth/internal/token/token_test.go
 services/auth/internal/faceclient/client.go services/auth/internal/faceclient/client_test.go
 services/auth/internal/riskclient/client.go services/auth/internal/riskclient/client_test.go
 services/auth/internal/mailer/mailer.go services/auth/internal/mailer/mailer_test.go
 services/auth/internal/janitor/janitor.go services/auth/internal/janitor/janitor_test.go
 services/auth/internal/httpapi/server.go services/auth/internal/httpapi/signup.go services/auth/internal/httpapi/face_signup.go
 services/auth/internal/httpapi/auth_flow.go services/auth/internal/httpapi/multipart.go services/auth/internal/httpapi/account.go
 services/auth/internal/httpapi/staff.go services/auth/internal/httpapi/risk.go services/auth/internal/httpapi/profile.go
 services/auth/internal/httpapi/recovery.go services/auth/internal/httpapi/flow_test.go services/auth/internal/httpapi/account_test.go
 services/auth/internal/httpapi/risk_test.go services/auth/internal/httpapi/recovery_test.go
 services/auth/internal/store/store.go services/auth/internal/store/account.go services/auth/internal/store/accountstore.go
 services/auth/internal/store/risk.go services/auth/internal/store/recovery.go
 services/face/pyproject.toml services/face/Dockerfile services/face/scripts/fetch_models.py
 services/face/app/config.py services/face/app/crypto.py services/face/app/vision.py services/face/app/liveness.py
 services/face/app/state.py services/face/app/store.py services/face/app/service.py services/face/app/main.py
 services/face/migrations/0001_face_templates.up.sql services/face/migrations/0001_face_templates.down.sql
 services/face/tests/test_face.py
 services/risk/pyproject.toml services/risk/Dockerfile services/risk/rules/auth_risk.yaml services/risk/rules/login_fail.yaml
 services/risk/app/engine.py services/risk/app/handler.py services/risk/app/main.py services/risk/tests/test_handler.py
)
missing=0; empty=0
for f in "${REQ[@]}"; do
  if [ ! -f "$f" ]; then bad "missing file: $f"; missing=$((missing+1))
  elif [ ! -s "$f" ]; then bad "file is EMPTY (paste lost?): $f"; empty=$((empty+1)); fi
done
[ $missing = 0 ] && [ $empty = 0 ] && ok "all ${#REQ[@]} required files exist and have content"
[ -d fyberflix ] || [ -d FyberFlix ] && warn "there is a nested fyberflix/ folder inside the repo: the tree must start at the repo root (services/, deploy/, libs/)"

sect "3. Copy-paste damage and leftovers"
bad_files=$(find . \( "${PRUNE[@]}" \) -prune -o -type f \( "${SRC_GLOBS[@]}" \) -print 2>/dev/null | xargs grep -lE '^[[:space:]]*```' 2>/dev/null)
[ -z "$bad_files" ] && ok "no stray markdown code fences (\`\`\`) inside source files" || { bad "markdown fence \`\`\` pasted into source files:"; echo "$bad_files" | indent; }
crlf=$(find . \( "${PRUNE[@]}" \) -prune -o -type f -name '*.sh' -print 2>/dev/null | xargs grep -l $'\r' 2>/dev/null)
[ -z "$crlf" ] && ok "shell scripts use Unix line endings" || { bad "Windows line endings (CRLF) in shell scripts (they will not run):"; echo "$crlf" | indent; note "fix:  sed -i 's/\\r\$//' <file>"; }
stale=0
for s in services/auth/internal/httpapi/server_test.go db/migrations services/auth/migrations/0001_identity_core.sql services/face/migrations/0001_face_templates.sql; do
  if [ -e "$s" ]; then bad "leftover from an old attempt, delete it:  $s"; stale=1; fi
done
[ $stale = 0 ] && ok "no leftover files from older drafts"

sect "4. Database migrations"
check_migrations() {
  local dir=$1 n=0 f base num problems=0
  [ -d "$dir" ] || { bad "$dir missing"; return; }
  for f in "$dir"/*.sql; do
    [ -e "$f" ] || continue
    case "$f" in *.up.sql|*.down.sql) ;; *) bad "$f must end in .up.sql or .down.sql"; problems=1 ;; esac
  done
  for f in $(ls "$dir"/*.up.sql 2>/dev/null | sort); do
    base=${f%.up.sql}; num=$(basename "$f" | cut -d_ -f1); n=$((n+1))
    [ -f "$base.down.sql" ] || { bad "no matching .down.sql for $f"; problems=1; }
    [ "$((10#$num))" = "$n" ] || { bad "migration numbering gap/duplicate near $f (expected $(printf '%04d' $n))"; problems=1; }
    [ -s "$f" ] || { bad "empty migration $f"; problems=1; }
  done
  [ $n = 0 ] && { bad "no .up.sql files in $dir"; return; }
  [ $problems = 0 ] && ok "$dir: $n migrations, up/down paired, numbering contiguous"
}
check_migrations services/auth/migrations
check_migrations services/face/migrations
[ -f deploy/postgres-init/01-databases.sql ] && { grep -q fyberflix_auth deploy/postgres-init/01-databases.sql && grep -q fyberflix_face deploy/postgres-init/01-databases.sql && ok "postgres-init creates both databases" || bad "deploy/postgres-init/01-databases.sql must create fyberflix_auth and fyberflix_face"; }

sect "5. Go module paths (GitHub: FyberFlix/FyberFlix)"
paths=$(grep -rhoE 'github\.com/[A-Za-z0-9_.-]+/[Ff]yber[Ff]lix' --include=go.mod --include='*.go' services libs 2>/dev/null | sort -u)
cnt=$(printf '%s\n' "$paths" | grep -c .)
if [ "$cnt" -gt 1 ]; then
  bad "mixed module paths found (Go is case-sensitive, all must match exactly):"; echo "$paths" | indent
  note "to unify:  grep -rlE 'github\\.com/[A-Za-z0-9_.-]+/[Ff]yber[Ff]lix' services libs | xargs sed -i -E 's#github\\.com/[A-Za-z0-9_.-]+/[Ff]yber[Ff]lix#github.com/fyberflix/fyberflix#g'"
elif [ "$cnt" = 1 ]; then
  ok "one consistent module path: $paths"
  [ "$paths" = "github.com/fyberflix/fyberflix" ] || { warn "module path is '$paths' (works, but the repo is github.com/FyberFlix/FyberFlix; recommended: github.com/fyberflix/fyberflix)"; note "rename:  grep -rlF '$paths' services libs | xargs sed -i 's#$paths#github.com/fyberflix/fyberflix#g'"; }
else ok "no module paths to compare"; fi
for gm in services/auth services/gateway libs/authz; do
  [ -f "$gm/go.mod" ] || continue
  grep -E '^[[:space:]]*(replace .*=>|.*=>)[[:space:]]*\.\.?/' "$gm/go.mod" 2>/dev/null | sed -E 's/.*=>[[:space:]]*//' | while read -r rp; do
    [ -d "$gm/$rp" ] && warn "$gm/go.mod uses local replace '$rp': the Docker build context must include that folder" || bad "$gm/go.mod replace target not found: $rp"
  done
done

# ---------------------------------------------------------------- 6. Go
if [ $DO_GO = 1 ]; then
  sect "6. Go: tidy, format, vet, tests (needs internet the first time)"
  for m in services/auth services/gateway libs/authz; do
    [ -f "$m/go.mod" ] || continue
    echo "  -- $m"
    out=$(cd "$m" && $TMO go mod tidy 2>&1) && ok "$m: go mod tidy (go.sum is now up to date: commit it)" || { bad "$m: go mod tidy failed (no internet, or a bad import):"; echo "$out" | indent; continue; }
    out=$(cd "$m" && gofmt -l . 2>&1)
    [ -z "$out" ] && ok "$m: gofmt clean" || { bad "$m: not gofmt-formatted (fix:  cd $m && gofmt -w .):"; echo "$out" | indent; }
    out=$(cd "$m" && $TMO go vet ./... 2>&1) && ok "$m: go vet" || { bad "$m: go vet reported problems:"; echo "$out" | indent 40; }
    out=$(cd "$m" && $TMO go test -count=1 ./... 2>&1) && ok "$m: go test passed" || { bad "$m: go test failed:"; echo "$out" | indent 60; }
  done
fi

# ---------------------------------------------------------------- 7. Python
if [ $DO_PY = 1 ]; then
  sect "7. Python: syntax, YAML rules, unit tests"
  PYABS=$(command -v "$PY")
  out=$(find services -name '*.py' -not -path '*/.venv/*' -print0 | xargs -0 "$PY" -c '
import ast,sys
bad=0
for p in sys.argv[1:]:
    try: ast.parse(open(p,encoding="utf-8").read(),p)
    except SyntaxError as e: print(f"{p}:{e.lineno}: {e.msg}"); bad=1
sys.exit(bad)' 2>&1) && ok "all Python files parse" || { bad "Python syntax errors:"; echo "$out" | indent; }
  if "$PY" -c 'import yaml' 2>/dev/null; then
    out=$("$PY" -c '
import sys,yaml,glob
bad=0
for p in glob.glob("services/risk/rules/*.yaml"):
    try:
        d=yaml.safe_load(open(p)); assert isinstance(d,dict) and d.get("rules"), "no rules: key"
    except Exception as e: print(p,e); bad=1
sys.exit(bad)' 2>&1) && ok "risk rule files are valid YAML with rules" || { bad "risk rule YAML problem:"; echo "$out" | indent; }
  else warn "PyYAML not installed: YAML check skipped (pip install pyyaml)"; fi
  out=$(cd services/face && $TMO "$PYABS" -m unittest tests.test_face 2>&1); rc=$?
  if [ $rc = 0 ]; then ok "face service unit tests passed"
  elif echo "$out" | grep -qE 'ModuleNotFoundError|ImportError'; then warn "face tests skipped: missing Python packages (pip install numpy cryptography)"; echo "$out" | grep -E 'Error' | head -2 | indent
  else bad "face service unit tests failed:"; echo "$out" | indent 40; fi
  if "$PY" -c 'import pytest' 2>/dev/null; then
    out=$(cd services/risk && $TMO "$PYABS" -m pytest -q 2>&1); rc=$?
    [ $rc = 0 ] && ok "risk service tests passed ($(echo "$out" | tail -1))" || { bad "risk service tests failed:"; echo "$out" | indent 40; }
  else warn "pytest not installed: risk tests skipped (pip install pytest)"; fi
  "$PY" -c 'import zikriyon_prism' 2>/dev/null && ok "zikriyon-prism is installed locally" || note "(zikriyon-prism not installed locally: fine, the risk container installs it)"
fi

# ---------------------------------------------------------------- 8. face models pin
sect "8. Face model checksums"
if [ -s services/face/models/SHA256SUMS ]; then
  n=$(grep -c . services/face/models/SHA256SUMS)
  [ "$n" -ge 2 ] && ok "services/face/models/SHA256SUMS present ($n models pinned)" || bad "SHA256SUMS should list 2 models, has $n"
  grep -qE '^[0-9a-f]{64}  ' services/face/models/SHA256SUMS || bad "SHA256SUMS is not in '<sha256>  <file>' format"
else
  bad "services/face/models/SHA256SUMS is missing: the face Docker build will FAIL without it"
  note "fix (once, ~38 MB download):  cd services/face && python3 scripts/fetch_models.py --init && cd ../.."
  note "then commit services/face/models/SHA256SUMS (the .onnx files stay git-ignored)"
fi

# ---------------------------------------------------------------- 9. secrets
sect "9. deploy/.env secrets"
ENVF=deploy/.env
if [ ! -f $ENVF ]; then
  bad "deploy/.env not found. Create it:  sh deploy/gen-env.sh"
else
  for k in POSTGRES_PASSWORD FACE_KEYS FACE_ACTIVE_KEY FACE_SERVICE_TOKEN AUTH_JWT_SEED AUTH_JWT_KID PUBLIC_BASE_URL RISK_SERVICE_TOKEN OTP_PEPPER; do
    v=$(grep -E "^$k=" $ENVF | head -1 | cut -d= -f2-)
    [ -n "$v" ] && ok "$k is set" || bad "$k is empty or missing in deploy/.env (delete deploy/.env and re-run  sh deploy/gen-env.sh  if it is an old file)"
  done
  grep -qiE '^[A-Z_]+=(changeme|password|secret|test|xxx)$' $ENVF && bad "deploy/.env contains a placeholder secret"
  perm=$(stat -c '%a' $ENVF 2>/dev/null || stat -f '%Lp' $ENVF 2>/dev/null)
  case "$perm" in 600|400|"") ok "deploy/.env permissions are private ($perm)" ;; *) warn "deploy/.env is readable by others ($perm):  chmod 600 deploy/.env" ;; esac
  if [ "$(grep -E '^APP_ENV=' $ENVF | cut -d= -f2-)" = "production" ] && [ "$(grep -E '^MAIL_MODE=' $ENVF | cut -d= -f2-)" != "smtp" ]; then warn "APP_ENV=production but MAIL_MODE is not smtp (OTP emails would only be logged)"; fi
fi
if git rev-parse --git-dir >/dev/null 2>&1; then
  if git ls-files --error-unmatch $ENVF >/dev/null 2>&1; then bad "deploy/.env is TRACKED by git: secrets are in your repo! run: git rm --cached deploy/.env  then rotate all secrets"
  elif git check-ignore -q $ENVF 2>/dev/null; then ok "deploy/.env is git-ignored"
  else bad "deploy/.env is not git-ignored: add 'deploy/.env' to .gitignore before you ever commit"; fi
else note "(not a git checkout: git-ignore check skipped)"; fi

# ---------------------------------------------------------------- 10. compose
if [ $DO_DOCKER = 1 ] && have docker && docker compose version >/dev/null 2>&1; then
  sect "10. docker-compose file"
  out=$(docker compose -f deploy/docker-compose.yml config -q 2>&1) && ok "docker-compose.yml is valid and all \${VARS} resolve" || { bad "docker compose config failed:"; echo "$out" | indent 30; }
  for s in postgres redis migrate-auth migrate-face face risk auth gateway; do
    grep -qE "^  $s:" deploy/docker-compose.yml && ok "service '$s' defined" || bad "service '$s' missing from docker-compose.yml"
  done
  if have "$PY" && docker compose -f deploy/docker-compose.yml config -q >/dev/null 2>&1; then
    out=$(docker compose -f deploy/docker-compose.yml config --format json 2>/dev/null | "$PY" -c '
import json,sys,os
try: c=json.load(sys.stdin)
except Exception: sys.exit(0)
bad=0
for n,s in c.get("services",{}).items():
    b=s.get("build")
    if not b: continue
    ctx=b if isinstance(b,str) else b.get("context","")
    df=os.path.join(ctx, (b.get("dockerfile","Dockerfile") if isinstance(b,dict) else "Dockerfile"))
    if not os.path.isfile(df): print(f"{n}: Dockerfile not found at {df}"); bad=1
sys.exit(bad)' 2>&1) && ok "every build: context has its Dockerfile" || { bad "compose build problem:"; echo "$out" | indent; }
    ports=$(docker compose -f deploy/docker-compose.yml config --format json 2>/dev/null | "$PY" -c '
import json,sys
try: c=json.load(sys.stdin)
except Exception: sys.exit(0)
for n,s in c.get("services",{}).items():
    for p in s.get("ports",[]) or []:
        print(n, p.get("host_ip",""), p.get("published",""))' 2>/dev/null)
    echo "$ports" | awk '$1=="auth" || $1=="face" || $1=="risk" {print}' | grep -q . && bad "auth/face/risk must NOT publish ports (only the gateway is public):" && echo "$ports" | awk '$1=="auth"||$1=="face"||$1=="risk"' | indent
    echo "$ports" | awk '$1=="postgres" && $2!="127.0.0.1" && $2!="" {print}' | grep -q . && bad "postgres is published on a public interface"
    echo "$ports" | grep -q '^gateway' && ok "gateway publishes its port; auth/face/risk are internal-only" || warn "gateway has no published port"
  fi
fi

# ---------------------------------------------------------------- 11. machine
sect "11. Machine: disk, port, internet"
free_kb=$(df -Pk . | awk 'NR==2{print $4}')
free_gb=$((free_kb/1024/1024))
if [ "$free_kb" -lt 3145728 ]; then bad "only ~${free_gb} GB free disk; first build needs about 3-5 GB"
elif [ "$free_kb" -lt 6291456 ]; then warn "~${free_gb} GB free disk (ok, but tight; build needs about 3-5 GB)"
else ok "~${free_gb} GB free disk"; fi
if have ss && ss -ltn 2>/dev/null | grep -q ':8080 '; then warn "something already listens on port 8080 (is the stack already running? otherwise stop it)"; else ok "port 8080 is free"; fi
if [ $DO_NET = 1 ] && have curl; then
  for u in "https://registry-1.docker.io/v2/|Docker Hub (images)" "https://proxy.golang.org/|Go modules" "https://pypi.org/simple/|Python packages" "https://github.com/opencv/opencv_zoo|face models (GitHub)"; do
    url=${u%%|*}; name=${u##*|}
    code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$url" 2>/dev/null)
    case "$code" in 000|"") warn "cannot reach $name ($url)" ;; *) ok "can reach $name (HTTP $code)" ;; esac
  done
fi

echo
echo "${B}Result:${N} ${G}$PASSES passed${N}, ${Y}$WARNS warnings${N}, ${R}$FAILS failures${N}"
if [ $FAILS -gt 0 ]; then echo "${R}Fix the FAIL lines above, then run this script again.${N}"; exit 1; fi
echo "${G}Preflight clean: safe to run the stack.${N}  Next:  cd deploy && docker compose up -d --build"
exit 0
