#!/usr/bin/env bash
# Run this suite's Playwright tests as parallel lanes: build once, start one
# server per lane on its own port, run each lane's list on its own server, and
# merge the results. Per-suite settings live in lanes.conf next to this file.
#
#   ./run-lanes.sh                       full run, LANES lanes (default from lanes.conf)
#   ./run-lanes.sh -g "<title regex>"    targeted: one server, one lane
#   ./run-lanes.sh --project phone a.spec.ts b.spec.ts
#   ./run-lanes.sh --serial              one server, every test in order (baseline)
#
# Options: --no-build, --no-install, --out DIR. Env: LANES, LANE_BUDGET
# (seconds per lane, default 1200), LANES_OUT, CARGO_TARGET_DIR.
#
# Output in $LANES_OUT (default lanes-out/<stamp>): lane-<i>/{timing.tsv,
# results.json, playwright.log, server.log}, stages.tsv, summary.{md,json}.
# timing.tsv is one line: lane, t0 (server start), t1 (ready), t2 (done), rc.
# The exit code comes from Playwright's results only: non-zero on any failed,
# missing or duplicated test, or a server that never became ready.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$here/lanes.conf"
if [ -n "${REPO_ROOT:-}" ]; then root=$(cd "$here/$REPO_ROOT" && pwd); else root=$(git -C "$here" rev-parse --show-toplevel); fi
[ -d "$root" ] || { echo "run-lanes: can't find the repo root" >&2; exit 2; }

build=1 install=1 serial=0 filter=() pw_project=() files=()
out=${LANES_OUT:-}
while [ $# -gt 0 ]; do
  case $1 in
    -g|--grep) filter+=(--grep "$2"); shift 2 ;;
    --project) pw_project+=(--project "$2"); shift 2 ;;
    --serial) serial=1; shift ;;
    --no-build) build=0; shift ;;
    --no-install) install=0; shift ;;
    --out) out=$2; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) files+=("$1"); shift ;;
  esac
done
targeted=0
[ ${#filter[@]} -gt 0 ] || [ ${#pw_project[@]} -gt 0 ] || [ ${#files[@]} -gt 0 ] && targeted=1
lanes=${LANES:-${LANES_DEFAULT:-8}}
[ "$serial" = 1 ] || [ "$targeted" = 1 ] && lanes=1
budget=${LANE_BUDGET:-1200}
out=$(realpath -m "${out:-$here/lanes-out/$(date +%Y%m%d-%H%M%S)}")
mkdir -p "$out"
stages=$out/stages.tsv
: >"$stages"
now() { date +%s.%N; }
stage() { awk -v n="$(now)" -v t="$2" -v s="$1" 'BEGIN { printf "%s\t%.1f\n", s, n - t }' >>"$stages"; }
log() { echo "run-lanes: $*" >&2; }

target=${CARGO_TARGET_DIR:-target}
case $target in /*) ;; *) target=$root/$target ;; esac
bin=$target/${PROFILE:-debug}/$SERVER_BIN
leptos_env=DEV
[ "${PROFILE:-debug}" = release ] && leptos_env=PROD
port_of() { echo $((PORT + 100 + $1)); }
port_busy() { ss -ltnH "sport = :$1" 2>/dev/null | grep -q .; }

for i in $(seq 1 "$lanes"); do
  if port_busy "$(port_of "$i")"; then
    log "port $(port_of "$i") is already in use; another run may be live"; exit 2
  fi
done

pids=()
cleanup() {
  local f
  for f in "$out"/lane-*/server.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
  if declare -F lane_teardown >/dev/null; then
    for i in $(seq 1 "$lanes"); do lane_teardown "$i" "$(port_of "$i")" "$out/lane-$i"; done
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

t_all=$(now)
if [ "$build" = 1 ]; then
  t=$(now)
  log "build: $BUILD_CMD"
  ( cd "$root" && nice -n 10 bash -c "$BUILD_CMD" ) >"$out/build.log" 2>&1
  rc=$?
  stage build "$t"
  [ $rc = 0 ] || { log "build failed (rc $rc); see $out/build.log"; tail -20 "$out/build.log" >&2; exit 1; }
fi
[ -x "$bin" ] || { log "no server binary at $bin"; exit 1; }
site=$root/$SITE_ROOT
[ -d "$site/pkg" ] || { log "no $site/pkg; the frontend build is missing"; exit 1; }

cd "$here" || exit 1
if [ "$install" = 1 ]; then
  t=$(now)
  if [ ! -f node_modules/.package-lock.json ] || [ package-lock.json -nt node_modules/.package-lock.json ]; then
    npm ci --no-audit --no-fund >"$out/npm.log" 2>&1 || { log "npm ci failed; see $out/npm.log"; exit 1; }
  fi
  stage npm "$t"
  t=$(now)
  npx playwright install chromium >"$out/pw-install.log" 2>&1 || { log "playwright install failed"; exit 1; }
  stage pw-install "$t"
fi

# Every test this run should cover, from Playwright itself.
npx playwright test --list --reporter=json "${filter[@]}" "${pw_project[@]}" "${files[@]}" \
  >"$out/all.json" 2>"$out/list.log" || { log "playwright --list failed"; cat "$out/list.log" >&2; exit 1; }

if [ "$serial" = 0 ] && [ "$targeted" = 0 ] && [ -f "lanes/list-$lanes.txt" ] && [ ! -f "lanes/list-$((lanes + 1)).txt" ]; then
  python3 -I "$here/lanes.py" lists --all "$out/all.json" --lists lanes --n "$lanes" --out "$out" >&2
elif [ "$serial" = 0 ] && [ "$targeted" = 0 ]; then
  log "no committed lists for $lanes lanes; splitting with --shard"
fi

run_lane() {
  local i=$1 port o rc=99 srv t0 t1 t2 args=()
  port=$(port_of "$i")
  o=$out/lane-$i
  mkdir -p "$o/srv"
  if declare -F lane_setup >/dev/null; then lane_setup "$i" "$port" "$o"; fi
  local lane_env=${LANE_ENV:-}
  lane_env=${lane_env//\{port\}/$port}
  t0=$(now)
  # SERVER_CWD=root runs the server from the repo root, for hosts that read
  # Cargo.toml at startup and keep no files of their own.
  local cwd=$o/srv
  [ "${SERVER_CWD:-}" = root ] && cwd=$root
  ( cd "$cwd" && exec env ${SERVER_ENV:-} $lane_env \
      LEPTOS_OUTPUT_NAME="$OUTPUT_NAME" LEPTOS_SITE_ROOT="$site" LEPTOS_SITE_PKG_DIR=pkg \
      LEPTOS_SITE_ADDR="127.0.0.1:$port" LEPTOS_ENV=$leptos_env \
      "$bin" >"$o/server.log" 2>&1 </dev/null ) &
  srv=$!
  echo "$srv" >"$o/server.pid"
  for _ in $(seq 600); do
    curl -sf -o /dev/null "http://127.0.0.1:$port${READY_PATH:-/health}" && break
    kill -0 "$srv" 2>/dev/null || break
    sleep 0.5
  done
  t1=$(now)
  if curl -sf -o /dev/null "http://127.0.0.1:$port${READY_PATH:-/health}"; then
    if [ "$serial" = 0 ] && [ "$targeted" = 0 ]; then
      if [ -f "$o/list.txt" ]; then args=(--test-list="$o/list.txt"); else args=(--shard="$i/$lanes"); fi
    fi
    env "${BASE_URL_VAR:-PLAYWRIGHT_BASE_URL}=http://${BASE_HOST:-127.0.0.1}:$port" \
        PLAYWRIGHT_JSON_OUTPUT_FILE="$o/results.json" \
      timeout --kill-after=30 "$budget" \
      npx playwright test --workers=1 --retries=0 --reporter=list,json --output="$o/test-results" \
        "${args[@]}" "${filter[@]}" "${pw_project[@]}" "${files[@]}" >"$o/playwright.log" 2>&1
    rc=$?
    [ $rc = 124 ] && echo "run-lanes: lane $i passed its ${budget}s budget and was stopped" >>"$o/playwright.log"
  else
    rc=98
    echo "run-lanes: server on port $port never became ready; see server.log" >"$o/playwright.log"
  fi
  t2=$(now)
  kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null
  printf '%s\t%s\t%s\t%s\t%s\n' "$i" "$t0" "$t1" "$t2" "$rc" >"$o/timing.tsv"
  grep -q 'panicked at' "$o/server.log" && echo "run-lanes: lane $i server log has a panic" >&2
  return 0
}

t=$(now)
log "$lanes lane(s) on ports $(port_of 1)-$(port_of "$lanes"), output in $out"
for i in $(seq 1 "$lanes"); do
  run_lane "$i" &
  pids+=($!)
  sleep 0.3
done
for p in "${pids[@]}"; do wait "$p"; done
pids=()
stage lanes "$t"
stage total "$t_all"

python3 -I "$here/lanes.py" merge --all "$out/all.json" --run "$out" --stages "$stages"
rc=$?
for i in $(seq 1 "$lanes"); do
  if port_busy "$(port_of "$i")"; then log "port $(port_of "$i") still bound after the run"; rc=1; fi
done
exit $rc
