#!/usr/bin/env bash
set -uo pipefail

BASE_URL="${1:-}"
if [[ -z "$BASE_URL" ]]; then
  echo "Usage: $0 https://<current-ngrok-host>" >&2
  exit 2
fi
BASE_URL="${BASE_URL%/}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
PASS=0
FAIL=0

check_get() {
  local path="$1"
  local expectation="${2:-200}"
  local code
  code="$(curl -sS --max-time 12 -H 'Accept: application/json' \
    -o "$TMP_DIR/body" -w '%{http_code}' "$BASE_URL$path" 2>/dev/null || true)"
  if [[ "$expectation" == "stats" ]]; then
    if [[ "$code" == "200" || "$code" == "202" ]]; then
      printf 'PASS GET %-58s HTTP %s\n' "$path" "$code"
      PASS=$((PASS + 1))
    else
      printf 'FAIL GET %-58s HTTP %s (expected 200 or 202)\n' "$path" "${code:-000}"
      FAIL=$((FAIL + 1))
    fi
  elif [[ "$code" == "$expectation" ]]; then
    printf 'PASS GET %-58s HTTP %s\n' "$path" "$code"
    PASS=$((PASS + 1))
  else
    printf 'FAIL GET %-58s HTTP %s (expected %s)\n' "$path" "${code:-000}" "$expectation"
    FAIL=$((FAIL + 1))
  fi
}

check_method() {
  local method="$1" path="$2" expected="$3" code
  code="$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
    -X "$method" "$BASE_URL$path" 2>/dev/null || true)"
  if [[ "$code" == "$expected" ]]; then
    printf 'PASS %s %-61s HTTP %s\n' "$method" "$path" "$code"
    PASS=$((PASS + 1))
  else
    printf 'FAIL %s %-61s HTTP %s (expected %s)\n' "$method" "$path" "${code:-000}" "$expected"
    FAIL=$((FAIL + 1))
  fi
}

# Contract v2.0-final read endpoints; no client bearer token is sent.
check_get '/runtime/health'
check_get '/topology/switches'
check_get '/topology/hosts'
check_get '/topology/links'
check_get '/topology/paths'
check_get '/topology/hosts/h6/path?source=h1'
check_get '/network/vlans'
check_get '/network/vlan-ports'
for dpid in 1 2 3 4 5 6; do
  check_get "/stats/desc/$dpid" stats
  check_get "/stats/port/$dpid" stats
  check_get "/stats/flow/$dpid" stats
done
check_get '/network/load-balancer'
check_get '/network/load-balancer/status'
check_get '/network/load-balancer/backends'
check_get '/network/load-balancer/stats'
check_get '/api/iot/devices'
check_get '/api/iot/sensors'
check_get '/api/iot/telemetry?device_id=h16&limit=5'
check_get '/firewall/status'
check_get '/firewall/rules'
check_get '/firewall/events?limit=100'
check_get '/network/events?limit=100'
check_get '/controller/clff'
check_get '/controller/resilience'

# Contract's POST exists only on the local runtime; the ngrok gateway is read-only.
check_method POST '/api/iot/telemetry' 405
check_method GET '/network/action' 404
check_method GET '/dashboard/snapshot' 404
check_method OPTIONS '/runtime/health' 204

printf '\nContract GET checks: %d passed, %d failed.\n' "$PASS" "$FAIL"
if (( FAIL > 0 )); then
  exit 1
fi
