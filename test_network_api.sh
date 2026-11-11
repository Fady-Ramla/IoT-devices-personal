#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only runtime API smoke test. Telemetry POST is deliberately not sent
# through a public tunnel; use `iot_test` in Mininet for the end-to-end write.
# Usage: API_TOKEN=... BASE_URL=https://... ./test_network_api.sh
BASE_URL="${1:-${BASE_URL:-}}"
API_TOKEN="${API_TOKEN:-}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${EXPECTED_LINKS:-}" ]]; then
  EXPECTED_LINKS="$(python3 - "$SCRIPT_DIR/mininet/vlan_config_38host.py" <<'PY'
import runpy, sys
config = runpy.run_path(sys.argv[1])
print(len(config["INTER_SWITCH_LINKS"]))
PY
)"
fi
export EXPECTED_LINKS
CORS_ORIGIN="${CORS_ORIGIN:-${SECUREIOT_ALLOWED_ORIGIN:-}}"
if [[ -z "$BASE_URL" || ${#API_TOKEN} -lt 32 ]]; then
  echo "Usage: API_TOKEN=<32+ chars> BASE_URL=https://... [EXPECTED_LINKS=<branch topology count>] $0" >&2
  exit 2
fi
BASE_URL="${BASE_URL%/}"
CURL=(curl --silent --show-error --connect-timeout 5 --max-time 15)
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
PASS=0
FAIL=0
pass() { printf 'PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL  %s\n' "$1" >&2; FAIL=$((FAIL + 1)); }
request_json() {
  local name="$1" path="$2" body="$TMP_DIR/${name}.json" code
  code=$("${CURL[@]}" -H "Authorization: Bearer $API_TOKEN" -o "$body" -w '%{http_code}' "$BASE_URL$path") || code=000
  if [[ "$code" != 200 ]] || ! python3 -m json.tool "$body" >/dev/null 2>&1; then
    fail "$name: HTTP $code or invalid JSON"
    return 1
  fi
  pass "$name: HTTP 200 and valid JSON"
}
assert_json() {
  local name="$1" file="$2" expression="$3"
  if [[ ! -s "$file" ]]; then fail "$name (no response file)"; return 1; fi
  if python3 - "$file" "$expression" <<'PY'
import json, os, sys
with open(sys.argv[1], encoding='utf-8') as f:
    data=json.load(f)
if not eval(sys.argv[2], {"__builtins__": {"len":len, "isinstance":isinstance, "all":all, "any":any, "sorted":sorted}}, {"data": data, "EXPECTED_LINKS": int(os.environ.get("EXPECTED_LINKS", "12"))}):
    raise SystemExit(1)
PY
  then pass "$name"; else fail "$name"; fi
}

echo "SecureIoT Network Dashboard API test"
echo "Base URL: $BASE_URL"
echo "Expected inter-switch links: $EXPECTED_LINKS"

# Liveness is intentionally public; all operational/data endpoints require a token.
request_json health /health || true
assert_json "health status is healthy" "$TMP_DIR/health.json" 'data.get("status") == "healthy"'
NOAUTH_CODE=$("${CURL[@]}" -o "$TMP_DIR/noauth.json" -w '%{http_code}' "$BASE_URL/controller/state" || true)
[[ "$NOAUTH_CODE" == 401 ]] && pass "controller endpoint rejects unauthenticated request" || fail "unauthenticated controller request returned HTTP $NOAUTH_CODE"

request_json controller_state /controller/state || true
assert_json "controller status is connected" "$TMP_DIR/controller_state.json" 'data.get("status") == "connected"'
assert_json "controller state is active" "$TMP_DIR/controller_state.json" 'data.get("state") == "active"'
assert_json "six switches are connected" "$TMP_DIR/controller_state.json" 'data.get("connected_switches") == 6'
assert_json "expected link count matches branch config" "$TMP_DIR/controller_state.json" 'data.get("expected_inter_switch_links") == EXPECTED_LINKS'
assert_json "active link count matches expected topology" "$TMP_DIR/controller_state.json" 'data.get("active_inter_switch_links") == data.get("expected_inter_switch_links")'
assert_json "CLFF is ready" "$TMP_DIR/controller_state.json" 'data.get("clff_ready") is True'
assert_json "resilience is ready" "$TMP_DIR/controller_state.json" 'data.get("resilience_status") == "ready"'

request_json controller_clff /controller/clff || true
assert_json "CLFF endpoint is ready" "$TMP_DIR/controller_clff.json" 'data.get("ready") is True'
assert_json "CLFF has six trees" "$TMP_DIR/controller_clff.json" 'data.get("tree_count") == 6'
assert_json "CLFF edge count matches branch config" "$TMP_DIR/controller_clff.json" 'data.get("physical_graph_edges") == EXPECTED_LINKS'
request_json controller_resilience /controller/resilience || true
assert_json "resilience endpoint is ready" "$TMP_DIR/controller_resilience.json" 'data.get("status") == "ready"'

request_json topology_switches /topology/switches || true
assert_json "six switch records are returned" "$TMP_DIR/topology_switches.json" 'isinstance(data, list) and len(data) == 6'
request_json topology_links /topology/links || true
assert_json "link records match branch topology" "$TMP_DIR/topology_links.json" 'isinstance(data, list) and len(data) == EXPECTED_LINKS'
request_json topology_hosts /topology/hosts || true
assert_json "all 38 configured hosts are returned" "$TMP_DIR/topology_hosts.json" 'isinstance(data, list) and len(data) == 38'
request_json vlans /network/vlans || true
assert_json "five VLAN records are returned" "$TMP_DIR/vlans.json" 'isinstance(data, list) and sorted(x.get("vlan_id") for x in data) == [10,20,30,40,50]'
request_json lb_config /network/load-balancer || true
assert_json "load-balancer configuration is reported without a false health claim" "$TMP_DIR/lb_config.json" 'data.get("status") == "configured" and data.get("backend_count") == 2'
request_json lb_backends /network/load-balancer/backends || true
assert_json "two configured backends are returned" "$TMP_DIR/lb_backends.json" 'isinstance(data, list) and len(data) == 2 and all(x.get("status") == "configured" and x.get("health_checked") is False for x in data)'
request_json iot_devices /api/iot/devices || true
assert_json "device inventory is an array" "$TMP_DIR/iot_devices.json" 'isinstance(data, list)'
request_json iot_sensors /api/iot/sensors || true
assert_json "sensor inventory is an array" "$TMP_DIR/iot_sensors.json" 'isinstance(data, list)'
request_json iot_telemetry /api/iot/telemetry?limit=5 || true
assert_json "telemetry history is an array" "$TMP_DIR/iot_telemetry.json" 'isinstance(data, list)'

if [[ -n "$CORS_ORIGIN" ]]; then
  CORS_HEADERS="$TMP_DIR/cors_headers.txt"
  CORS_CODE=$("${CURL[@]}" -D "$CORS_HEADERS" -o /dev/null -w '%{http_code}' \
    -H "Origin: $CORS_ORIGIN" -H "Authorization: Bearer $API_TOKEN" "$BASE_URL/controller/state" || true)
  if [[ "$CORS_CODE" == 200 ]] && grep -Fqi "access-control-allow-origin: $CORS_ORIGIN" "$CORS_HEADERS"; then
    pass "configured dashboard origin is allowed by CORS"
  else
    fail "configured dashboard origin is not allowed by CORS (HTTP $CORS_CODE)"
  fi
  PREFLIGHT_HEADERS="$TMP_DIR/preflight_headers.txt"
  PREFLIGHT_CODE=$("${CURL[@]}" -D "$PREFLIGHT_HEADERS" -o /dev/null -w '%{http_code}' \
    -X OPTIONS -H "Origin: $CORS_ORIGIN" \
    -H 'Access-Control-Request-Method: GET' \
    -H 'Access-Control-Request-Headers: authorization' \
    "$BASE_URL/controller/state" || true)
  if [[ "$PREFLIGHT_CODE" == 204 || "$PREFLIGHT_CODE" == 200 ]] && \
     grep -Fqi "access-control-allow-origin: $CORS_ORIGIN" "$PREFLIGHT_HEADERS" && \
     grep -qi '^access-control-allow-headers:.*authorization' "$PREFLIGHT_HEADERS"; then
    pass "CORS preflight permits the configured origin and Authorization header"
  else
    fail "CORS preflight failed (HTTP $PREFLIGHT_CODE)"
  fi
  OTHER_ORIGIN="https://not-authorized.invalid"
  OTHER_HEADERS="$TMP_DIR/other_cors_headers.txt"
  "${CURL[@]}" -D "$OTHER_HEADERS" -o /dev/null -H "Origin: $OTHER_ORIGIN" \
    -H "Authorization: Bearer $API_TOKEN" "$BASE_URL/controller/state" || true
  if grep -Fqi "access-control-allow-origin: $OTHER_ORIGIN" "$OTHER_HEADERS"; then
    fail "untrusted origin was granted CORS"
  else
    pass "untrusted origin is not granted CORS"
  fi
fi

echo
printf 'Passed: %s\nFailed: %s\n' "$PASS" "$FAIL"
if (( FAIL > 0 )); then echo "RESULT: FAIL"; exit 1; fi
echo "RESULT: PASS"
