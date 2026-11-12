# SecureIoT Full Demo Scenario — اختبار كل الـ Endpoints

هذا السيناريو يعمل كـ demo كامل من بداية تشغيل النظام إلى link failure ثم recovery. نفّذيه بالترتيب حتى تكون عندك before/after evidence واضحة.

## 0. المتطلبات

شغّلي Ryu وngrok وMininet حسب:

```text
docs/SECUREIOT_QUICK_START_AR.md
```

واستخدمي آخر branch:

```bash
cd ~/Graduation_Project/IoT-devices
git switch api-runtime-latest-20261111
git pull --ff-only origin api-runtime-latest-20261111
```

من terminal عادي:

```bash
export API=http://127.0.0.1:8080
export TOKEN='secureiot-local-demo-token-2026-abcdef'
```

في هذا الـ lab تم تعطيل API auth للـ GET endpoints، لكن firewall/link actions ما زالت تحتاج:

```text
X-SecureIoT-Token: secureiot-local-demo-token-2026-abcdef
```

## 1. Baseline snapshot

احفظي snapshot قبل أي تغيير:

```bash
mkdir -p /tmp/secureiot-demo

curl -s "$API/health" > /tmp/secureiot-demo/health.before.json
curl -s "$API/controller/state" > /tmp/secureiot-demo/controller.before.json
curl -s "$API/topology/links" > /tmp/secureiot-demo/links.before.json
curl -s "$API/runtime/topology" > /tmp/secureiot-demo/topology.before.json
curl -s "$API/controller/clff" > /tmp/secureiot-demo/clff.before.json
curl -s "$API/controller/resilience" > /tmp/secureiot-demo/resilience.before.json
curl -s "$API/network/load-balancer" > /tmp/secureiot-demo/lb.before.json
curl -s "$API/network/load-balancer/status" > /tmp/secureiot-demo/lb-status.before.json
curl -s "$API/network/load-balancer/backends" > /tmp/secureiot-demo/lb-backends.before.json
curl -s "$API/firewall/status" > /tmp/secureiot-demo/firewall.before.json
curl -s "$API/firewall/rules" > /tmp/secureiot-demo/firewall-rules.before.json
curl -s "$API/network/events" > /tmp/secureiot-demo/events.before.json
```

المتوقع في baseline:

```text
controller connected
links = 12
isolated_links = []
CLFF ready = true
resilience event/recovery counters موجودة
load balancer backends configured/healthy
firewall default-deny موجود
```

## 2. IoT polling and changing telemetry

من داخل Mininet CLI:

```text
h2 curl --noproxy '*' -sS http://10.10.10.16:8081/health
h2 curl --noproxy '*' -sS http://10.10.10.16:8081/sensor/readings
h2 head -n 20 /tmp/web_api_h2_iot_live.log
```

ومن terminal عادي:

```bash
curl -s "$API/api/iot/devices"
curl -s "$API/api/iot/sensors"
curl -s "$API/api/iot/telemetry?device_id=h16&limit=1"
sleep 6
curl -s "$API/api/iot/telemetry?device_id=h16&limit=1"
```

قارني الردين. يجب أن يتغير:

```text
sequence
timestamp
sensor value
last_seen
```

وفي ngrok inspector يجب أن تري تقريبًا:

```text
POST /api/iot/telemetry 201
```

## 3. Flow stats: pending ثم ready

```bash
curl -i "$API/stats/flow/1"
sleep 3
curl -i "$API/stats/flow/1"
```

النتيجة المطلوبة:

```text
HTTP 202 + {"status":"pending"}
ثم
HTTP 200 + {"status":"ready","flows":[...]}
```

ومن داخل Mininet ولتوليد traffic:

```text
h16 ping -c 5 10.10.10.1
```

ثم:

```bash
curl -s "$API/stats/flow/1"
curl -s "$API/stats/port/1"
curl -s "$API/topology/switches"
```

قارني `packet_count` و`byte_count` و`timestamp`. يجب أن تكون counters حية وليست snapshot ثابتة.

## 4. Load balancer

الـ HTTP load balancer هو:

```text
VIP: 10.10.20.100:5000
primary: h2 -> 10.10.20.2:5000
backup:  h18 -> 10.10.20.8:5000
```

افحصي state الحالي:

```bash
curl -s "$API/network/load-balancer"
curl -s "$API/network/load-balancer/status"
curl -s "$API/network/load-balancer/backends"
curl -s "$API/network/load-balancer/stats"
```

ولتشغيل requests من داخل Mininet:

```text
h21 sh -c 'for i in $(seq 1 10); do curl -4 -sS --max-time 2 http://10.10.20.100:5000/health; echo; sleep 1; done'
```

بعدها افحصي:

```bash
curl -s "$API/network/load-balancer"
curl -s "$API/network/load-balancer/backends"
curl -s "$API/network/load-balancer/stats"
```

المتوقع أن تتغير:

```text
requests_total
last_backend
backend_requests
updated_at
healthy_backends
```

## 5. Firewall block/unblock

داخل Mininet خذي MAC جهاز h16:

```text
h16 cat /sys/class/net/h16-eth0/address
```

مثال:

```text
00:00:00:00:00:11
```

اعملي block:

```bash
curl -i -X POST "$API/network/action" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "action": "BLOCK_DEVICE",
    "mac": "00:00:00:00:00:11",
    "host_ip": "10.10.10.16",
    "request_id": "FULL-DEMO-BLOCK-001",
    "reason": "full endpoint integration demo"
  }'
```

ثم:

```bash
curl -s "$API/firewall/status"
curl -s "$API/firewall/rules"
curl -s "$API/firewall/events"
```

المتوقع:

```text
blocked_flows = 1
blocked_device_count = 1
rule priority = 50000
action = DROP
source = 00:00:00:00:00:11
event_type = firewall_action
```

بعد انتهاء الاختبار اعملي unblock:

```bash
curl -i -X POST "$API/network/action" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "action": "UNBLOCK_DEVICE",
    "mac": "00:00:00:00:00:11",
    "host_ip": "10.10.10.16",
    "request_id": "FULL-DEMO-UNBLOCK-001",
    "reason": "full endpoint integration recovery"
  }'
```

## 6. Prepare an active flow for resilience

قبل عزل link، اعرفي path فعلي بين client وservice:

```bash
curl -s "$API/topology/paths?source=h21&destination=h2"
```

اختاري link موجود في `nodes` أو `links` للمسار. لو أردتِ استخدام المثال المعروف:

```text
failed link: s1-s2 => [1,2]
```

شغّلي traffic مستمرًا من داخل Mininet:

```text
h21 sh -c 'while true; do curl -4 -sS --max-time 2 http://10.10.20.2:5000/health >/dev/null; sleep 1; done' &
```

ثم راقبي flow وswitch activity:

```bash
curl -s "$API/stats/flow/1"
curl -s "$API/topology/switches"
```

لو أردتِ الاحتفاظ بالـ process والـ PID داخل h21:

```text
h21 sh -c 'while true; do curl -4 -sS --max-time 2 http://10.10.20.2:5000/health >/dev/null; sleep 1; done >/tmp/h21-demo-traffic.log 2>&1 & echo $!'
```

## 7. Link failure

اعزلي الرابط `s1-s2`:

```bash
curl -i -X POST "$API/network/link/isolate" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "src_dpid": 1,
    "dst_dpid": 2,
    "reason": "full endpoint link failure demo"
  }'
```

بعدها مباشرة افحصي كل endpoints:

```bash
curl -s "$API/topology/links"
curl -s "$API/runtime/topology"
curl -s "$API/network/events"
curl -s "$API/controller/clff"
curl -s "$API/controller/resilience"
curl -s "$API/stats/flow/1"
curl -s "$API/topology/switches"
```

التغييرات المطلوبة:

```text
/topology/links:
  link 1-2 => isolated=true, status=isolated

/runtime/topology:
  isolated_links contains [1,2]
  operational_links excludes [1,2]
  topology_change_count increases

/network/events:
  link_isolation event
  resilience removed event

/controller/clff:
  operational_graph_edges decreases
  last_rebuild_reason=isolated_link_change
  last_rebuild_at changes

/controller/resilience:
  event_count increases
  recovery_count increases after recovery handler
  last_recovery.failed_links contains [1,2]

flow/path:
  active flow either reroutes or remains pending until the new path is installed
```

إذا ظهر:

```text
rerouted: 0
```

فهذا يعني أن الـ active flow لم يكن يمر عبر الرابط `1-2`. اختاري link آخر من path الفعلي ثم كرري الاختبار.

## 8. Load balancer أثناء failure

افحصي هل الطلبات ما زالت تصل إلى VIP:

```text
h21 sh -c 'for i in $(seq 1 10); do date -Is; curl -4 -sS --max-time 3 http://10.10.20.100:5000/health; echo; sleep 1; done'
```

ثم:

```bash
curl -s "$API/network/load-balancer/status"
curl -s "$API/network/load-balancer/backends"
curl -s "$API/network/load-balancer/stats"
```

لو صار backend unhealthy، يجب أن يظهر ذلك في `healthy_backends` و`backend_requests`، ويستمر الـ VIP في استخدام backend الصحي إذا كان المسار الشبكي متاحًا.

## 9. Restore and final verification

أعيدي الرابط:

```bash
curl -i -X POST "$API/network/link/restore" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "src_dpid": 1,
    "dst_dpid": 2,
    "reason": "full endpoint recovery demo"
  }'
```

انتظري 3–10 ثوانٍ لإعادة اكتشاف LLDP، ثم افحصي:

```bash
curl -s "$API/runtime/topology"
curl -s "$API/topology/links"
curl -s "$API/network/events"
curl -s "$API/controller/clff"
curl -s "$API/controller/resilience"
curl -s "$API/network/load-balancer/stats"
curl -s "$API/firewall/status"
curl -s "$API/firewall/rules"
```

النتيجة النهائية:

```text
link_count = 12
isolated_links = []
operational_graph_edges = 12
link 1-2 status = active
CLFF ready = true
resilience history محفوظة
load-balancer counters محفوظة ومتزايدة
firewall rules لا تحتوي device-block بعد unblock
IoT telemetry ما زالت تتغير
```

## 10. Evidence commands للـ demo report

احفظي النتائج النهائية:

```bash
for endpoint in \
  /controller/state \
  /topology/links \
  /runtime/topology \
  /controller/clff \
  /controller/resilience \
  /network/events \
  /network/load-balancer \
  /network/load-balancer/status \
  /network/load-balancer/backends \
  /network/load-balancer/stats \
  /firewall/status \
  /firewall/rules \
  /firewall/events; do
  name=$(printf '%s' "$endpoint" | tr '/' '_')
  curl -s "$API$endpoint" > "/tmp/secureiot-demo/final${name}.json"
done
```

هذه الملفات توضح before/after ويمكن استخدامها في تقرير التخرج أو أثناء العرض.

## 11. Cleanup

أوقفي traffic loop من Mininet:

```text
h21 pkill -f 'curl.*10.10.20.2:5000/health' || true
```

ثم:

```text
mininet> exit
```

ومن terminal النظام:

```bash
sudo mn -c
```

ثم أوقفي Ryu وngrok باستخدام `Ctrl+C`.
