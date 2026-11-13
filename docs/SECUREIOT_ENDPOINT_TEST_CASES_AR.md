# SecureIoT — Test Cases منفصلة للـ Endpoints

هذه ليست Demo واحدة متصلة. كل Test Case مستقل ويمكن تشغيله وحده حسب الـ endpoint الذي تريدين اختباره.

## التحضير المشترك مرة واحدة فقط

شغّلي Ryu وMininet أولًا، ثم من terminal عادي:

```bash
export API=http://127.0.0.1:8080
export TOKEN='secureiot-local-demo-token-2026-abcdef'
```

عمليات `GET` تعمل في lab mode بدون API token لأننا نشغل:

```text
SECUREIOT_DISABLE_API_AUTH=1
```

أما عمليات `POST` الخاصة بالـ firewall وlink actions فتحتاج:

```text
X-SecureIoT-Token: secureiot-local-demo-token-2026-abcdef
```

---

## TC-01 — Health وController

### الهدف
التأكد أن Ryu والـ TopologyMonitor شغالان.

### التنفيذ

```bash
curl -i "$API/health"
curl -s "$API/controller/state"
```

### النجاح المتوقع

```text
HTTP 200
status = active/healthy
controller_connected = true
connected_switches = 6
```

---

## TC-02 — IoT telemetry dynamic

### الهدف
التأكد أن polling يجيب readings جديدة وليست قيمة ثابتة.

### التنفيذ

```bash
curl -s "$API/api/iot/telemetry?device_id=h16&limit=1"
sleep 6
curl -s "$API/api/iot/telemetry?device_id=h16&limit=1"
```

### النجاح المتوقع

قارني الردين. يجب أن يتغير:

```text
sequence
timestamp
vibration_mm_s أو sensor value
```

ولفحص الـ inventory:

```bash
curl -s "$API/api/iot/devices"
curl -s "$API/api/iot/sensors"
```

### فحص sensor الداخلي من Mininet

داخل Mininet فقط:

```text
h2 curl --noproxy '*' -sS http://10.10.10.16:8081/health
h2 curl --noproxy '*' -sS http://10.10.10.16:8081/sensor/readings
```

---

## TC-03 — Flow stats pending ثم ready

### الهدف
التأكد أن endpoint لا يخترع flow data، وينتظر OpenFlow reply.

### التنفيذ

```bash
curl -i "$API/stats/flow/1"
sleep 3
curl -i "$API/stats/flow/1"
```

### النجاح المتوقع

المحاولة الأولى قد تكون:

```text
HTTP 202
{"status":"pending","dpid":1,"flows":[]}
```

ثم بعد وصول OpenFlow reply:

```text
HTTP 200
{"status":"ready","dpid":1,"flows":[...]}
```

هذا Test Case مستقل ولا يحتاج link failure.

---

## TC-04 — Flow counters وSwitch traffic activity

### الهدف
التأكد أن counters و`traffic_active` تتغير مع traffic حقيقي.

### التنفيذ

داخل Mininet:

```text
h16 ping -c 5 10.10.10.1
```

ثم خارج Mininet:

```bash
curl -s "$API/stats/flow/1"
curl -s "$API/stats/port/1"
curl -s "$API/topology/switches"
```

### النجاح المتوقع

- `packet_count` أو `byte_count` يزيدان.
- `timestamp` جديد.
- switch يملك `traffic_active: true` لفترة قصيرة.
- بعد انتهاء نافذة النشاط، قد يرجع `traffic_active: false`.

---

## TC-05 — Load balancer health فقط

### الهدف
فحص load-balancer state بدون عمل failure.

### التنفيذ

```bash
curl -s "$API/network/load-balancer"
curl -s "$API/network/load-balancer/status"
curl -s "$API/network/load-balancer/backends"
curl -s "$API/network/load-balancer/stats"
```

### النجاح المتوقع

يظهر:

```text
host_id = h38
service_port = 5000
primary = h2:5000
backup = h18:5000
healthy_backends
health_checks_performed
updated_at
```

---

## TC-06 — Load balancer counters

### الهدف
التأكد أن load balancer يسجل requests ويتغير backend selection.

### التنفيذ

داخل Mininet:

```text
h21 sh -c 'for i in $(seq 1 10); do curl -4 -sS --max-time 2 http://10.10.20.100:5000/health; echo; sleep 1; done'
```

ثم خارج Mininet:

```bash
curl -s "$API/network/load-balancer/stats"
curl -s "$API/network/load-balancer"
curl -s "$API/network/load-balancer/backends"
```

### النجاح المتوقع

```text
requests_total يزيد
last_backend يتحدث
backend_requests تزيد
updated_at يتغير
```

---

## TC-07 — Firewall block فقط

### الهدف
التأكد أن `BLOCK_DEVICE` ينشئ DROP rule حقيقية.

### MAC جهاز h16

داخل Mininet:

```text
h16 cat /sys/class/net/h16-eth0/address
```

### التنفيذ

استبدلي الـ MAC إذا كان مختلفًا:

```bash
curl -i -X POST "$API/network/action" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "action": "BLOCK_DEVICE",
    "mac": "00:00:00:00:00:11",
    "host_ip": "10.10.10.16",
    "request_id": "TC-FW-BLOCK-001",
    "reason": "firewall endpoint test"
  }'
```

### التحقق

```bash
curl -s "$API/firewall/status"
curl -s "$API/firewall/rules"
curl -s "$API/firewall/events"
```

### النجاح المتوقع

```text
blocked_flows = 1
blocked_device_count = 1
priority = 50000
action = DROP
source = MAC of h16
```

---

## TC-08 — Firewall unblock فقط

### الهدف
التأكد أن القاعدة تختفي بينما يظل الحدث في history.

### التنفيذ

```bash
curl -i -X POST "$API/network/action" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "action": "UNBLOCK_DEVICE",
    "mac": "00:00:00:00:00:11",
    "host_ip": "10.10.10.16",
    "request_id": "TC-FW-UNBLOCK-001",
    "reason": "firewall recovery test"
  }'
```

### التحقق

```bash
curl -s "$API/firewall/status"
curl -s "$API/firewall/rules"
curl -s "$API/firewall/events"
```

### النجاح المتوقع

```text
blocked_flows = 0
blocked_device_count = 0
rules تحتوي default-deny فقط
الأحداث تحتوي BLOCK_DEVICE وUNBLOCK_DEVICE
```

---

## TC-09 — Link status بدون failure

### الهدف
فحص حالة links الحالية فقط.

```bash
curl -s "$API/topology/links"
curl -s "$API/runtime/topology"
```

### النجاح المتوقع

```text
status = active
isolated = false
isolated_links = []
link_count = 12
operational graph edges = 12
```

---

## TC-10 — Link isolation فقط

### الهدف
التأكد أن link واحد يتغير بدون اختبار firewall أو load balancer.

### التنفيذ

```bash
curl -i -X POST "$API/network/link/isolate" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "src_dpid": 1,
    "dst_dpid": 2,
    "reason": "isolated link endpoint test"
  }'
```

### التحقق

```bash
curl -s "$API/topology/links"
curl -s "$API/runtime/topology"
curl -s "$API/network/events"
```

### النجاح المتوقع

```text
link 1-2: isolated=true, status=isolated
isolated_links contains [1,2]
operational_links does not contain [1,2]
network/events contains link_isolation
```

---

## TC-11 — CLFF بعد link isolation

### الهدف
فحص CLFF فقط بعد تغيير topology.

```bash
curl -s "$API/controller/clff"
```

### النجاح المتوقع

```text
ready = true إذا بقي graph connected
operational_graph_edges أقل بواحد
last_rebuild_reason = isolated_link_change
last_rebuild_at تغير
last_error = null
```

لا تحتاجي active flow لهذا الاختبار.

---

## TC-12 — Resilience بعد link isolation

### الهدف
التأكد أن ResilienceEngine استقبل failure event.

```bash
for i in 1 2 3 4 5; do
  date -Is
  curl -s "$API/controller/resilience"
  sleep 3
done
```

### النجاح المتوقع

```text
event_count يزيد
last_event.removed يحتوي [1,2]
recovery_count يزيد بعد تنفيذ recovery
last_recovery.failed_links يحتوي [1,2]
```

إذا ظهر:

```text
rerouted = 0
```

فهذا يعني فقط أنه لا يوجد active flow كان يستخدم الرابط. هذا ليس فشلًا في resilience.

---

## TC-13 — Link restore فقط

### التنفيذ

```bash
curl -i -X POST "$API/network/link/restore" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "src_dpid": 1,
    "dst_dpid": 2,
    "reason": "restore endpoint test"
  }'
```

### التحقق

انتظري من 3 إلى 10 ثوانٍ بسبب LLDP، ثم:

```bash
curl -s "$API/topology/links"
curl -s "$API/runtime/topology"
curl -s "$API/controller/clff"
curl -s "$API/network/events"
```

### النجاح المتوقع

```text
link 1-2: isolated=false, status=active
isolated_links = []
link_count = 12
operational_graph_edges = 12
network/events contains link_restore
```

---

## TC-14 — Path endpoint فقط

### الهدف
فحص path الحالي بين host وhost بدون failure.

```bash
curl -s "$API/topology/paths?source=h21&destination=h2"
curl -s "$API/topology/hosts/h2/path?source=h21"
```

بعد link isolation كرري نفس الأمر وقارني `nodes` و`links`. يجب أن يتغير المسار إذا كان الـ failed link مستخدمًا في المسار الأصلي.

---

## TC-15 — Active-flow reroute فقط

### الهدف
إظهار `rerouted > 0` في resilience.

1. اعرفي path:

```bash
curl -s "$API/topology/paths?source=h21&destination=h2"
```

2. شغّلي traffic مستمرًا من داخل Mininet:

```text
h21 sh -c 'while true; do curl -4 -sS --max-time 2 http://10.10.20.2:5000/health >/dev/null; sleep 1; done >/tmp/h21-flow.log 2>&1 & echo $!'
```

3. اختاري link موجود فعلًا في الـ path، ثم اعملي isolate له.

4. افحصي:

```bash
curl -s "$API/controller/resilience"
curl -s "$API/network/events"
curl -s "$API/topology/paths?source=h21&destination=h2"
```

5. أوقفي traffic:

```text
h21 pkill -f 'curl.*10.10.20.2:5000/health' || true
```

### النجاح المتوقع

```text
last_recovery.success = true
last_recovery.rerouted > 0
new path لا يحتوي الـ failed link
```

---

## TC-16 — Endpoint history

### الهدف
التأكد أن الأحداث لا تختفي بعد تغير الحالة.

```bash
curl -s "$API/network/events"
curl -s "$API/firewall/events"
curl -s "$API/controller/resilience"
```

### النجاح المتوقع

حتى بعد restore/unblock، يظل history يحتوي:

```text
link_isolation
link_restore
BLOCK_DEVICE
UNBLOCK_DEVICE
resilience topology event
recovery event
```

أما القواعد النشطة فقط فهي التي تختفي من:

```text
/firewall/rules
```

---

## ملاحظة مهمة

لا يلزم تشغيل كل Test Cases. اختاري حسب المطلوب:

| المطلوب | Test Cases |
|---|---|
| IoT data dynamic | TC-02 |
| Flow pending/ready | TC-03 |
| Switch traffic | TC-04 |
| Load balancer | TC-05 وTC-06 |
| Firewall | TC-07 وTC-08 |
| Link status/failure | TC-09 وTC-10 وTC-13 |
| CLFF | TC-11 |
| Resilience | TC-12 |
| Real reroute | TC-14 وTC-15 |
| Event history | TC-16 |
