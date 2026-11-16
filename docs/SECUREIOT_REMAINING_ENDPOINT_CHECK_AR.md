# SecureIoT — فحص الـ Endpoints المتبقية وتوثيق النتائج

هذا الدليل يكمل فحص عقد SecureIoT API بعد اختبار IoT وLoad Balancer وFirewall وlink isolation. الأوامر تستخدم `curl` فقط، ولا تحتاج `jq`.

## 0. التحضير

من Ubuntu terminal العادي، وليس من `mininet>`:

```bash
export API='http://127.0.0.1:8080'
export TOKEN='secureiot-local-demo-token-2026-abcdef'
```

إذا كانت بيئة Ryu شغالة مع authentication، أضيفي هذا header إلى أوامر الـ GET:

```bash
-H "Authorization: Bearer $TOKEN"
```

أما أوامر link وfirewall فتستخدم:

```bash
-H "X-SecureIoT-Token: $TOKEN"
```

> لا تخلطي بين Ubuntu terminal وMininet CLI. أوامر `curl $API/...` تعمل من Ubuntu، وأوامر `h5 ...` أو `h2 ...` تعمل بعد ظهور `mininet>`.

## 1. فحص موحّد لكل الـ GET endpoints

هذا الأمر يطبع اسم endpoint وHTTP status والـ response body:

```bash
for path in \
  /health \
  /runtime/health \
  /controller/state \
  /runtime/controller \
  /runtime/topology \
  /topology/switches \
  /topology/hosts \
  /topology/links \
  /network/vlans \
  /network/vlan-ports \
  /network/load-balancer \
  /network/load-balancer/status \
  /network/load-balancer/backends \
  /network/load-balancer/stats \
  /firewall/status \
  /firewall/rules \
  /firewall/events \
  /network/events \
  /controller/clff \
  /runtime/clff \
  /controller/resilience \
  /runtime/resilience \
  /api/iot/devices \
  /api/iot/sensors \
  /api/iot/telemetry
 do
   echo "===== $path ====="
   curl -sS -w "\nHTTP_STATUS=%{http_code}\n" "$API$path"
   echo
 done
```

النتيجة الطبيعية لمعظم endpoints هي `HTTP_STATUS=200`. إرجاع array فاضية في `/firewall/events` أو `/network/events` لا يعني خطأ؛ معناه أنه لا يوجد event مسجل في تلك اللحظة.

## 2. Runtime وcontroller

```bash
curl -sS "$API/health"
curl -sS "$API/runtime/health"
curl -sS "$API/controller/state"
curl -sS "$API/runtime/controller"
curl -sS "$API/runtime/topology"
```

تحققي من:

```text
status = connected أو healthy
switch_count = 6
switches = [1,2,3,4,5,6]
topology_ready = true
full_topology_discovered = true
```

الـ aliases `/runtime/health` و`/runtime/controller` يجب ألا ترجع 502؛ هي compatibility routes لنفس حالة runtime.

## 3. Switches وhosts وlinks

```bash
curl -sS "$API/topology/switches"
curl -sS "$API/topology/hosts"
curl -sS "$API/topology/links"
```

في الحالة الطبيعية:

```text
switches = 6
physical links = 12 في topology الكاملة
operational links = 12 قبل isolation
```

في `/topology/switches` تحققي من:

```text
switch_id
 dpid
n_ports
status
controller_connected
traffic_active
```

`traffic_active` يجب أن يتغير فقط للسويتشات التي يوجد على مسارها host flow حديث، وليس بسبب LLDP فقط.

في `/topology/hosts` تحققي من host IDs مثل `h2`, `h5`, `h16`, `h18`, `h38`، ومن:

```text
controller_seen
ipv4
vlan_id
port_no
traffic_active
```

## 4. VLAN inventory وVLAN port map

```bash
curl -sS "$API/network/vlans"
curl -sS "$API/network/vlan-ports"
```

الـ VLANs المتوقعة:

```text
VLAN 10 — IoT — 10.10.10.0/24 — gateway 10.10.10.1
VLAN 20 — Services — 10.10.20.0/24 — gateway 10.10.20.1
VLAN 30 — DNS — 10.10.30.0/24 — gateway 10.10.30.1
VLAN 40 — Management — 10.10.40.0/24 — gateway 10.10.40.1
VLAN 50 — Employees — 10.10.50.0/24 — gateway 10.10.50.1
```

كل record في `/network/vlan-ports` يجب أن يحتوي على port حقيقي، وليس `0` أو placeholder:

```text
vlan_id
switch_id
dpid
port_no
host_id
mode = access أو trunk
status = configured
```

## 5. Paths قبل وبعد failure

المسار الذي تم التحقق منه في الـ lab هو `h5 → h2`:

```bash
curl -sS "$API/topology/paths?source=h5&destination=h2"
```

قبل عزل الرابط يكون المسار عادةً:

```text
h5 → s4 → s2 → h2
```

أو يظهر كـ:

```json
"nodes": [4,2,1]
```

اختبري host-path alias أيضًا:

```bash
curl -sS "$API/topology/hosts/h2/path?source=h5"
```

بعد تغيير topology يجب أن يعيد endpoint حساب المسار من `operational_graph`، لا من snapshot قديم.

## 6. OpenFlow Description Stats

نفذي لكل DPID:

```bash
for dpid in 1 2 3 4 5 6; do
  echo "===== DESC DPID $dpid ====="
  curl -sS -w "\nHTTP_STATUS=%{http_code}\n" "$API/stats/desc/$dpid"
  echo
 done
```

الفحص اليدوي لـ DPID 2:

```bash
curl -sS "$API/stats/desc/2"
```

النجاح المتوقع:

```text
HTTP 200
status = ready
dpid = 2
switch_id = s2
of_version = 1.3
```

وقد تظهر fallback values موثقة للـ virtual OVS مثل:

```text
sw_desc = Ryu/OpenFlow 1.3
hw_desc = virtual-datapath
serial_num = dpid-2
```

## 7. OpenFlow Port Stats

أول قراءة قد تعيد `202 pending` لأن الطلب asynchronous. أعيدي القراءة بعد 3 ثوانٍ:

```bash
curl -i "$API/stats/port/2"
sleep 3
curl -i "$API/stats/port/2"
```

الفحص لكل السويتشات:

```bash
for dpid in 1 2 3 4 5 6; do
  echo "===== PORT DPID $dpid ====="
  curl -sS -w "\nHTTP_STATUS=%{http_code}\n" "$API/stats/port/$dpid"
  echo
 done
```

تحققي من وجود:

```text
dpid
status = pending أو ready
ports
port_no
rx_packets
tx_packets
rx_bytes
tx_bytes
rx_dropped
tx_dropped
rx_errors
tx_errors
timestamp
```

إذا ظهر `pending`، فهذا سلوك صحيح وليس failure؛ endpoint أرسل OpenFlow request والقراءة التالية بعد وصول reply يجب أن تصبح `ready`.

## 8. OpenFlow Flow Stats

```bash
curl -i "$API/stats/flow/2"
sleep 3
curl -i "$API/stats/flow/2"
```

ولكل DPID:

```bash
for dpid in 1 2 3 4 5 6; do
  echo "===== FLOW DPID $dpid ====="
  curl -sS -w "\nHTTP_STATUS=%{http_code}\n" "$API/stats/flow/$dpid"
  echo
 done
```

كل flow record يجب أن يعرض counters حقيقية وم serialized strings:

```text
table_id
priority
idle_timeout
hard_timeout
cookie
duration_sec
packet_count
byte_count
match
instructions
```

لإثبات أن counters dynamic:

```bash
curl -sS "$API/stats/flow/2" > /tmp/secureiot-flow-before.json
```

من Mininet:

```text
mininet> h5 ping -c 10 10.10.20.2
```

ثم:

```bash
curl -sS "$API/stats/flow/2" > /tmp/secureiot-flow-after.json
cat /tmp/secureiot-flow-before.json
cat /tmp/secureiot-flow-after.json
```

قارني `packet_count`, `byte_count`, و`timestamp`. يجب أن يزيد counter إذا كان traffic مر عبر DPID 2.

## 9. Load-balancer endpoints

```bash
curl -sS "$API/network/load-balancer"
curl -sS "$API/network/load-balancer/status"
curl -sS "$API/network/load-balancer/backends"
curl -sS "$API/network/load-balancer/stats"
```

القيم المهمة:

```text
VIP = 10.10.20.100:5000
primary = 10.10.20.2:5000
backup = 10.10.20.8:5000
algorithm = round_robin
healthy_backends
requests_total
last_backend
backend_requests
```

من Mininet، استخدمي TCP وليس ping إلى VIP:

```text
mininet> h5 sh -c 'for i in $(seq 1 10); do curl -sS --max-time 3 http://10.10.20.100:5000/; echo; sleep 1; done'
```

ثم:

```bash
curl -sS "$API/network/load-balancer/stats"
```

المفروض `requests_total` و`backend_requests` يزيدان، و`last_backend` يتغير. `h38` هو VIP/Load Balancer؛ لا تستخدمي `ping h38` كاختبار HTTP service.

## 10. Firewall وnetwork events

```bash
curl -sS "$API/firewall/status"
curl -sS "$API/firewall/rules"
curl -sS "$API/firewall/events"
curl -sS "$API/network/events"
```

في baseline:

```text
status = active
 default_policy = DROP
default-deny rule موجودة
blocked_flows = 0 إذا لم يوجد block فعلي
```

بعد block/unblock أو link failure، يجب أن تظل الأحداث في history حتى لو رجعت القاعدة إلى الحالة الطبيعية.

## 11. CLFF وResilience

```bash
curl -sS "$API/controller/clff"
curl -sS "$API/runtime/clff"
curl -sS "$API/controller/resilience"
curl -sS "$API/runtime/resilience"
```

الـ aliases canonical والـ legacy يجب أن يعيدا حالة متوافقة. تحققي من:

```text
CLFF:
ready
root_count
tree_count
last_rebuild_at
last_rebuild_reason
last_error

Resilience:
event_count
recovery_count
last_event
last_recovery
```

## 12. Dynamic link-failure check

شغلي flow مستمرًا من Mininet:

```text
mininet> h5 ping -i 1 10.10.20.2
```

من Ubuntu، اعزلي الرابط الذي كان في المسار `s4-s2`:

```bash
curl -sS -X POST "$API/network/link/isolate" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{"src_dpid":4,"dst_dpid":2,"reason":"dynamic rerouting endpoint test"}'
```

تحققي مباشرة:

```bash
curl -sS "$API/runtime/topology"
curl -sS "$API/topology/links"
curl -sS "$API/topology/paths?source=h5&destination=h2"
curl -sS "$API/controller/clff"
curl -sS "$API/controller/resilience"
curl -sS "$API/network/events"
```

النتيجة الصحيحة التي تم إثباتها في الـ lab:

```text
isolated_links contains [2,4]
link s2-s4 has isolated=true and status=isolated
operational_links excludes [2,4]
old path s4-s2 is removed
new path becomes, for example, [4,5,1]
```

في path response:

```text
links = links used by the current path
isolated_links = links currently isolated
```

لذلك من الطبيعي أن تكون links الحالية `isolated:false`؛ هذا يعني أن الـ rerouted path يستخدم links سليمة.

## 13. Restore والتحقق النهائي

```bash
curl -sS -X POST "$API/network/link/restore" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{"src_dpid":4,"dst_dpid":2,"reason":"restore after dynamic rerouting test"}'
```

انتظري 3–10 ثوانٍ ثم:

```bash
curl -sS "$API/runtime/topology"
curl -sS "$API/topology/links"
curl -sS "$API/topology/paths?source=h5&destination=h2"
curl -sS "$API/controller/clff"
curl -sS "$API/controller/resilience"
curl -sS "$API/network/events"
```

النجاح المتوقع:

```text
isolated_links = []
s2-s4 = isolated:false, status:active
operational_links تحتوي الرابط بعد LLDP rediscovery
CLFF ready = true
link_restore event موجود في history
```

## 14. IoT GET endpoints

```bash
curl -sS "$API/api/iot/devices"
curl -sS "$API/api/iot/sensors"
curl -sS "$API/api/iot/telemetry?device_id=h16&limit=1"
sleep 6
curl -sS "$API/api/iot/telemetry?device_id=h16&limit=1"
```

قارني:

```text
sequence
timestamp
last_seen
readings/value
sample_count
```

القيم يجب أن تكون dynamic. الـ polling الداخلي يحدث على sensor services الخاصة، ولا يحتاج telemetry POST عبر ngrok.

## 15. Evidence snapshot للتقرير

```bash
mkdir -p /tmp/secureiot-endpoint-evidence
for path in \
  /runtime/health \
  /controller/state \
  /runtime/topology \
  /topology/switches \
  /topology/hosts \
  /topology/links \
  /network/vlans \
  /network/vlan-ports \
  /controller/clff \
  /controller/resilience \
  /network/events \
  /network/load-balancer \
  /network/load-balancer/status \
  /network/load-balancer/backends \
  /network/load-balancer/stats \
  /firewall/status \
  /firewall/rules \
  /firewall/events \
  /api/iot/devices \
  /api/iot/sensors; do
  name=$(printf '%s' "$path" | tr '/' '_')
  curl -sS "$API$path" > "/tmp/secureiot-endpoint-evidence${name}.json"
 done

for dpid in 1 2 3 4 5 6; do
  curl -sS "$API/stats/desc/$dpid" > "/tmp/secureiot-endpoint-evidence/desc-$dpid.json"
  curl -sS "$API/stats/port/$dpid" > "/tmp/secureiot-endpoint-evidence/port-$dpid.json"
  curl -sS "$API/stats/flow/$dpid" > "/tmp/secureiot-endpoint-evidence/flow-$dpid.json"
 done
```

## Contract coverage summary

| المجموعة | Endpoints | الفحص |
|---|---|---|
| Runtime | health, controller, topology | connected/ready |
| Inventory | switches, hosts, links | real topology and activity |
| VLAN | vlans, vlan-ports | networks, gateways, concrete ports |
| Paths | paths, host path | computed path and reroute |
| OpenFlow | desc, port, flow | pending ثم ready وcounters حقيقية |
| Load balancer | identity, status, backends, stats | health وround-robin counters |
| Firewall | status, rules, events | default-deny وblock history |
| Resilience | events, CLFF, resilience | isolation, rebuild, recovery |
| IoT | devices, sensors, telemetry | changing readings and last_seen |

`/dataset/run` وAI/trust-score endpoints ليست ضمن Contract Version 2.0-final، لذلك لا تدخل في dashboard network endpoint checklist.
