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
التأكد أن simulator اله5-h16 يرسل readings جديدة إلى Web/API الخاص داخل Mininet، وأن contract GET يقرأ آخر sample من SQLite المشتركة.

### التنفيذ

```bash
curl -s "$API/api/iot/telemetry?device_id=h16&limit=1"
sleep 11
curl -s "$API/api/iot/telemetry?device_id=h16&limit=1"
```

### النجاح المتوقع

قارني الردين. يجب أن يتغير:

```text
sequence
timestamp
vibration_rms أو sensor value
```

ولفحص الـ inventory:

```bash
curl -s "$API/api/iot/devices"
curl -s "$API/api/iot/sensors"
```

### فحص simulator وWeb/API الداخليين من Mininet

داخل Mininet فقط:

```text
h2 curl --noproxy '*' -sS http://127.0.0.1:5000/health
h16 tail -n 15 /tmp/secureiot-h16-iot.log
h2 tail -n 25 /tmp/web_api_h2_iot_live.log
```

يُتوقع `telemetry sent ... http_status=202` في log الخاص بـh16. الـPOST داخلي فقط من simulator إلى h2:5000؛ الـDashboard يستخدم GET عبر الـgateway لقراءة SQLite.

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

## TC-04 — Telemetry / ICMP / HTTP-Load Balancer traffic activity

### الهدف
التأكد أن `traffic_active` يعكس عيّنات telemetry الناجحة، وICMP ping، وتدفّق HTTP/Load Balancer على منافذ الخدمات المعرّفة للمشروع (ومنها 5000 و443). لا يكفي وجود port counters عامة أو flow قديم لتفعيل الحالة.

### التنفيذ

داخل Mininet، h27 على s5 وh28 على s6 وفي نفس VLAN. ابدئي ping محدودًا بالخلفية حتى يبقى traffic جاريًا أثناء GET checks:

```text
h27 sh -c 'ping -n -i 0.5 -c 60 10.10.50.28 >/tmp/h27_to_h28_ping.log 2>&1 &'
```

لاختبار HTTP والـLoad Balancer بدلًا من ping، شغّلي طلبات متواصلة من h21 إلى الـVIP ‏10.10.20.100:5000 (الـLoad Balancer هو h38):

```text
h21 sh -c 'for i in $(seq 1 60); do curl -4 -fsS --max-time 2 http://10.10.20.100:5000/health >/dev/null; sleep 1; done' &
```

من Terminal عادي خارج Mininet، أثناء استمرار الـping:

```bash
BASE_URL='https://<your-current-ngrok-host>'
python3 webtrack_gateway/check_dynamic_endpoints.py "$BASE_URL"
```

أثناء طلبات الـLoad Balancer، افحصي حالة الـhosts والـswitches مباشرةً:

```bash
curl -fsS "$BASE_URL/topology/hosts" | python3 -c 'import json,sys; [print(h["host_id"],"traffic_active=",h.get("traffic_active"),"active_flows=",h.get("active_flows"),"path=",h.get("path")) for h in json.load(sys.stdin) if h.get("host_id") in {"h21","h38","h2","h18"}]'
curl -fsS "$BASE_URL/topology/switches" | python3 -c 'import json,sys; [print(s["switch_id"],"traffic_active=",s.get("traffic_active"),"last_traffic_at=",s.get("last_traffic_at")) for s in json.load(sys.stdin)]'
```

### النجاح المتوقع

- للـping، يزيد عداد قاعدة ICMP echo المخصصة. ولـHTTP، تزيد counters لقواعد الخدمة/الـLoad Balancer ذات الأولوية المخصصة. يظهر الطرفان والسويتشات على المسار `traffic_active: true`، وتحتوي `active_flows` على مسار حديث مصنّف `ping` أو `http` أو `load_balancer`.
- مع VIP الاختبار، يتغيّر `requests_total` و`last_backend` في `/network/load-balancer/stats`، ويظهر نشاط المسار بين h21 وh38 والـbackend الذي استقبل الطلب.
- `/topology/paths?source=h27&destination=h28` و`/topology/hosts/h28/path?source=h27` يعرضان المسار؛ مع flow فعلي متتبع يظهر `path_source: installed_flow` و`nodes` من DPID 5 إلى DPID 6. رد `computed: true` وحده يثبت graph route ممكنًا، وليس flow متثبتًا.
- بعد توقف كل ping/HTTP على host أو path، ترجع الحالة إلى `false` خلال نحو 8 ثوانٍ من آخر packet/counter delta. قد يظل h2 أو h38 أو backend نشطًا إذا استمرت telemetry أو LB health checks؛ هذا نشاط حقيقي وليس stale state. لا يُعدّ المسار القديم في `path_history` نشاطًا جاريًا.
- يجب أن يتغير sequence/timestamp الخاص بقراءة h16 بين عينتين يفصل بينهما 11 ثانية تقريبًا طالما simulator يعمل. الـGET يقرأ SQLite ولا يبدأ توليد أو ingestion جديدًا.
- الـPOST من IoT simulator إلى Web/API خاص ولا يمر عبر ngrok؛ واجهة المستخدم تقرأ telemetry باستخدام GET. كما أن مجرد GET للداشبورد أو وجود مسار محفوظ لا يثبت traffic على الـdata plane.

بعد انتهاء ping أو طلبات الـLoad Balancer، انتظري 10 ثوانٍ ثم أعيدي `GET /topology/hosts` و`GET /topology/switches`. تحققي خصوصًا من h21 (مصدر الاختبار): يجب أن تنطفئ حالته إذا لم يبقَ له traffic؛ أما h2/h38 أو سويتشات المسار فقد تظل نشطة عند استمرار health checks أو telemetry. لم يتغير أي VLAN أو link في هذا الاختبار.

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

في اختبار failover، إذا كان الـprimary غير healthy وتم توجيه الطلب إلى backup، يزيد `backend_failovers` لكل طلب تم تحويله. اختيار backup بسبب round-robin والـprimary سليم لا يُحسب failover. وتظل الزيادة موجودة أيضًا عند عدم وجود backend healthy أو فشل الاتصال بالـbackend المختار.

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

اتركي traffic مستمرًا قبل العزل، ثم افحصي المسار على نفس endpoint:

```bash
curl -s "$API/topology/paths?source=h27&destination=h28" | python3 -m json.tool
curl -s "$API/topology/hosts/h28/path?source=h27" | python3 -m json.tool
```

الرد قد يحتوي `path_source=installed_flow` عندما يكون المسار مأخوذًا من flow فعلي، أو `computed=true` عندما لا يوجد flow متتبع. إذا كان الـflow المرصود عكس اتجاه الاستعلام، يعكس الـAPI ترتيب الـnodes ويضع `flow_direction=reverse_observation`؛ كما يعرض سجل الحدث `direction_reversed=true` مع حقول توضح الاتجاه المرصود. حقل `history` داخل نفس الرد يعرض المسار الأول، تغييرات المسار، وأحداث link down/restore مع الوقت والسبب. لا يوجد endpoint جديد.

بعد link isolation ثم restore كرري الأمرين نفسيهما وقارني `nodes` و`history`. يجب أن يسجل التاريخ حالة الرابط وقت التغيير، والمسار الجديد إذا أعاد الـcontroller توجيه flow متأثرًا. قد يظل flow صحيحًا على مسار backup بعد restore؛ لذلك لا يُشترط الرجوع فورًا إلى أقصر مسار.

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

## TC-17 — SSH attempts and authenticated logins

### الهدف
عرض محاولة SSH ونتيجة المصادقة بين جهازين داخل ردود الـGET الحالية، مع إظهار المسار من غير كشف اسم المستخدم أو كلمة المرور. `ssh_events` مصدره سجل `sshd`، أما `traffic_active` و`active_flows` فيعتمدان على مرور TCP/22 المرصود في OpenFlow؛ سجل login قد يبقى ظاهرًا كتاريخ بعد انتهاء الجلسة، لكنه لا يجعل `traffic_active` يظل true.

### سياسة الوصول
السياسة الفعلية تسمح لأجهزة Management VLAN 40 فقط (`h36` ‏10.10.40.36 و`h37` ‏10.10.40.37) بالوصول إلى TCP/22 على خادمي SSH المعرّفين: الأساسي `h4` ‏10.10.20.4 والاحتياطي `h20` ‏10.10.20.20. عند منافذ وصول الأجهزة، تُسقط قواعد OpenFlow محاولات SSH الصادرة من VLANs 10 و20 و30 و50. وعلى الـtrunks، تُطابق IPv4 source subnet الأصلية بدلًا من VLAN tag؛ لأن بوابة الشبكة تغيّر VLAN tag للاتصال الموجّه من VLAN 40 إلى VLAN 20 مع إبقاء source IP الخاص بـh36/h37. تُحظر أيضًا IPv6 SSH محليًا عند منافذ الأجهزة غير الإدارية، ولا تتأثر أنواع الترافيك الأخرى.

بعد تشغيل Mininet وانتظار ظهور `VLAN map ready` في سجل Ryu، اختبري من داخل Mininet:

```text
h21 nc -vz -w 2 10.10.20.4 22
h36 nc -vz -w 2 10.10.20.4 22
h37 nc -vz -w 2 10.10.20.4 22
```

الأول يجب أن يفشل أو ينتهي بمهلة؛ الاثنان الآخران يجب أن يصلا إلى h4 إذا كان `sshd` يستمع. افحصي سياسة الجدار عبر GET موجود:

```bash
curl -fsS "$API/firewall/rules" | python3 -c 'import json,sys; [print(r) for r in json.load(sys.stdin) if str(r.get("rule_id", "")).startswith("ssh-")]'
```

يجب أن تظهَر قواعد `ssh-management-allow-*` و`ssh-nonmanagement-drop-*` بحالة `installed`. محاولة مرفوضة عند الـswitch لا تصل إلى `sshd`، لذلك لا يُتوقع أن تظهر كسجل مصادقة داخل `ssh_events`؛ قواعد الـACL ظاهرة في `/firewall/rules`.

### تجهيز خادم h4 لتسجيل أحداث sshd
داخل Mininet، تحققي أولًا من أن port 22 مستمع:

```text
h4 ss -lntp '( sport = :22 )'
```

استخدمي `-e` لتسجيل رسائل sshd في ملف خاص داخل مجلد runtime بصلاحية 700، مع بادئة وقت UTC لكل سطر. إذا كان هناك sshd يعمل بالفعل ولا يكتب هذا الملف، أوقفي فقط PID الخاص بالمستمع على h4 بعد التأكد منه؛ إيقافه ينهي جلسات SSH الحالية. ثم شغّلي:

```text
h4 sh -c 'install -d -m 700 /run/secureiot/ssh; touch /run/secureiot/ssh/secureiot-sshd-h4.log; chmod 600 /run/secureiot/ssh/secureiot-sshd-h4.log; umask 077; ( /usr/sbin/sshd -D -e 2>&1 | while IFS= read -r line; do printf "%s %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$line" >> /run/secureiot/ssh/secureiot-sshd-h4.log; done ) >/dev/null 2>&1 &'
```

لا تستخدمي `pkill sshd` من Mininet؛ قد يوقف خوادم SSH أخرى على الـVM. إذا لم يكن SSH server مثبتًا على الـVM أصلًا، ثبتيه على الـVM ثم أعيدي تشغيل Mininet قبل تنفيذ الاختبار.

### تنفيذ تسجيل دخول من h36 إلى h4
اتركي جلسة SSH مفتوحة مؤقتًا:

```text
h36 ssh -o StrictHostKeyChecking=accept-new zolikha@10.10.20.4
```

اكتبي كلمة المرور عند prompt التفاعلي فقط، ولا تضعيها في أمر أو في GET. من terminal عادي آخر، أثناء/بعد الاختبار:

```bash
BASE_URL='https://<your-current-ngrok-host>'
curl -fsS "$BASE_URL/topology/hosts" | python3 -c 'import json,sys; [print(h["host_id"],"traffic_active=",h.get("traffic_active"),"active_flows=",[(f.get("traffic_category"),f.get("path")) for f in h.get("active_flows",[])],"ssh_events=",h.get("ssh_events")) for h in json.load(sys.stdin) if h.get("host_id") in {"h36","h4"}]'
curl -fsS "$BASE_URL/topology/paths?source=h36&destination=h4" | python3 -m json.tool
```

لاختبار الرفض، نفّذي محاولة واحدة بكلمة مرور خاطئة عند prompt، ثم أعيدي GET؛ لا تسجلي كلمة المرور في command history.

### النجاح المتوقع
- يظهر الحدث نفسه على h36 وh4 داخل `ssh_events`، مع `source_host_id=h36` و`destination_host_id=h4` و`destination_port=22`.
- تتضمن `event_type` القيم `connection_attempt` و`login_success` أو `login_failure` حسب ما سجله sshd. لا تتضمن الاستجابة اسم المستخدم أو نص سجل sshd الخام أو كلمة المرور.
- يحتوي رد `/topology/paths` على `ssh_events` للزوج المطلوب. يكون `path_source=installed_flow` فقط عند وجود flow مرصود؛ وإلا يكون `computed` أو `not_observed` بوضوح.
- أثناء وجود حزم TCP/22 حديثة، يصنّف `active_flows[].traffic_category` كـ`ssh` ويكون `traffic_active=true` للطرفين والسويتشات التي رصدت العدادات. لا يعني سجل نجاح login وحده أن الاتصال ما زال نشطًا.
- الـgateway يظل GET-only؛ لم تتم إضافة endpoint أو POST.

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
| SSH audit and activity | TC-17 |

---

## الحقول الثابتة مقابل المتغيرة

| الحقل / المجموعة | التصنيف | التوضيح |
|---|---|---|
| `host_id`, `switch_id`, `dpid`, `ipv4`, `vlan_id` | ثابت/مهيأ | مصدره إعدادات Mininet والطوبولوجيا؛ لا يتغير أثناء التجربة العادية. |
| `port_no` | مهيأ مع احتمال اختلاف البيئة | قيمة منفذ host من إعدادات/اكتشاف الـcontroller، وليست counter للمرور. |
| `status`, `controller_seen`, `traffic_active`, `last_seen` | ديناميكي | يعكس حالة الاتصال وآخر رصد حقيقي. `traffic_active` يشمل ICMP ping وHTTP/Load Balancer وTCP/22 المرصود وقراءات telemetry الناجحة، ويعود إلى false بعد انتهاء نافذة النشاط؛ لا يُمدَّد بمجرد وجود حدث SSH تاريخي. |
| `path`, `path_source`, `history`, `active_flows` | ديناميكي | يتأثر بالـflow الفعلي، وتغيّر الروابط، وإعادة التوجيه. `history` يظل داخل الاستجابة الحالية لـ`/topology/paths` أو `/topology/hosts/{host_id}/path`، وليس endpoint منفصلًا. |
| `ssh_events` | ديناميكي/تاريخي | يُقرأ من سجل sshd لكل host خلال آخر 24 ساعة (حتى 200 حدث على مستوى الرد)، ويُعرض على host العميل والخادم وفي استجابة path الموجودة؛ تتضمن النتيجة والنقاط الطرفية والتوقيت فقط، ولا تُعرض أسماء المستخدمين أو كلمات المرور. |
| OpenFlow packet/byte counters | ديناميكي تراكمي | تتغير مع المرور حتى تنتهي/تحذف القاعدة أو يعاد تشغيل الـswitch/controller. |
| topology links و`isolated_links` | ديناميكي | تتغير عند link down/restore أو العزل/الاستعادة. |
| telemetry readings و`sequence` و`timestamp` | ديناميكي | تتغير مع كل قراءة جديدة محفوظة؛ طلبات GET تقرأ المخزن ولا تبدأ polling أو ingestion. |
| resilience events/counters, firewall events, load-balancer counters | ديناميكي | تتغير عند recovery أو security action أو طلب خدمة جديد، على الترتيب. |
