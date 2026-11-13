# SecureIoT — طريقة التشغيل السريعة

هذا المستند يشرح تشغيل النظام من البداية، وتشغيل Mininet وIoT server polling وngrok، ثم اختبار الـ API والـ firewall.

## 1. Architecture

```text
IoT hosts h5..h16
  GET /sensor/readings:8081
          |
          | private polling through Mininet
          v
Web/API server h2:5000
  background poller every 5 seconds
          |
          | local SQLite write
          v
shared SQLite: /var/lib/secureiot/iot-telemetry.sqlite3
          ^
          | Ryu reads the same database
          |
read-only gateway :8090 <- ngrok <- WebTrack authenticated GET

Firewall: Ryu TopologyMonitor -> OpenFlow DROP rule on switches
```

الـ Web/API server يعمل polling للـ sensors باستخدام GET ويحفظ القراءات محليًا في SQLite. الـ Dashboard يستخدم GET لقراءة الـ snapshot عبر read-only gateway. لا يوجد telemetry POST أو GET يغيّر قاعدة البيانات عبر ngrok.

## 2. Update the project

```bash
cd ~/Graduation_Project/IoT-devices
git switch api-runtime-latest-20261111
git pull --ff-only origin api-runtime-latest-20261111
git log -1 --oneline
```

## 3. Start Ryu — Terminal 1

شغّلي Ryu أولًا واتركي الـ terminal مفتوحًا:

```bash
cd ~/Graduation_Project/IoT-devices
source ~/.secureiot_api_token
sudo --preserve-env=SECUREIOT_API_TOKEN env \
  SECUREIOT_API_TOKEN="$SECUREIOT_API_TOKEN" \
  SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3 \
  SECUREIOT_LB_STATS_FILE=/var/tmp/secureiot-lb-stats.json \
  SECUREIOT_TRAFFIC_ACTIVE_WINDOW=8 \
  "$PWD/ryu_env/bin/ryu-manager" \
  --observe-links \
  --ofp-tcp-listen-port 6633 \
  --wsapi-host 127.0.0.1 \
  --wsapi-port 8080 \
  topology_monitor.py \
  traffic_monitor_merged.py \
  resilience_engine.py \
  runtime_network_api.py
```

يجب إبقاء مصادقة Ryu مفعّلة؛ لا تضعي `SECUREIOT_DISABLE_API_AUTH=1` ولا تستخدمي token ثابتًا داخل الأمر.

اختبار سريع من Terminal 2:

```bash
source ~/.secureiot_api_token
curl -i -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  http://127.0.0.1:8080/firewall/status
```

المتوقع `HTTP/1.1 200 OK` و`"status":"active"`.

## 4. Start ngrok — Terminal 2

ngrok يجب أن يوجه إلى read-only gateway المحلي على port `8090`، وليس مباشرةً إلى Ryu `8080` أو Flask `h2:5000`. استخدمي الخدمات المثبتة على الـVM:

```bash
sudo systemctl is-active secureiot-webtrack-readonly.service ngrok-webtrack-readonly.service
```

استخدمي الـ public URL الحالي للخدمة. لا تشغّلي tunnel إضافيًا إلى Ryu مباشرةً.

```text
https://<your-ngrok-host> -> http://127.0.0.1:8090
```

لو تغيّر hostname، حدّثيه عند فريق WebTrack فقط؛ لا تضعيه في إعدادات IoT poller.

لرؤية الطلبات:

```bash
curl -s http://127.0.0.1:4040/api/requests/http
```

أو افتحي:

```text
http://127.0.0.1:4040
```

## 5. Start Mininet — Terminal 3

```bash
cd ~/Graduation_Project/IoT-devices
sudo mn -c

export RYU_IP=127.0.0.1
export RYU_PORT=6633
export START_DEMO_SERVICES=1
export START_IOT_SIMULATORS=1
export IOT_POLLING_ENABLED=1
export IOT_POLL_INTERVAL=5
export IOT_SENSOR_PORT=8081
export SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3
unset IOT_TELEMETRY_GET_URL IOT_TELEMETRY_POST_URL

sudo -E python3 mininet/Real_network_topology.py
```

## 6. Verify polling inside Mininet

الأوامر التالية تُنفّذ داخل prompt الخاص بـ Mininet، بدون كتابة `mininet>` يدويًا داخل الأمر:

```text
h2 ping -c 2 10.10.20.1
h2 curl --noproxy '*' -sS http://10.10.10.16:8081/health
h2 curl --noproxy '*' -sS http://10.10.10.16:8081/sensor/readings
h2 ps -ef | grep -E 'web_api_server|iot_poller' | grep -v grep
h2 head -n 20 /tmp/web_api_h2_iot_live.log
```

المتوقع:

- `h2` يستطيع قراءة sensor endpoint على `h16:8081`.
- log يحتوي على `IoT telemetry stored` تقريبًا كل 5 ثوانٍ.
- قاعدة SQLite تتحدث محليًا؛ لا تنتظري POST من Mininet إلى ngrok.

## 7. Verify changing telemetry

من Terminal 2 أو أي terminal خارج Mininet:

```bash
BASE_URL='https://<your-ngrok-host>'
curl -sS "$BASE_URL/dashboard/snapshot"
sleep 6
curl -sS "$BASE_URL/dashboard/snapshot"
```

افحصي `iot_telemetry` داخل JSON؛ يجب أن يتغير `sequence` و`timestamp` وقيمة sensor. الـ GET يقرأ فقط ولا يبدأ poll جديدًا؛ الـ poller يعمل تلقائيًا بالخلفية.

Endpoints مفيدة للـ Dashboard عبر الـ gateway:

```bash
curl -sS "$BASE_URL/dashboard/snapshot"
```

## 8. Test the firewall dynamically

### 8.1 Get the device MAC

داخل Mininet:

```text
h16 cat /sys/class/net/h16-eth0/address
```

مثال:

```text
00:00:00:00:00:11
```

### 8.2 Block the device

من terminal عادي خارج Mininet:

```bash
curl -i -X POST \
  http://127.0.0.1:8080/network/action \
  -H 'Content-Type: application/json' \
  -H 'X-SecureIoT-Token: secureiot-local-demo-token-2026-abcdef' \
  -d '{
    "action": "BLOCK_DEVICE",
    "mac": "00:00:00:00:00:11",
    "host_ip": "10.10.10.16",
    "request_id": "FIREWALL-TEST-001",
    "reason": "manual firewall integration test"
  }'
```

المتوقع:

```json
{"success":true,"status":"executed","action":"BLOCK_DEVICE"}
```

### 8.3 Verify the active rule, event, and status

```bash
curl -s http://127.0.0.1:8080/firewall/rules
curl -s http://127.0.0.1:8080/firewall/events
curl -s http://127.0.0.1:8080/firewall/status
```

المتوقع أن تظهر:

```text
rule_id: device-block-000000000011
priority: 50000
action: DROP
blocked_flows: 1
blocked_device_count: 1
```

### 8.4 Unblock the device

```bash
curl -i -X POST \
  http://127.0.0.1:8080/network/action \
  -H 'Content-Type: application/json' \
  -H 'X-SecureIoT-Token: secureiot-local-demo-token-2026-abcdef' \
  -d '{
    "action": "UNBLOCK_DEVICE",
    "mac": "00:00:00:00:00:11",
    "host_ip": "10.10.10.16",
    "request_id": "FIREWALL-TEST-002",
    "reason": "manual firewall recovery test"
  }'
```

بعد ذلك تختفي قاعدة `device-block-...` من `/firewall/rules`، وترجع counters إلى صفر، بينما يظل تاريخ block/unblock في `/firewall/events`.

`/network/action` يحتاج `X-SecureIoT-Token`. هذا ليس AI token؛ إنه control token لتنفيذ قرارات الـ firewall.

## 9. Troubleshooting

### Ryu يعرض `Address already in use`

```bash
sudo ss -ltnp | grep -E ':8080|:6633'
```

أغلقي process القديم أو استخدميه بدل تشغيل Ryu مرة ثانية.

### Poller يعرض `Temporary failure in name resolution`

تحققي من:

```text
mininet> gw ip route
mininet> h2 cat /etc/resolv.conf
mininet> h2 curl --noproxy '*' -v --max-time 10 https://<ngrok-host>/health
```

المشكلة غالبًا في WAN/NAT أو DNS من Services VLAN، وليست في sensor endpoint.

### `/firewall/events` يرجع `[]`

لا يوجد event حتى الآن أو تم رفض الطلب. تأكدي من:

- استخدام MAC حقيقي بصيغة `aa:bb:cc:dd:ee:ff`.
- استخدام header `X-SecureIoT-Token`.
- أن Ryu يعمل بملف commit الأخير.

### ngrok يعرض `401`

الـ public gateway لا يحتاج client bearer token. تأكدي أن نسخة الـ proxy المحدّثة
هي المثبتة، وأنها تحتفظ بـ Ryu token داخليًا في ملف الخدمة. لا تعالجي `401`
بتعطيل مصادقة Ryu أو بفتح منفذ Ryu مباشرةً على الإنترنت. أما أوامر التحكم فتظل
محلية ومحمية بتوكن التحكم.

## 10. Stop and clean up

للخروج من Mininet:

```text
mininet> exit
```

ثم نظّفي namespaces والـ OVS state:

```bash
sudo mn -c
```

أوقفي Ryu وngrok من الـ terminals الخاصة بهما باستخدام `Ctrl+C`.
