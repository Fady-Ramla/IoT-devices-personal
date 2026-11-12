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
          | POST /api/iot/telemetry
          v
ngrok -> Ryu Runtime API :8080
          |
          +--> SQLite telemetry store
          +--> dashboard/API GET endpoints

Firewall: Ryu TopologyMonitor -> OpenFlow DROP rule on switches
```

الـ IoT devices لا ترسل مباشرة إلى ngrok. الـ Web/API server هو الذي يعمل polling داخليًا، ثم يرسل القراءة الجديدة إلى Ryu عبر ngrok.

## 2. Update the project

```bash
cd ~/Graduation_Project/IoT-devices
git switch api-runtime-latest-20261111
git pull --ff-only origin api-runtime-latest-20261111
git log -1 --oneline
```

آخر إصلاح للـ firewall يجب أن يظهر كالتالي:

```text
9f80235 Expose live firewall rules and events
```

## 3. Start Ryu — Terminal 1

شغّلي Ryu أولًا واتركي الـ terminal مفتوحًا:

```bash
cd ~/Graduation_Project/IoT-devices

sudo env \
  SECUREIOT_DISABLE_API_AUTH=1 \
  SECUREIOT_API_TOKEN='secureiot-local-demo-token-2026-abcdef' \
  SECUREIOT_CONTROL_TOKEN='secureiot-local-demo-token-2026-abcdef' \
  SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3 \
  SECUREIOT_LB_STATS_FILE=/var/tmp/secureiot-lb-stats.json \
  SECUREIOT_ALLOWED_ORIGIN='https://uneasy-cobweb-headdress.ngrok-free.dev' \
  SECUREIOT_TRAFFIC_ACTIVE_WINDOW=3 \
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

اختبار سريع من Terminal 2:

```bash
curl -i http://127.0.0.1:8080/firewall/status
```

المتوقع `HTTP/1.1 200 OK` و`"status":"active"`.

## 4. Start ngrok — Terminal 2

ngrok يجب أن يوجه إلى Ryu على port `8080`، وليس إلى `h2:5000`:

```bash
ngrok http 127.0.0.1:8080
```

احتفظي بالـ public URL، مثال:

```text
https://uneasy-cobweb-headdress.ngrok-free.dev -> http://127.0.0.1:8080
```

إذا أعطى ngrok hostname جديدًا، غيّري `IOT_TELEMETRY_POST_URL` في خطوة Mininet قبل التشغيل.

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
export IOT_TELEMETRY_POST_URL='https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/telemetry'
export IOT_TELEMETRY_POST_TOKEN=''

sudo -E python3 mininet/Real_network_topology.py
```

لو تغير hostname الخاص بـ ngrok، عدّلي هذا السطر فقط:

```bash
export IOT_TELEMETRY_POST_URL='https://NEW-NGROK-HOST/api/iot/telemetry'
```

## 6. Verify polling inside Mininet

الأوامر التالية تُنفّذ داخل prompt الخاص بـ Mininet، بدون كتابة `mininet>` يدويًا داخل الأمر:

```text
h2 ping -c 2 10.10.20.1
h2 curl --noproxy '*' -sS http://10.10.10.16:8081/health
h2 curl --noproxy '*' -sS http://10.10.10.16:8081/sensor/readings
gw ip addr show sio-wan-gw
gw ip route
h2 curl --noproxy '*' -sS --max-time 10 https://uneasy-cobweb-headdress.ngrok-free.dev/health
h2 ps -ef | grep -E 'web_api_server|iot_poller' | grep -v grep
h2 head -n 20 /tmp/web_api_h2_iot_live.log
```

المتوقع:

- `h2` يستطيع قراءة sensor endpoint على `h16:8081`.
- log يحتوي على polling ناجح.
- ngrok inspector يعرض `POST /api/iot/telemetry` تقريبًا كل 5 ثوانٍ.
- الرد الناجح يكون غالبًا `201 Created`.

## 7. Verify changing telemetry

من Terminal 2 أو أي terminal خارج Mininet:

```bash
curl -sS 'https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/telemetry?device_id=h16&limit=1'
sleep 6
curl -sS 'https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/telemetry?device_id=h16&limit=1'
```

يجب أن يتغير `sequence` و`timestamp` وقيمة sensor.

Endpoints مفيدة:

```bash
curl -sS https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/devices
curl -sS https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/sensors
curl -sS https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/telemetry
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

في lab mode يجب تشغيل Ryu مع:

```bash
SECUREIOT_DISABLE_API_AUTH=1
```

أما `/network/action` فيظل يحتاج `SECUREIOT_CONTROL_TOKEN` حتى مع تعطيل API auth.

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
