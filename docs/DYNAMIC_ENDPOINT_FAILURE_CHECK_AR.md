# Dynamic Endpoint Check — Link Failure and Recovery

هذا الاختبار يثبت أن الـ endpoints لا تعرض snapshot ثابتًا، بل تتغير مع link failure ثم recovery.

> شغّلي Ryu وMininet أولًا حسب `SECUREIOT_QUICK_START_AR.md`. في lab mode يمكن ترك `SECUREIOT_DISABLE_API_AUTH=1`، لكن عمليات isolate/restore تحتاج `X-SecureIoT-Token`.

## 1. Baseline قبل الفشل

من terminal عادي:

```bash
export API=http://127.0.0.1:8080
export TOKEN='secureiot-local-demo-token-2026-abcdef'

curl -s "$API/topology/links" > /tmp/links.before.json
curl -s "$API/network/events" > /tmp/events.before.json
curl -s "$API/controller/clff" > /tmp/clff.before.json
curl -s "$API/controller/resilience" > /tmp/resilience.before.json
curl -i "$API/stats/flow/1"
```

### ماذا نثبت في الـ baseline؟

- `/topology/links` يعرض links بحالة `status: active`.
- `/controller/clff` يعرض `ready: true` و`operational_graph_edges` بعدد الروابط التشغيلية.
- `/controller/resilience` يعرض `event_count` و`recovery_count` الحاليين.
- `/stats/flow/1` قد يرجع `202` مع `status: pending` إذا لم تصل OpenFlow flow-stats reply بعد. هذا متوقع؛ endpoint يعيد `200` بعد وصول الرد، ولا يختلق flow فارغًا على أنه live flow.

## 2. اعمل link failure يدويًا

سنفصل الرابط بين `s1` و`s2`:

```bash
curl -i -X POST "$API/network/link/isolate" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "src_dpid": 1,
    "dst_dpid": 2,
    "reason": "dynamic endpoint failure test"
  }'
```

المتوقع:

```json
{
  "success": true,
  "status": "executed",
  "action": "ISOLATE",
  "src_dpid": 1,
  "dst_dpid": 2
}
```

## 3. افحص التغييرات فورًا

```bash
curl -s "$API/topology/links"
curl -s "$API/runtime/topology"
curl -s "$API/network/events"
curl -s "$API/controller/clff"
curl -s "$API/controller/resilience"
curl -i "$API/stats/flow/1"
```

### التغييرات المتوقعة

في `/topology/links` يجب أن يصبح الرابط:

```json
{
  "src_dpid": 1,
  "dst_dpid": 2,
  "isolated": true,
  "status": "isolated"
}
```

في `/runtime/topology` يجب أن يظهر الرابط في `isolated_links` ويختفي من `operational_links`، بينما تظل الـ physical `links` موجودة لأنها ما زالت جزءًا من topology inventory.

في `/network/events` يجب أن يظهر event جديد مثل:

```json
{
  "event_type": "link_isolation",
  "status": "executed",
  "failed_link": [1, 2]
}
```

في `/controller/clff`:

- `operational_graph_edges` يقل بمقدار الرابط المعزول.
- `last_rebuild_reason` يصبح `isolated_link_change`.
- `last_rebuild_at` يتغير.
- `ready` يظل `true` إذا كان graph البديل ما زال connected؛ وإلا يصبح `false` مع `last_error` يوضح السبب.

في `/controller/resilience` قد يظهر التغيير بعد أن يصل LLDP/port failure إلى Ryu. لذلك افحصيه عدة مرات:

```bash
for i in 1 2 3 4 5; do
  date -Is
  curl -s "$API/controller/resilience"
  sleep 3
done
```

عند وصول physical topology event:

- `event_count` يزيد.
- `last_event.removed` يحتوي `[1, 2]` أو الرابط المعزول.
- `recovery_count` يزيد بعد تنفيذ recovery.
- `last_recovery.failed_links` يحتوي الرابط الفاشل.
- `last_recovery.rerouted` يوضح عدد الـ active flows التي تم تحويلها.

## 4. اختبار flow stats pending ثم live

الـ flow statistics endpoint يعتمد على OpenFlow reply حقيقي:

```bash
curl -i "$API/stats/flow/1"
sleep 3
curl -i "$API/stats/flow/1"
```

- `202` و`status: pending` يعني أن request أُرسل وما زلنا ننتظر reply.
- `200` و`status: ready` يعني أن flow stats وصلت وتم تخزينها.
- لا يتم اعتبار `flows: []` flow نشطًا؛ هي فقط قيمة فارغة أثناء انتظار الرد أو عندما لا توجد flows في switch.

لإنشاء traffic يحرّك counters، من Mininet:

```text
h16 ping -c 5 10.10.10.1
h16 curl --max-time 5 http://10.10.10.1/ || true
```

ثم افحصي:

```bash
curl -s "$API/stats/flow/1"
curl -s "$API/topology/switches"
```

`traffic_active` في switches يتغير بعد counter growth ثم ينتهي بعد نافذة `SECUREIOT_TRAFFIC_ACTIVE_WINDOW`.

## 5. Restore link

```bash
curl -i -X POST "$API/network/link/restore" \
  -H 'Content-Type: application/json' \
  -H "X-SecureIoT-Token: $TOKEN" \
  -d '{
    "src_dpid": 1,
    "dst_dpid": 2,
    "reason": "dynamic endpoint recovery test"
  }'
```

ثم افحصي:

```bash
curl -s "$API/topology/links"
curl -s "$API/runtime/topology"
curl -s "$API/network/events"
curl -s "$API/controller/clff"
curl -s "$API/controller/resilience"
```

المتوقع:

- الرابط يرجع إلى `status: active` و`isolated: false`.
- `operational_links` يعيد الرابط بعد إعادة اكتشافه.
- event جديد `link_restore` يظهر في `/network/events`.
- CLFF يعمل rebuild جديد، ويتغير `last_rebuild_at` و`last_rebuild_reason`.
- Resilience يحتفظ بتاريخ failure/recovery ولا يمسح الأحداث السابقة.
- الـ active flow لا يرجع لمساره القديم تلقائيًا، لتجنب route flapping؛ يظل على المسار البديل حتى قرار routing جديد.

## 6. Endpoint checklist للـ dashboard

| Endpoint | القيمة الديناميكية التي يجب مراقبتها |
|---|---|
| `/topology/links` | `isolated`, `status` |
| `/runtime/topology` | `isolated_links`, `operational_links`, `topology_change_count` |
| `/network/events` | `link_isolation`, `link_restore`, rerouting/resilience events |
| `/stats/flow/{dpid}` | `202 pending` ثم `200 ready`, `flows`, timestamp |
| `/stats/port/{dpid}` | counters و`timestamp` |
| `/topology/switches` | `traffic_active`, `last_traffic_at` |
| `/controller/clff` | `ready`, operational edge count, rebuild time/reason |
| `/controller/resilience` | event/recovery counters وlast event/recovery |
| `/topology/paths` | active path بعد routing/recovery |
| `/firewall/rules` | active DROP rules |
| `/firewall/events` | block/unblock history |

## 7. ملاحظة مهمة

الـ physical link قد يظل ظاهرًا في `links` بعد failure لأنه inventory لما اكتشفه LLDP. الحالة التي يعتمد عليها routing هي `operational_links`، ولذلك يجب متابعة endpointين معًا:

```bash
curl -s "$API/topology/links"
curl -s "$API/runtime/topology"
```

وجود link في `links` مع `isolated: true` وغيابه من `operational_links` هو السلوك الصحيح.
