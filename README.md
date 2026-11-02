# Person 3 — Explicit MAC Device Blocking

هذه الحزمة تعدّل الملفات المرسلة فقط، وتفصل **تقييم الثقة** عن **تنفيذ الحظر**.

## السلوك بعد التعديل

- `80–100` ينتج `TRUSTED` و`ALLOW`.
- `0–79` ينتج `UNTRUSTED` و`KEEP_UNTRUSTED`.
- **لا يُصدر Trust Score أو تنبؤ AI أمر حظر تلقائيًا.**
- الحظر أو فكّه يحصل فقط عندما يرسل Security فعلًا صريحًا: `BLOCK_DEVICE` أو `UNBLOCK_DEVICE`.
- MAC هو هوية المطابقة في قاعدة OpenFlow. عنوان IP اختياري للتسجيل فقط؛ تغييره لا يلغي الحظر.
- تُثبّت قاعدة إسقاط لحزم المصدر MAC على كل السويتشات المتصلة، وتُعاد إضافتها عند اتصال سويتش جديد أثناء تشغيل Ryu.
- فك الحظر يحذف قاعدة MAC فقط، ولا يغيّر Trust Score أو Trust State المخزّنين.

## الملفات

انسخ الملفات مع الحفاظ على المسارات داخل مجلد المشروع:

```text
traffic_monitor_merged.py
topology_monitor.py
zero_trust/
  zero_trust_policy.py
  zero_trust_decision.py
  zero_trust_engine.py
  zero_trust_network_bridge.py
tests/
  test_explicit_device_block.py
```

احتفظ بنسخة احتياطية من الملفات الحالية قبل الاستبدال. يعتمد `topology_monitor.py` على `path_engine.py` الموجود أصلًا في المشروع، ولم يتغير ذلك الملف.

## عقد أمر Security

استخدم `ZeroTrustNetworkBridge.block_device(...)` و`unblock_device(...)` من مكوّن Security. شكل الطلب الذي يرسله الجسر إلى `POST /network/action`:

```json
{
  "action": "BLOCK_DEVICE",
  "mac": "02:00:00:00:00:05",
  "ip": "10.0.0.5",
  "request_id": "SEC-001",
  "reason": "malicious traffic detected"
}
```

ولفك الحظر، أرسل `"action": "UNBLOCK_DEVICE"` مع **نفس MAC**. يمكن حذف `ip` عند عدم توفره. لا ترسل `trust_score` أو `trust_state` لهذا الأمر؛ الحظر لا يحدّثهما.

مثال الاستدعاء من Security:

```python
bridge.block_device(
    mac="02:00:00:00:00:05",
    ip="10.0.0.5",
    request_id="SEC-001",
    reason="malicious traffic detected",
)

# بعد قرار أمني صريح بالسماح مجددًا:
bridge.unblock_device(
    mac="02:00:00:00:00:05",
    ip="10.0.0.5",
    request_id="SEC-002",
    reason="explicit recovery approval",
)
```

## التحقق

من جذر المشروع:

```bash
python3 -m py_compile traffic_monitor_merged.py topology_monitor.py zero_trust/*.py
python3 -m unittest -v tests/test_explicit_device_block.py
```

تحقق من قاعدة الـdrop على السويتشات:

```text
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=50000
```

كرر الفحص على بقية السويتشات. بعد أمر فك الحظر، يجب أن تختفي قاعدة MAC ذات الأولوية `50000`. اختبر كذلك أن تغيير IP للجهاز لا يعيد اتصاله، وأن جهازًا آخر يظل قادرًا على الاتصال.

## حدود يجب معرفتها

سجل الأجهزة المحظورة محفوظ في ذاكرة Ryu؛ يستمر عند تنقّل الجهاز بين السويتشات وعند اتصال سويتش جديد **ما دام Ryu يعمل**، لكنه لا يبقى بعد إعادة تشغيل عملية Ryu. كما أن MAC قابل للانتحال؛ إذا كان مطلوبًا منع مهاجم يغيّر MAC أيضًا، فستحتاجون لاحقًا إلى ربط الهوية بطريقة أقوى مثل NAC/802.1X أو سجل أجهزة موثوق.


## Live Mininet IoT telemetry and dashboard API

The interactive 38-host demo can run the real Flask Web/API on `h2:5000`, persist simulator readings in a shared SQLite database, and expose authenticated reads through the Ryu runtime API on loopback port `8080`. It is separate from the dataset batch collector. The Network API requires a bearer token on operational routes and uses exact-origin opt-in CORS; never expose it through a public tunnel without authentication.

See [the end-to-end integration guide](docs/SECUREIOT_NETWORK_API_INTEGRATION_GUIDE.md) for startup steps and security requirements. In the Mininet CLI, run `iot_test` to send a probe from `h5` through `h2` and verify it via Ryu. Run `python3 -m unittest -v tests/test_iot_telemetry_store.py tests/test_iot_simulator_auth.py tests/test_topology_inventory.py` for the storage tests and `API_TOKEN=... BASE_URL=... ./test_network_api.sh` for the read-only API contract checks.
