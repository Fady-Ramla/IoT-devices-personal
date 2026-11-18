# خطة جمع Packet-In حقيقية بدون Oversampling

## الهدف

بناء Dataset جديدة من `packetin_window` فقط، بدون دمج مع `labeled_traffic_features.csv` وبدون تكرار أو تصنيع صفوف.

الهدف التشغيلي هو جمع **120,000 unique labeled observations**، موزعة بالتساوي:

- Normal: 30,000
- Port_Scan: 30,000
- SYN_Flood: 30,000
- Malicious_POST: 30,000

جمع 120,000 بدل 100,000 يترك مساحة كافية لتقسيم train/validation/test مع holdout مستقل.

## مصدر البيانات

شغّل Ryu باستخدام `mininet/traffic_monitor_merged.py`. يجب أن تكون صفوف Flow الناتجة التي تدخل الـdataset النهائية موسومة:

```text
source=packetin_window
```

لا تدخل صفوف:

```text
source=switch_flow_stats
```

في packet-in path، يتم حساب `syn_count`, `ack_count`, `rst_count`, `fin_count`, `unique_dst_ports`, و`failed_connection_count` من Packet-In windows. هذه ليست قيمًا حقيقية في صفوف `switch_flow_stats` القديمة.

## إعداد Ryu لوضع جمع Packet-In

شغّلي Ryu في بيئة المختبر المعزولة مع تفعيل mirror للـpackets عند source access ingress، حتى تصل packets الحقيقية إلى الـcontroller حتى بعد تركيب forwarding flow. لا تفعّلي هذا الإعداد على شبكة إنتاج:

```bash
SECUREIOT_PACKETIN_COLLECTION_MIRROR=1 \
SECUREIOT_PACKETIN_COLLECTION_HARD_TIMEOUT=30 \
```

يمكن تقييد الـmirror إلى مجموعة hosts محددة باستخدام `SECUREIOT_PACKETIN_COLLECTION_SOURCE_MACS` (قائمة MAC مفصولة بفواصل). عند بدء كل dataset run، يمسح collector قواعد الـforwarding التي يملكها `TopologyMonitor` فقط؛ تحققي من استجابة `/dataset/run/status` أن:

```json
"forwarding_flows_reset": true
```

ابدئي بـpilot صغير، وتحققي أن ملفات الـflow الجديدة تحتوي `source=packetin_window` قبل أي batch كبير. راقبي حمل الـcontroller لأن الـmirror يزيد Packet-In rate.

## قواعد عدم التحيز والتسريب

1. كل تجربة تبدأ بـUUID `run_id` جديد.
2. كل observation يحصل على `observation_id` فريد.
3. لا نستخدم oversampling أو undersampling.
4. لا نكرر أي raw observation.
5. نفس Ryu collector ونفس topology لكل classes.
6. نغيّر المهاجم والهدف والخدمة والمعدل والمدة بين runs.
7. نترك وقتًا فاصلًا بين runs حتى لا تختلط labels.
8. نحتفظ بالـraw CSV والـmanifest ولا نكتب فوقها.
9. split يكون على مستوى `run_id`، وليس على مستوى الصف.
10. الـfinal holdout يكون runs جديدة لم تدخل في اختيار features أو tuning.

## قبول الـrun

لا تُقبل التجربة إلا إذا:

```text
status=completed
source=packetin_window
label_status=matched
run_id موجود وغير فارغ
observation_id موجود وفريد
الـrows أكبر من صفر
```

أي run فاشلة أو ambiguous أو unmatched تظل في تقرير الإخفاقات ولا تدخل التدريب.

## أمثلة أوامر Mininet

الأوامر التالية أمثلة من صيغة `Real_network_topology.py`. يجب تغيير attacker/target/parameters بين runs:

```text
normal h5 http_api h2 20 2
attack h5 port_scan h2 1-1000 100 20
attack h6 syn_flood h2 5000 100 20
attack h7 malicious_post h2 /api/iot/telemetry 100 100 1 20
```

لا تعتبر run مكتملة من command فقط؛ تحقق من `run_manifest.csv` ومن raw packet-in flow file.

## خطة التوزيع

اجمع runs بالتناوب بين الأربع classes بدل تشغيل class واحدة بالكامل أولًا. مثال:

```text
Normal -> Port_Scan -> SYN_Flood -> Malicious_POST
```

ثم كرر مع attacker/target/service/rate/duration مختلفين.

يجب أن نراقب عدد observations، لا عدد runs فقط؛ لأن run واحدة قد تنتج عددًا مختلفًا من windows حسب كثافة traffic.

## أوامر التحقق بعد كل batch

```bash
python3 - <<'PY'
import pandas as pd
from pathlib import Path

files = list(Path('New_Datasets/raw/flow').rglob('*.csv'))
df = pd.concat((pd.read_csv(p) for p in files), ignore_index=True)
assert df['source'].eq('packetin_window').all()
assert df['run_id'].notna().all()
assert df['observation_id'].notna().all()
assert not df['observation_id'].duplicated().any()
print('rows=', len(df))
print('runs=', df['run_id'].nunique())
print(df['label'].value_counts())
PY
```

قبل التدريب، نفّذ quality gate للتأكد من:

```text
duplicate full rows = 0
duplicate observation_id = 0
missing run_id = 0
missing labels = 0
source values = packetin_window only
train/validation/test run overlap = 0
```

## التقسيم المقترح

بعد الوصول إلى 120,000 unique rows، نفّذ grouped split:

```text
Train:      70%
Validation: 15%
Test:       15%
```

ويجب أن يكون لكل class عدد runs في كل split. احتفظ بمجموعة holdout نهائية منفصلة من runs لم تُستخدم في اختيار model أو features.

## ما يرسل إلى AI

الـAI يستقبل features فقط:

```text
protocol
src_port
dst_port
priority
packet_count
byte_count
packet_rate
byte_rate
duration_sec
avg_packet_size
syn_count
ack_count
rst_count
fin_count
syn_ack_ratio
rst_ratio
unique_dst_ports
failed_connection_count
tcp_fraction
udp_fraction
icmp_fraction
source
```

ولا يُرسل إليه:

```text
label
run_id
observation_id
timestamp
src_ip
dst_ip
switch_dpid
MAC addresses
```

الـlabel يستخدم offline فقط للتدريب والتقييم.

## معيار النجاح

لا نعلن accuracy نهائية مرتفعة مسبقًا. نعلن النتيجة فقط بعد:

1. unique observations verified.
2. run-level split verified.
3. final holdout evaluated مرة واحدة.
4. per-class precision/recall/F1 reported.
5. confusion matrix and balanced accuracy reported.

الـaccuracy الحالية `91.25% Macro-F1` تخص dataset القديمة ذات 1,862 row، ولا تُنسب إلى dataset الجديدة قبل انتهاء الجمع والتقييم.
