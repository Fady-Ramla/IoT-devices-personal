# New_Datasets

مجلد مستقل لإعادة بناء Packet وFlow datasets من الصفر. لا يعدّل هذا المجلد `traffic_monitor_merged.py` أو كود الـ SDN؛ يقرأ raw outputs ويحوّلها تدريجيًا إلى datasets قابلة للتدريب.

## المبدأ

```text
run registration
→ raw collection
→ extraction
→ labeling
→ quality gate
→ feature engineering
→ grouped split
→ training
```

Packet وFlow يظلان Datasetين منفصلين في الإصدار الأول، لكنهما يشتركان في `run_id` عند صدورهما من نفس التجربة.

## تعريف الهوية

- `run_id`: تجربة جمع مستقلة كاملة، Normal أو Attack.
- `capture_id`: ملف PCAP أو جلسة telemetry مرتبطة بالـ run.
- `observation_id`: صف observation فريد داخل dataset.
- `flow_id`: معرف flow إذا كان المصدر flow-level.

## حالات الـ labeling

- `matched`: تم ربط observation بتجربة ground truth واحدة.
- `unmatched`: لم يوجد تطابق موثوق.
- `ambiguous`: أكثر من تجربة محتملة.

لا تدخل `unmatched` أو `ambiguous` في التدريب تلقائيًا.

## أول خطوة

```bash
cd New_Datasets
python3 scripts/register_run.py \
  --run-id normal_0001 \
  --run-type normal \
  --start-time 2026-10-18T21:30:00+00:00 \
  --end-time 2026-10-18T21:31:00+00:00 \
  --status completed
```

للهجوم:

```bash
python3 scripts/register_run.py \
  --run-id syn_0001 \
  --run-type attack \
  --label SYN_Flood \
  --attack-type SYN_Flood \
  --attacker-ip 10.10.10.5 \
  --target-ip 10.10.20.2 \
  --protocol TCP \
  --dst-port 5000 \
  --start-time 2026-10-18T21:35:00+00:00 \
  --end-time 2026-10-18T21:35:20+00:00 \
  --status completed
```

لا نبدأ collection الكبير قبل نجاح Run واحدة Normal وRun واحدة من كل attack type في التسجيل والـ validation.

## قواعد مهمة

1. لا نضيف labels داخل `traffic_monitor_merged.py`.
2. لا نستخدم `run_id`, IPs, host names, controller decisions أو firewall outcome كـ model features.
3. لا نحول observation غير المطابقة تلقائيًا إلى Normal.
4. الـ train/validation/test split سيكون على مستوى `run_id`، وليس الصفوف.
5. لا نحذف raw files أو نكتب فوق outputs بدون نسخة وإصدار واضح.
