# Step 3 فقط: active_run.json

تتضمن هذه الحزمة ملفي `mininet/attack_manager.py` و`mininet/traffic_monitor_merged.py` بعد تنفيذ Step 3 على مصدر التشغيل الحالي.

- يظل `attack_manager.get_run_id()` منشئ الـUUID الوحيد.
- بعد إدخال التشغيل في manifest بحالة planned، يكتب attack_manager `New_Datasets/active_run.json` كتابة ذرية بنفس `run_id` و`generation` وبحالة `active` قبل استدعاء Ryu.
- endpoint `/dataset/run` يرفض البدء إن كان الملف مفقودًا أو غير صالح أو غير مطابق.
- قبل حفظ packet/flow observations يتحقق المراقب مجددًا من تطابق الملف وحالة active؛ وعند الفشل يرفض التسجيل fail-closed.
- بعد stop وdrain يبدل orchestrator الحالة ذريًا إلى inactive؛ وإذا فشل lifecycle تصبح failed. تبقى هوية التشغيل وسجل manifest كما هما.
- يدعم الطرفان `SECUREIOT_ACTIVE_RUN_FILE` إذا لزم تحديد مسار موحد، وإلا يستخدمان `New_Datasets/active_run.json` في جذر المشروع.

لم يُنفّذ Step 4 (ملفات CSV المنفصلة)، ولا تعديل `build_dataset.py`، ولا PCAP/mirroring/Online AI.

## تثبيت بعد وجود نسخة احتياطية

تأكد أن نسخة Step 1 الاحتياطية موجودة في المسار الذي أنشأته. نزّل الحزمة إلى Downloads، ثم نفّذ:

```bash
cd ~/IoT-devices
tar -xzf ~/Downloads/person2_step3_active_run.tar.gz -C ~/IoT-devices
```

الأرشيف يحتوي فقط على `mininet/attack_manager.py` و`mininet/traffic_monitor_merged.py`، فيستبدل هذين الملفين فقط. تحقق من syntax بدون الكتابة إلى `__pycache__`:

```bash
cd ~/IoT-devices
python3 - <<'PY'
from pathlib import Path
for name in ("mininet/attack_manager.py", "mininet/traffic_monitor_merged.py"):
    path = Path(name)
    compile(path.read_text(encoding="utf-8"), str(path), "exec")
    print("Syntax OK:", path)
PY
```

لا تشغّل خطة تجارب ولا تبدأ Mininet في هذه المرحلة. بعد نجاح فحص syntax، نختبر حالات active_run (مطابق، مفقود، تالف، غير مطابق) محليًا/بوحدة اختبار، ثم لا ننتقل إلى Step 4 قبل اعتماد Step 3.
