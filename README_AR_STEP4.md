# Step 4 فقط: ملفات raw مستقلة لكل run

تحتوي هذه الحزمة على تعديل `mininet/traffic_monitor_merged.py` واختبار غير شبكي `test_step4_raw_files.py`. لم يتغير `build_dataset.py`؛ ذلك ضمن Step 5.

الإخراج الافتراضي:

```text
New_Datasets/raw/packet/<run_id>.csv
New_Datasets/raw/flow/<run_id>.csv
```

يحافظ المراقب على حقول packet وflow الحالية، ويضيف في بداية كل صف `run_id` و`observation_id`. معرّفات الملاحظات تُولّد وقت الكتابة وتكون من النوع `..._packet_00000001` أو `..._flow_00000001`، لذلك لا نفترض أن packet observation وflow observation هما الحدث/الصف نفسه. حقل `source` في flow محفوظ.

ينشئ المراقب ملفي كل تشغيل حصريًا قبل إقرار بدء التسجيل، ويكتب الرأس حتى لو لم تصل ملاحظات من نوع معين. عند اكتمال stop/drain يعمل flush/fsync ويغلق ملفي التشغيل. لا يكتب إلى ملفات `packet_features.csv` و`traffic_features.csv` العامة القديمة، ولا يحذفها أو يعدلها. ويحتفظ بسجل حجز التشغيل في `New_Datasets/raw/.dataset_run_ids.jsonl`.

عند بدء Ryu يُفحص كل ملف موجود: اسم الملف، الرأس، تطابق run_id في الصفوف، وعدم تكرار observation_id. كذلك يجب أن تكون مجموعتا IDs في مجلدي packet وflow متطابقتين. عند المخالفة يفشل تهيئة التسجيل بدل إلحاق بيانات غير سليمة.

## التثبيت

تأكد أن نسخة Step 4 الاحتياطية موجودة (المسار الذي أرسلته هو `backups/before_per_run_csv_20261021_211008`). نزّل الحزمة إلى Downloads، ثم من جذر المشروع نفّذ:

```bash
cd ~/IoT-devices
tar -xzf ~/Downloads/person2_step4_per_run_csv.tar.gz -C ~/IoT-devices
```

سيستبدل الأرشيف `mininet/traffic_monitor_merged.py` فقط، ويضيف `test_step4_raw_files.py` وملف التعليمات هذا.

## اختبار قبل Mininet

افحص الصياغة واختبر منطق الكتابة داخل مجلد مؤقت:

```bash
cd ~/IoT-devices
python3 - <<'PY'
from pathlib import Path
path = Path("mininet/traffic_monitor_merged.py")
compile(path.read_text(encoding="utf-8"), str(path), "exec")
print("Syntax OK:", path)
PY
python3 test_step4_raw_files.py
```

المتوقع 6 أسطر `PASS`. الاختبار لا يستورد Ryu، ولا يبدأ Mininet، ولا يكتب في بيانات المشروع؛ كل ملفات CSV التجريبية داخل `TemporaryDirectory`.

لا تبدأ خطة تجارب ولا تمسح CSV القديمة الآن. بعد نجاح الفحوص المحلية نراجع النتيجة ونغلق Step 4 قبل تعديل `build_dataset.py` في Step 5.
