# حزمة ربط `run_id` وIP/MAC — Person 2 (v4)

## ما الذي تغيّر؟

تحتوي الحزمة على أربعة ملفات لتسجيل دورة كل تجربة وربط الصفوف بها:

- `mininet/traffic_monitor_merged.py`: يضيف عمود `run_id` إلى آخر الأعمدة. ويضيف إلى `traffic_features.csv` الحقلين `src_mac` و`dst_mac`. إذا كانت قاعدة OpenFlow MAC-only، يملأ IP من mapping تعلّمه المراقب من IP/MAC الفعليين في الحزم؛ وإذا لم يتعلم mapping يترك IP فارغًا بدل اختراعه. لا يغيّر قواعد التوجيه. الجهاز يمكن أن يكون لديه IP وMAC معًا، لكن قاعدة السويتش الحالية تطابق MAC فقط. يرفض الترويسات القديمة بدل خلط البيانات، ويتأكد من السويتشات الستة والتصريف النهائي.
- `mininet/attack_manager.py`: ينشئ UUID واحدًا، ويسجّل حالات `planned → running → completed/failed` في manifest، ولا يبدأ أمر الحركة إذا لم يحصل على إقرار مطابق من Ryu. يشغّل تجربة واحدة في كل مرة، ويوقف الدفعة عند الفشل.
- `mininet/Real_network_topology.py`: يربط أوامر `attack` و`normal` بدورة التسجيل والتصريف نفسها. يزيل `--flood` ويقيّد SYN إلى 10–200 حزمة/ثانية و5–20 ثانية. يحتفظ بمدد Normal الموجودة في الخطة حتى 45 ثانية، ويختار اسم الخدمة الاحتياطية الصحيح للمضيف `h8`. أوامر CLI ترجع إلى `mininet>` بعد الانتهاء بدل إغلاق الشبكة، مع بقاء دفعة الجمع متوقفة عند أي فشل.
- `New_Datasets/scripts/register_run.py`: تسجيل/تحديث manifest بقفل وكتابة ذرية؛ manifest الصحيح هو `New_Datasets/experiments/run_manifest.csv`. ملف manifest الناتج قابل للقراءة من المستخدم (0644) حتى عند تشغيل Mininet بصلاحيات root؛ ملف الاسترداد المؤقت يبقى خاصًا (0600).

عقد الاتصال بين المشغّل والمراقب موحّد: `POST /dataset/run` مع `operation=start|stop`، ثم `GET /dataset/run/status`. العنوان ثابت على loopback ولا يوجد fallback إلى شبكة خارجية.

## التحقق الذي أُجري

اجتازت النسخ المدمجة فحوص الصياغة النحوية، و32 اختبارًا offline للـmonitor (بينها اختبار MAC-only بلا IP)، و33 اختبارًا offline للـorchestrator، إضافةً إلى فحوص مدد Normal وأسماء الخدمات وسلوك CLI وصلاحيات الملفات. هذه اختبارات mock محلية فقط؛ لم يتم تشغيل Ryu أو Mininet أو أي حركة فعلية على هذا الإصدار، لذلك لا تعتبر اختبار تكامل حيًا.

## تثبيت آمن على جهازك

لا تستخدم مجلدات الاختبار السابقة لهذا الإصدار، وخصوصًا `New_Datasets/raw/person2_runid_smoke_8X5itW`؛ مجلدها يحتوي صفوف التجربة الأولى وترويسة تدفقات أقدم لا تضم حقلي MAC. اتركها كما هي للمراجعة. أنشئ مجلدًا جديدًا تمامًا للاختبار؛ الكود سيرفض الترويسات القديمة عمدًا بدل خلط البيانات.

بعد تنزيل الإصدار الرابع من الأرشيف إلى `~/Downloads/person2-runid-ip-mac-v4.tar.gz`، نفّذ من طرفية المشروع:

```bash
cd ~/IoT-devices
STAMP=$(date +%Y%m%d_%H%M%S)
BACKUP="$HOME/person2-before-runid-$STAMP.tar.gz"
tar -czf "$BACKUP" \
  mininet/traffic_monitor_merged.py \
  mininet/attack_manager.py \
  mininet/Real_network_topology.py \
  New_Datasets/scripts/register_run.py

tar -xzf "$HOME/Downloads/person2-runid-ip-mac-v4.tar.gz" -C "$HOME/IoT-devices"
```

ثم افحص الصياغة دون كتابة ملفات `__pycache__`:

```bash
cd ~/IoT-devices
python3 - <<'PY'
from pathlib import Path
files = [
    Path('mininet/traffic_monitor_merged.py'),
    Path('mininet/attack_manager.py'),
    Path('mininet/Real_network_topology.py'),
    Path('New_Datasets/scripts/register_run.py'),
]
for path in files:
    compile(path.read_text(encoding='utf-8'), str(path), 'exec')
    print('Syntax OK:', path)
PY
```

## الخطوة التالية: اختبار Ryu فقط، بلا Mininet أو هجوم

أنشئ مجلدًا جديدًا وفارغًا؛ احتفظ بهذا المجلد نفسه لاحقًا إذا أردت استخدامه لمخرجات الجمع:

```bash
cd ~/IoT-devices
PROJECT="$HOME/IoT-devices"
PILOT_DIR=$(mktemp -d "$PROJECT/New_Datasets/raw/person2_runid_smoke_XXXXXX")
echo "مجلد الاختبار الجديد: $PILOT_DIR"
cd "$PILOT_DIR"
PYTHONPATH="$PROJECT:$PROJECT/mininet${PYTHONPATH:+:$PYTHONPATH}" \
  ryu-manager "$PROJECT/topology_monitor.py" \
              "$PROJECT/mininet/traffic_monitor_merged.py"
```

اترك Ryu يعمل قليلًا ثم أوقفه بـ`Ctrl+C`. هذا الاختبار لا يرسل حركة؛ نتوقع ظهور الملفات بالترويسات الجديدة فقط. في طرفية ثانية، استبدل المسار أدناه بالقيمة التي طبعها الأمر السابق:

```bash
PILOT_DIR="$HOME/IoT-devices/New_Datasets/raw/ضع_المجلد_الذي_ظهر_لك"
head -n 1 "$PILOT_DIR/packet_features.csv"
head -n 1 "$PILOT_DIR/traffic_features.csv"
```

يجب أن يكون آخر عمود في كل ترويسة هو `run_id`، وأن يظهر `src_mac,dst_mac` قبل `run_id` في `traffic_features.csv`. في التشغيل الفعلي يُملأ `src_ip,dst_ip` من FlowStats إذا وُجدا، وإلا من mapping تعلمه المراقب من الحزم. أرسل سجل Ryu والترويسات قبل تشغيل Mininet أو أي `attack`/`normal`. **لا تشغّل الخطة الكاملة الآن.**

## ملاحظات سلامة مهمة

- لا تعدّل ملفات CSV القديمة ولا تنقلها إلى مجلد الاختبار الجديد.
- إذا لم يحصل المشغّل على إقرار Ryu، فلن يطلق أمر الهجوم أو الحركة.
- إذا تعذّر التأكد من التصريف النهائي أو انقطع سويتش، يظل التشغيل معلّمًا كفاشل/غير محسوم ويُمنع بدء run آخر. لا تحذف ملفات `*.in_flight.json` أو سجل IDs يدويًا؛ أرسل الخطأ أولًا.
- كل صف CSV يحمل `run_id`، لكن `packet_features.csv` ما زال يعكس حزم PacketIn التي يراها الـcontroller وليس التقاطًا كاملًا لكل الحزم على السلك.
