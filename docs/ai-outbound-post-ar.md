# إرسال packetin_window إلى API خارجي

هذا التغيير يضيف إرسالًا اختياريًا من Ryu لصفوف `packetin_window` فقط. يبقى تسجيل CSV كما هو. الإرسال يتم في عامل خلفي بطابور محدود ومهلة قصيرة حتى لا ينتظر مسار معالجة Ryu رد الشبكة. لا تُقرأ استجابة التصنيف ولا تُنفّذ قرارات أمنية في هذه المرحلة؛ نجاح أي رد HTTP من فئة 2xx يعني أن المستقبل قبل الطلب فقط.

## شكل الطلب

يرسل Ryu طلب `POST` بترميز JSON. قسم `features` يحتوي 22 عمودًا من صف التدفق، بالترتيب نفسه الموجود في ترويسة CSV، من `src_port` إلى `source`. قسم `context` يحمل معلومات التتبع:

```json
{
  "features": {
    "src_port": 51514,
    "dst_port": 5000,
    "protocol": "tcp",
    "priority": 0,
    "packet_count": 3,
    "byte_count": 180,
    "packet_rate": 1.5,
    "byte_rate": 90.0,
    "duration_sec": 2.0,
    "avg_packet_size": 60.0,
    "syn_count": 1,
    "ack_count": 1,
    "rst_count": 0,
    "fin_count": 0,
    "syn_ack_ratio": 1.0,
    "rst_ratio": 0.0,
    "unique_dst_ports": 1,
    "failed_connection_count": 0,
    "tcp_fraction": 1.0,
    "udp_fraction": 0.0,
    "icmp_fraction": 0.0,
    "source": "packetin_window"
  },
  "context": {
    "run_id": "...",
    "observation_id": "..._flow_00000001",
    "timestamp": 1794487197.5,
    "switch_dpid": 4,
    "src_ip": "10.10.10.5",
    "dst_ip": "10.10.20.2",
    "src_mac": "00:00:00:00:00:06",
    "dst_mac": "02:10:00:00:00:01"
  }
}
```

القيم في الطلب مصدرها صف النافذة التي كتبها Ryu. يرسل Ryu المنفذ المعروف كعدد صحيح، ويحوّل المنفذ الفارغ أو المتعدد إلى الرقم `0`؛ وهذا يطابق `New_Datasets/scripts/aggregate_packet_to_flow.py` الذي يعرّف `0` للمنفذ المتعدد أو غير المحدد. يظل CSV كما هو ويترك الخانة فارغة ليحافظ على معنى «غير وحيد/غامض». أما `run_id` و`observation_id` وحقول IP/MAC وDPID فهي للسياق والتتبع، وليست خصائص نموذج.

## اختبار بمستقبل محلي

شغّل المستقبل في طرفية:

```bash
cd ~/IoT-devices
python3 mininet/mock_ai_receiver.py --port 5001
```

يستمع افتراضيًا على `127.0.0.1` فقط، ويطبع كل JSON مستلم ويرد `202` مع `{"received": true}`. لا تعرضه على الإنترنت؛ وظيفته اختبار محلي فقط.

عند تشغيل Ryu، أضف متغير البيئة إلى أمر `sudo env`:

```bash
SECUREIOT_AI_API_URL=http://127.0.0.1:5001/predict
```

على سبيل المثال:

```bash
sudo env \
  PYTHONPATH="$PWD/mininet:$PWD" \
  SECUREIOT_ACTIVE_RUN_FILE="$PILOT_DIR/active_run.json" \
  SECUREIOT_RAW_DATA_ROOT="$PILOT_DIR/raw" \
  SECUREIOT_AI_API_URL=http://127.0.0.1:5001/predict \
  /home/fady/.pyenv/versions/3.8.20/bin/ryu-manager \
  --ofp-tcp-listen-port 6633 --observe-links \
  traffic_monitor_merged topology_monitor
```

بعد تشغيل Mininet وبدء تسجيل تجربة عادية، يرسل Ryu كل صف `packetin_window` عند إغلاق نافذته (كل نحو 10 ثوانٍ) إلى المستقبل. راقب سجل `mock_ai_receiver.py` للتأكد من وصول `features` و`context`، وقارن `observation_id` وMAC مع ملف CSV.

## إعدادات الإرسال

- `SECUREIOT_AI_API_URL`: عنوان استقبال POST. إذا لم يُضبط، يبقى الإرسال معطّلًا.
- `SECUREIOT_AI_API_TOKEN`: اختياري؛ إن وُجد يرسل `Authorization: Bearer ...`. لا تضع السر داخل Git أو سطر أوامر محفوظ في سجل مشترك.
- `SECUREIOT_AI_POST_TIMEOUT`: مهلة الطلب بالثواني؛ الافتراضي 2، والحد الأعلى 10.
- `SECUREIOT_AI_QUEUE_SIZE`: حد الطابور؛ الافتراضي 1000. إذا امتلأ، يسجل Ryu تحذيرًا ويتجاهل الإرسال الزائد بدل تعليق معالجة الشبكة.

لما تصبح API البعيدة جاهزة، غيّر `SECUREIOT_AI_API_URL` إلى عنوان HTTPS العام مع المسار الصحيح. لو تستخدم ngrok، شغّل نفقه على جهاز خدمة الاستقبال، وليس على جهاز Ryu لمجرد إرسال الطلب. تحقق من حماية API قبل إرسال بيانات فعلية.
