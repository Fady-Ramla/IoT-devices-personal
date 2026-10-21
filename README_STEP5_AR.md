# Step 5 فقط: تحديث `build_dataset.py`

الحزمة v3 تستبدل `New_Datasets/scripts/build_dataset.py` فقط، وتضيف اختبار قبول `New_Datasets/scripts/test_build_dataset.py`. لا تستبدل مراقب Ryu أو manifest، ولا تشغّل الشبكة.

## سبب تحديث v3

في التقارير الفعلية، ظهر أولًا `invalid_numeric_feature: src_port`، وبعد معالجة المنافذ ظهر `invalid_numeric_feature: icmp_type`. هذه قيم غائبة بصورة مشروعة في بعض أنواع الحزم: لا يوجد منفذ نقل لحزم ليست TCP/UDP، ولا يوجد `icmp_type` لغير ICMP، ولا يوجد `arp_operation` لغير ARP. الإصدار v3 يعامل المنفذ الفارغ أو `*`، وحقلي ICMP/ARP الفارغين، كقيمة صفرية مناسبة لعدم الانطباق. يظل يرفض القيم الرقمية المشوهة، والهوية أو timestamp غير السليم.

## سلوك النسخة

- تقرأ ملفات packet أو flow المنفصلة بالاسم `<run_id>.csv`.
- تتحقق من UUID اسم الملف ووجوده في manifest وحالة التشغيل والتوافق بين `run_type` و`attack_type` و`label`.
- تتحقق من مخطط raw الكامل لكل مستوى، وتطابق `run_id` في كل صف مع اسم الملف.
- ترفض `observation_id` المفقود أو المكرر والطابع الزمني غير الرقمي/غير المحدود والصفوف ذات CSV غير السليم.
- تحافظ على `run_id` و`observation_id` الأصليين؛ لا تولّد معرّفًا بديلًا.
- لا تستنتج label من حركة المرور. Normal في manifest يحمل label فارغًا حسب المخطط الحالي، ويصبح label الناتج `Normal` فقط عندما يكون `run_type=normal` والتصنيف متوافقًا.
- تميز مجلد الإدخال المفقود، والملف المفقود لتشغيل مكتمل، والملف الصفري، والملف الذي يحوي الرأس فقط، والملف غير الصالح. أسبابها تظهر في تقرير JSON.
- تستبدل الناتج ذريًا بدل الإلحاق، كي لا تتكرر الصفوف عند إعادة البناء. إذا لم يوجد صف صالح أو غاب مجلد الإدخال أو الـmanifest، لا تنشئ أو تستبدل ملف dataset السابق.
- تقبل packet وflow كلًا على حدة باستخدام `--level` و`--input-dir`.

## اختبار محلي فقط

بعد فك الحزمة في جذر المشروع، نفّذ:

```bash
cd ~/IoT-devices
python3 -m py_compile New_Datasets/scripts/build_dataset.py New_Datasets/scripts/test_build_dataset.py
python3 New_Datasets/scripts/test_build_dataset.py
```

المتوقع 11 سطر `PASS`. الاختبارات تضع manifest وCSV والنواتج داخل `TemporaryDirectory`، ولا تقرأ أو تكتب CSV الحقيقية للمشروع، ولا تبدأ Ryu أو Mininet.

لا تشغّل Builder على بيانات المشروع قبل مراجعة نتائج الاختبار المحلي معًا. بعد نجاح الاختبارات، نعيد محاولة بناء البيانات الفعلية في مجلد تحقق منفصل، ونراجع التقرير والصفوف المقبولة قبل اعتمادها.
