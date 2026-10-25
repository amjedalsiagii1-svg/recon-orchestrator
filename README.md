# recon-orchestrator

منصة أمنية متعددة المراحل (7 مراحل) - Termux + Kali Linux

## الحالة
- 7 مراحل مترابطة (P1-P7) ✅
- 69 اختبار ناجح ✅
- 15 CVE مدمجة (dnsmasq, Apache, OpenSSH, Samba…) ✅
- تقارير HTML عربية RTL ✅
- dry-run فقط للاستغلال (لا تنفيذ تلقائي) ✅
- Scope Guard مع CIDR ✅

## التشغيل
  bash run.sh              # جلسة جديدة
  bash run.sh --resume ID  # استئناف جلسة
  bash run.sh --demo       # وضع تجريبي
  bash scripts/smoke_test.sh

## الاختبارات
  python3 -m pytest tests/ -v

## الأمان
- Scope Guard إلزامي (config/scope.txt)
- لا تنفيذ تلقائي للاستغلال
- تأكيد EXPLOIT مطلوب لعرض التفاصيل

## للاستخدام على شبكات مصرّح بها فقط
