# ◈ Phantom Recon

أداة استطلاع شبكي متكاملة — تجمع كل المعلومات عن هدف في مكان واحد.

## 🚀 التشغيل

```bash
pip install -r requirements.txt
python3 main.py
```

## 🔍 الوحدات

| الوحدة | الوصف |
|---|---|
| **🌐 DNS** | سجلات DNS كاملة + Zone Transfer + Wildcard |
| **🚪 PORT** | فحص المنافذ + Service Detection + Banner Grabbing |
| **📋 WHOIS** | معلومات التسجيل + تواريخ الانتهاء |
| **🔒 SSL** | تحليل الشهادات + Cipher Suites + HSTS |
| **🕸 WEB** | كشف التقنيات + CMS + Headers + Forms + APIs |
| **📍 GEO** | IP Geolocation + ASN + Shared Hosting |
| **🔍 SUB** | Subdomains (Brute Force + CT Logs + Passive) |

## ⚡ المميزات

- **Real-time Results** — النتائج تظهر فورياً
- **Severity Coloring** — تلوين حسب الخطورة (Info → Critical)
- **Multi-threading** — فحص متوازي وسريع
- **Session Storage** — حفظ النتائج في SQLite
- **Export** — تصدير JSON/TXT
- **Google Dorks** — 20 Dork تلقائي
- **Port Profiles** — Common / Top1000 / Full

## 📊 الواجهة

```
┌─────────────────────────────────────────────┐
│  Target Input  │  Scan Profile  │  Modules  │
├─────────────────────────────────────────────┤
│  Progress Bars (7 modules in real-time)    │
├─────────────────────────────────────────────┤
│  Findings Table with Severity Dots         │
│  ●  [TIME]  [CATEGORY]  [KEY]  [VALUE]     │
└─────────────────────────────────────────────┘
```

## 🎯 الاستخدام

1. أدخل الهدف (Domain أو IP)
2. اختر Scan Profile (Quick/Deep/Stealth)
3. فعّل/عطّل الوحدات حسب الحاجة
4. اضغط "بدء المسح"
5. شاهد النتائج فورياً

## 💾 البيانات

تُحفظ في: `~/.phantom_recon/scans.db`

## 📦 المتطلبات

- Python 3.8+
- PyQt6
- dnspython, python-whois, requests, beautifulsoup4
- Linux / macOS / Windows
