# 🔍 Shodan Hunter v1.0

أداة سحب بيانات من Shodan API — Port Search / ASN / Company / CVE  
بتحفظ الداتا أول بأول على الـ disk وبتكمل من آخر نقطة لو وقفت.

---

## 📦 Installation

```bash
pip install shodan
```

---

## 🔑 API Key

اجيب الـ API key من: [account.shodan.io](https://account.shodan.io)

---

## 🚀 كل الـ Commands

---

### 1️⃣ Port Search — STRATEGIES

بيشغّل queries متعددة على port 2087 و 2083 ويجمع كل النتايج.

```bash
# 2087 + 2083 كاملين
python3 shodan_hunter.py -k YOUR_KEY --use-strategies

# 2087 فقط
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --no-2083

# 2083 فقط
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --no-2087

# بورتات إضافية مع 2087/2083
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --ports 2086 2082 2096

# بورتات إضافية فقط بدون 2087/2083
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --no-2087 --no-2083 --ports 8080 8443
```

---

### 2️⃣ ASN Search — جيب IPs من ASN معين

```bash
# ASN واحد — كل IPs فيه على port 2087
python3 shodan_hunter.py -k YOUR_KEY --asn AS16509 --port 2087

# ASN واحد — كل IPs بدون فلتر بورت
python3 shodan_hunter.py -k YOUR_KEY --asn AS16509

# أكتر من ASN
python3 shodan_hunter.py -k YOUR_KEY --asn AS16509 AS24940 AS14061 --port 2087

# من ملف asns.txt (سطر لكل ASN)
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087

# من ملف بدون فلتر بورت
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt
```

**شكل ملف `asns.txt`:**
```
# Hosting Companies
AS16509   # Amazon AWS
AS24940   # Hetzner
AS16276   # OVH
AS14061   # DigitalOcean
AS26496   # GoDaddy
```

---

### 3️⃣ Company Search — ابحث باسم الشركة

```bash
# شركة واحدة على port 2087
python3 shodan_hunter.py -k YOUR_KEY --company "Hetzner Online" --port 2087

# شركة واحدة بدون فلتر بورت
python3 shodan_hunter.py -k YOUR_KEY --company "Hetzner Online"

# من ملف companies.txt
python3 shodan_hunter.py -k YOUR_KEY --company-file companies.txt --port 2087

# من ملف بدون فلتر بورت
python3 shodan_hunter.py -k YOUR_KEY --company-file companies.txt
```

**شكل ملف `companies.txt`:**
```
# اسم شركة في كل سطر
Hetzner Online
OVH
DigitalOcean
GoDaddy
STC
TE Data
Vodafone Egypt
```

---

### 4️⃣ CVE Search — ابحث عن hosts متأثرة بـ CVE

```bash
# CVE واحد
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298

# CVE مع فلتر بورت
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298 --port 2087

# أكتر من CVE
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298 CVE-2022-27228 CVE-2021-44228

# CVE + ASN
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298 --asn AS16509
```

---

### 5️⃣ Custom Query — أي Shodan query

```bash
# ASN + port
python3 shodan_hunter.py -k YOUR_KEY --query 'asn:AS16509 port:2087'

# Company + port + vuln
python3 shodan_hunter.py -k YOUR_KEY --query 'org:"OVH" port:2087 vuln:*'

# Country filter
python3 shodan_hunter.py -k YOUR_KEY --query 'port:2087 country:EG'
python3 shodan_hunter.py -k YOUR_KEY --query 'port:2087 country:SA'

# Product filter
python3 shodan_hunter.py -k YOUR_KEY --query 'port:2087 product:cPanel'

# Title filter
python3 shodan_hunter.py -k YOUR_KEY --query 'port:2087 http.title:"WHM"'

# CVE على بورت معين
python3 shodan_hunter.py -k YOUR_KEY --query 'vuln:CVE-2023-29298 port:2087'
```

---

### 6️⃣ Test Mode — تأكد إن الـ queries شغالة

بيشغّل query واحدة بس ويطبع عدد النتايج — **مش بيسحب داتا**.

```bash
# تيست ASN
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087 --test

# تيست Company
python3 shodan_hunter.py -k YOUR_KEY --company "Hetzner Online" --port 2087 --test

# تيست STRATEGIES
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --test

# تيست Custom query
python3 shodan_hunter.py -k YOUR_KEY --query 'port:2087 country:EG' --test
```

---

### 7️⃣ Resume — كمّل من آخر نقطة

لو السكريبت وقف (نت / خطأ / Ctrl+C) — شغّله تاني **بنفس الـ command** وهيكمل تلقائي.

```bash
# نفس الـ command — هيشوف الـ checkpoint ويكمل
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087

# لو عايز تبدأ من الأول وتمسح الـ checkpoint
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087 --reset
```

---

### 8️⃣ Combined — أكتر من mode مع بعض

```bash
# ASN + CVE
python3 shodan_hunter.py -k YOUR_KEY \
  --asn-file asns.txt \
  --port 2087 \
  --cve CVE-2023-29298

# STRATEGIES + ASN + CVE
python3 shodan_hunter.py -k YOUR_KEY \
  --use-strategies \
  --asn AS16509 AS24940 \
  --port 2087 \
  --cve CVE-2023-29298

# Company + Custom query
python3 shodan_hunter.py -k YOUR_KEY \
  --company-file companies.txt \
  --port 2087 \
  --query 'port:2087 country:EG'
```

---

## 🏁 Flags Reference

| Flag | Type | Description |
|------|------|-------------|
| `-k`, `--api-key` | `str` *(required)* | Shodan API key |
| `--use-strategies` | flag | شغّل queries متعددة على 2087/2083 |
| `--no-2087` | flag | تخطي port 2087 في الـ strategies |
| `--no-2083` | flag | تخطي port 2083 في الـ strategies |
| `--ports` | `int...` | بورتات إضافية مع الـ strategies |
| `--asn` | `str...` | ASN واحد أو أكتر |
| `--asn-file` | `path` | ملف ASNs (سطر لكل ASN) |
| `--port` | `int` | فلتر بورت مع ASN أو Company |
| `--company` | `str` | اسم شركة واحدة |
| `--company-file` | `path` | ملف أسماء شركات |
| `--cve` | `str...` | CVE ID واحد أو أكتر |
| `--query` | `str` | Raw Shodan query |
| `--test` | flag | تجربة بدون سحب داتا |
| `--reset` | flag | امسح الـ checkpoint وابدأ من الأول |

---

## 📁 Output Structure

كل run بيعمل فولدر بالتاريخ والوقت:

```
shodan_results/
└── session_20260511_143022/
    ├── all_results.json          ← كل الداتا كاملة
    ├── all_results.csv           ← Excel-ready
    ├── ips_only.txt              ← IPs نضيفة واحدة لكل سطر
    ├── port_2087.json            ← نتايج port 2087
    ├── port_2087.csv
    ├── port_2087_ips.txt
    ├── AS16509_port2087.json     ← per-ASN
    ├── AS16509_port2087_ips.txt
    ├── company_Hetzner.json      ← per-company
    └── cve_CVE-2023-29298.json   ← per-CVE
```

**CSV Columns:**
`ip, port, protocol, org, asn, country, city, isp, hostnames, cves, product, version, os, http_title, http_status, banner, source`

---

## ⚙️ How It Works

- **Streaming Save** — بيكتب على الـ disk كل 50 record فوراً
- **Deduplication** — بيشيل التكرار بـ `IP:PORT` key
- **Checkpoint** — بيحفظ آخر query خلصت بعد كل request
- **Resume** — لو وقف بيكمل من نفس النقطة تلقائي
- **Retry** — بيعيد المحاولة 5 مرات عند فشل الشبكة
- **Pagination** — بيجيب كل الـ pages مش أول page بس

---

## 💡 Shodan Query Tips

```bash
# فلتر بالدولة
port:2087 country:EG
port:2087 country:SA
port:2087 country:AE

# فلتر بالـ OS
port:2087 os:Linux
port:2087 os:"CentOS"

# فلتر بالـ product
port:2087 product:cPanel
port:2087 product:Apache

# فلتر بالـ vuln
port:2087 vuln:*                    ← أي CVE
port:2087 vuln:CVE-2023-29298       ← CVE محدد

# فلتر بالـ ISP
port:2087 isp:"Amazon"
port:2087 isp:"Hetzner"

# مجموعة فلاتر
port:2087 country:EG product:cPanel vuln:*
```

---

## ⚠️ Legal Notice

للاستخدام في **authorized security research, OSINT, and penetration testing** فقط على أنظمة تملكها أو عندك إذن صريح باختبارها.

---

## 📜 License

MIT License
