# Shodan Hunter v1.0

نفس منطق Netlas Hunter بس بـ Shodan API — أسرع وأقوى في الـ ASN search.

## Installation

```bash
pip install shodan
```

## All Commands

### Port Search (STRATEGIES)
```bash
# 2087 + 2083 بكل الـ queries
python3 shodan_hunter.py -k YOUR_KEY --use-strategies

# 2087 فقط
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --no-2083

# بورتات إضافية
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --ports 2086 2082
```

### ASN Search
```bash
# ASN واحد مع port
python3 shodan_hunter.py -k YOUR_KEY --asn AS16509 --port 2087

# أكتر من ASN
python3 shodan_hunter.py -k YOUR_KEY --asn AS16509 AS24940 --port 2087

# من ملف
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087

# كل IPs في ASN بدون فلتر بورت
python3 shodan_hunter.py -k YOUR_KEY --asn AS16509
```

### Company Search
```bash
# شركة واحدة
python3 shodan_hunter.py -k YOUR_KEY --company "Hetzner Online" --port 2087

# من ملف
python3 shodan_hunter.py -k YOUR_KEY --company-file companies.txt --port 2087
```

### CVE Search
```bash
# CVE واحد
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298

# مع فلتر بورت
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298 --port 2087

# أكتر من CVE
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298 CVE-2022-27228
```

### Custom Query
```bash
python3 shodan_hunter.py -k YOUR_KEY --query 'asn:AS16509 port:2087'
python3 shodan_hunter.py -k YOUR_KEY --query 'org:"OVH" port:2087 vuln:*'
python3 shodan_hunter.py -k YOUR_KEY --query 'port:2087 country:EG'
python3 shodan_hunter.py -k YOUR_KEY --query 'port:2087 product:cPanel'
```

### Test Mode
```bash
# تحقق إن الـ queries شغالة من غير ما تسحب
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087 --test
```

### Resume
```bash
# لو السكريبت وقف — شغّله تاني وهيكمل تلقائي
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087

# لو عايز تبدأ من الأول
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087 --reset
```

## Output

```
shodan_results/session_*/
├── all_results.json     ← كل الداتا
├── all_results.csv      ← Excel
├── ips_only.txt         ← IPs نضيفة
├── AS16509_port2087.*   ← per-ASN
└── company_Hetzner.*    ← per-company
```

## Flags

| Flag | Description |
|------|-------------|
| `-k` | Shodan API key |
| `--use-strategies` | شغّل queries متعددة على 2087/2083 |
| `--asn` | ASN واحد أو أكتر |
| `--asn-file` | ملف ASNs |
| `--port` | فلتر بورت مع ASN/Company |
| `--company` | اسم شركة |
| `--company-file` | ملف شركات |
| `--cve` | CVE واحد أو أكتر |
| `--query` | Raw Shodan query |
| `--test` | تجربة بدون سحب |
| `--reset` | امسح checkpoint |
