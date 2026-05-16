# 🔍 Shodan Hunter Toolkit

A complete toolkit for **port intelligence**, **ASN harvesting**, **CVE hunting**, and **CIDR extraction**.

> Built for security researchers, OSINT analysts, and penetration testers.

---

## 🗂️ Scripts Overview

| Script | Description |
|--------|-------------|
| `shodan_hunter.py` | Hunt IPs via Shodan — Port / ASN / Company / CVE / Custom Query |
| `bgp_hunter.py` | Scrape ASN numbers from bgp.he.net using a real browser |
| `fetch_cidrs.py` | Fetch all IPv4 CIDR ranges for a list of ASNs from RIPEstat |

---

## 📦 Installation

```bash
pip install shodan requests playwright beautifulsoup4
python3 -m playwright install chromium
```

---

## 🔵 shodan_hunter.py

Pulls IP data from Shodan with streaming save, checkpoint/resume, and auto-retry.

### Get your API key
👉 [account.shodan.io](https://account.shodan.io)

---

### Port Search — STRATEGIES mode

Runs multiple queries against ports 2087 and 2083.

```bash
# Full scan — port 2087 + 2083
python3 shodan_hunter.py -k YOUR_KEY --use-strategies

# Port 2087 only
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --no-2083

# Port 2083 only
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --no-2087

# Extra ports on top of 2087/2083
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --ports 2086 2082 2096

# Custom ports only (skip 2087/2083)
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --no-2087 --no-2083 --ports 8080 8443
```

---

### ASN Search

```bash
# Single ASN filtered to port 2087
python3 shodan_hunter.py -k YOUR_KEY --asn AS16509 --port 2087

# Multiple ASNs
python3 shodan_hunter.py -k YOUR_KEY --asn AS16509 AS24940 AS14061 --port 2087

# From a file
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087

# All IPs in ASN — no port filter
python3 shodan_hunter.py -k YOUR_KEY --asn AS16509
```

**`asns.txt` format:**
```
# one ASN per line, comments ignored
AS16509   # Amazon AWS
AS24940   # Hetzner
AS16276   # OVH
AS14061   # DigitalOcean
AS26496   # GoDaddy
```

---

### Company Search

```bash
# Single company on port 2087
python3 shodan_hunter.py -k YOUR_KEY --company "Hetzner Online" --port 2087

# Single company — all ports
python3 shodan_hunter.py -k YOUR_KEY --company "Hetzner Online"

# From a file
python3 shodan_hunter.py -k YOUR_KEY --company-file companies.txt --port 2087
```

**`companies.txt` format:**
```
# one company name per line
Hetzner Online
OVH
DigitalOcean
GoDaddy
STC
TE Data
Vodafone Egypt
```

---

### CVE Search

```bash
# Single CVE
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298

# CVE with port filter
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298 --port 2087

# Multiple CVEs
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298 CVE-2022-27228 CVE-2021-44228

# CVE + ASN filter
python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298 --asn AS16509
```

---

### Custom Query

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

# CVE on specific port
python3 shodan_hunter.py -k YOUR_KEY --query 'vuln:CVE-2023-29298 port:2087'
```

---

### Test Mode — verify queries without downloading

```bash
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087 --test
python3 shodan_hunter.py -k YOUR_KEY --company "Hetzner Online" --port 2087 --test
python3 shodan_hunter.py -k YOUR_KEY --use-strategies --test
python3 shodan_hunter.py -k YOUR_KEY --query 'port:2087 country:EG' --test
```

---

### Resume — continue from last checkpoint

If the script stops (network error, Ctrl+C, crash) — just run the **same command again** and it will continue automatically.

```bash
# Same command — auto-resumes
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087

# Start fresh — wipe checkpoint
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087 --reset
```

---

### Run in background (recommended for large jobs)

```bash
screen -S shodan
python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087

# Detach without stopping
# Ctrl+A then D

# Reattach
screen -r shodan
```

---

### Combined examples

```bash
# ASN file + CVE + strategies all at once
python3 shodan_hunter.py -k YOUR_KEY \
  --use-strategies \
  --asn-file asns.txt \
  --port 2087 \
  --cve CVE-2023-29298

# Company file + custom query
python3 shodan_hunter.py -k YOUR_KEY \
  --company-file companies.txt \
  --port 2087 \
  --query 'port:2087 country:EG'
```

---

### Flags Reference

| Flag | Type | Description |
|------|------|-------------|
| `-k`, `--api-key` | `str` *(required)* | Shodan API key |
| `--use-strategies` | flag | Run multi-query strategies on ports 2087/2083 |
| `--no-2087` | flag | Skip port 2087 in strategies |
| `--no-2083` | flag | Skip port 2083 in strategies |
| `--ports` | `int...` | Additional ports |
| `--asn` | `str...` | One or more ASNs |
| `--asn-file` | `path` | File with ASNs (one per line) |
| `--port` | `int` | Port filter for ASN/Company mode |
| `--company` | `str` | Company name |
| `--company-file` | `path` | File with company names |
| `--cve` | `str...` | CVE ID(s) |
| `--query` | `str` | Raw Shodan query string |
| `--test` | flag | Check queries without downloading |
| `--reset` | flag | Clear checkpoint and start fresh |

---

### Output Structure

```
shodan_results/
└── session_20260511_143022/
    ├── all_results.json          ← full merged data
    ├── all_results.csv           ← Excel-ready
    ├── ips_only.txt              ← clean unique IPs, one per line
    ├── port_2087.json
    ├── port_2087.csv
    ├── port_2087_ips.txt
    ├── AS16509_port2087.json
    ├── AS16509_port2087_ips.txt
    ├── company_Hetzner_Online.*
    └── cve_CVE-2023-29298.*
```

**CSV columns:**
`ip, port, protocol, org, asn, country, city, isp, hostnames, cves, product, version, os, http_title, http_status, banner, source`

---

### How it works

- **Streaming save** — writes every 50 records to disk instantly
- **Deduplication** — tracks `IP:PORT` keys, no duplicates
- **Auto-split** — if results exceed 10,000, splits by country automatically
- **Checkpoint** — saves progress after every query
- **Resume** — picks up exactly where it left off
- **Retry** — retries up to 5 times on network errors

---

## 🟢 bgp_hunter.py

Scrapes ASN numbers from [bgp.he.net](https://bgp.he.net) using a real Chromium browser (bypasses bot detection).

### Requirements

```bash
pip install playwright beautifulsoup4
python3 -m playwright install chromium
```

### Usage

```bash
# Single company
python3 bgp_hunter.py --company "Webafrica FTTH - CPT"

# From a file
python3 bgp_hunter.py --company-file companies.txt

# With IPv4 prefixes
python3 bgp_hunter.py --company "Hetzner" --fetch-prefixes

# Watch the browser
python3 bgp_hunter.py --company "Hetzner" --show-browser

# Single ASN — get its prefixes
python3 bgp_hunter.py --asn AS37087

# Full auto — scrape BGP then feed into Shodan
python3 bgp_hunter.py \
  --company-file companies.txt \
  --netlas-key YOUR_SHODAN_KEY \
  --netlas-port 2087
```

### Combine all session ASNs into one file

```bash
cat bgp_results/session_*/all_asns.txt | grep "^AS" | sort -u > all_asns_combined.txt
```

### Output

```
bgp_results/session_*/
├── all_asns.txt              ← ready for --asn-file
├── CompanyName_asns.txt      ← per-company ASN list
└── CompanyName.json          ← full data
```

### Flags

| Flag | Description |
|------|-------------|
| `--company` | Single company name |
| `--company-file` | File with company names |
| `--asn` | Single ASN to get prefixes |
| `--fetch-prefixes` | Also fetch IPv4 prefixes |
| `--show-browser` | Show browser window |
| `--netlas-key` | Auto-feed ASNs to shodan_hunter |
| `--netlas-port` | Port to filter in Shodan (default: 2087) |

---

## 🌐 fetch_cidrs.py

Fetches all IPv4 CIDR ranges for every ASN in a file using the RIPEstat API.

### Requirements

```bash
pip install requests
```

### Usage

```bash
# Remove proxy if active
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY

# Run
python3 fetch_cidrs.py

# Retry failed ASNs
python3 fetch_cidrs.py --retry

# Run in background
screen -S cidrs
python3 fetch_cidrs.py
# Ctrl+A then D to detach
# screen -r cidrs to reattach
```

### Input — `all_asns_combined.txt`

```
AS16509   # Amazon AWS
AS24940   # Hetzner
AS16276   # OVH
```

Build this file from bgp_hunter output:
```bash
cat bgp_results/session_*/all_asns.txt | grep "^AS" | sort -u > all_asns_combined.txt
```

### Live progress

```
[1,000/45,956] [####----------------] 2.2%  |  ASN: AS1234  |  Got: 8 CIDRs  |  Total CIDRs: 4,521  |  Failed: 3
```

### Output

```
all_cidrs.txt        ← all IPv4 CIDR ranges
failed_asns.txt      ← ASNs that failed — rerun with --retry
```

---

## 🔄 Full Workflow

```bash
# Step 1 — Scrape ASNs from bgp.he.net
python3 bgp_hunter.py --company-file companies.txt

# Step 2 — Merge all ASNs into one file
cat bgp_results/session_*/all_asns.txt | grep "^AS" | sort -u > all_asns_combined.txt

# Step 3 — Fetch CIDR ranges
python3 fetch_cidrs.py

# Step 4 — Hunt IPs on Shodan
python3 shodan_hunter.py -k YOUR_KEY \
  --asn-file all_asns_combined.txt \
  --port 2087
```

---

## 💡 Useful Shodan Queries

```
port:2087 country:EG              # Egypt
port:2087 country:SA              # Saudi Arabia
port:2087 country:AE              # UAE
port:2087 os:Linux                # Linux only
port:2087 product:cPanel          # cPanel product
port:2087 vuln:*                  # any CVE
port:2087 vuln:CVE-2023-29298     # specific CVE
port:2087 isp:"Amazon"            # Amazon hosted
asn:AS16509 port:2087             # Amazon ASN + port
org:"Hetzner" port:2087 vuln:*    # Hetzner with any CVE
```

---

## ⚠️ Legal Notice

This toolkit is intended for **authorized security research, OSINT, and penetration testing on systems you own or have explicit written permission to test**. Unauthorized scanning may violate laws in your jurisdiction. Use responsibly.

---

## 📜 License

MIT License — free to use, modify, and distribute.
