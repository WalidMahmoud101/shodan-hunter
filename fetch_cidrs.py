#!/usr/bin/env python3
"""
CIDR Fetcher — يسحب IPv4 prefixes لكل ASN من RIPEstat API
Input:  all_asns_combined.txt
Output: all_cidrs.txt
"""

import sys
import time
import urllib.request
import json
from pathlib import Path
from datetime import datetime

INPUT_FILE  = Path("all_asns_combined.txt")
OUTPUT_FILE = Path("all_cidrs.txt")
FAILED_FILE = Path("failed_asns.txt")
SLEEP       = 0.3   # ثانية بين كل request
MAX_RETRIES = 3

def utcnow():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def get_prefixes(asn: str) -> list:
    """جيب IPv4 prefixes من RIPEstat"""
    asn_clean = asn.strip().split("#")[0].strip().replace("AS","").strip()
    url       = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req  = urllib.request.Request(
                url,
                headers={"User-Agent": "CIDR-Fetcher/1.0"}
            )
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())

            prefixes = []
            for p in data.get("data", {}).get("prefixes", []):
                prefix = p.get("prefix","")
                if prefix and ":" not in prefix:  # IPv4 فقط
                    prefixes.append(prefix)
            return prefixes

        except Exception as e:
            if attempt < MAX_RETRIES:
                time.sleep(2)
            else:
                return None  # فشل

    return None

def main():
    if not INPUT_FILE.exists():
        print(f"[!] File not found: {INPUT_FILE}")
        sys.exit(1)

    # قرا الـ ASNs
    asns = []
    for line in INPUT_FILE.read_text().splitlines():
        line = line.split("#")[0].strip()
        if line.startswith("AS"):
            asns.append(line.split()[0])

    total    = len(asns)
    print(f"[+] ASNs loaded : {total:,}")
    print(f"[+] Output      : {OUTPUT_FILE}")
    print(f"[+] Started     : {utcnow()}")
    print(f"[+] Estimated   : ~{total * SLEEP / 60:.0f} minutes\n")

    done         = 0
    total_cidrs  = 0
    failed       = []

    out_f    = open(OUTPUT_FILE, "w")
    failed_f = open(FAILED_FILE, "w")

    out_f.write(f"# CIDRs generated at {utcnow()}\n")
    out_f.write(f"# Total ASNs: {total}\n\n")

    for i, asn in enumerate(asns, 1):
        prefixes = get_prefixes(asn)

        if prefixes is None:
            failed.append(asn)
            failed_f.write(asn + "\n")
            failed_f.flush()
            print(f"  [{i:,}/{total:,}] {asn:<12} FAILED", end="\r")
            time.sleep(SLEEP)
            continue

        if prefixes:
            out_f.write(f"# {asn}\n")
            for p in prefixes:
                out_f.write(p + "\n")
                total_cidrs += 1
            out_f.flush()

        done += 1

        # Progress كل 100
        if i % 100 == 0 or i == total:
            pct = i / total * 100
            print(f"  [{i:,}/{total:,}] {pct:.1f}% — "
                  f"CIDRs: {total_cidrs:,} — "
                  f"Failed: {len(failed)} — "
                  f"{asn:<12}      ")

        time.sleep(SLEEP)

    out_f.close()
    failed_f.close()

    print(f"\n{'='*55}")
    print(f"  DONE!")
    print(f"  ASNs processed : {done:,}/{total:,}")
    print(f"  Total CIDRs    : {total_cidrs:,}")
    print(f"  Failed ASNs    : {len(failed)}")
    print(f"  Output         : {OUTPUT_FILE}")
    if failed:
        print(f"  Failed file    : {FAILED_FILE}")
        print(f"  Re-run failed  : python3 fetch_cidrs.py --retry")
    print(f"{'='*55}")

if __name__ == "__main__":
    # لو --retry — اشتغل على الـ failed فقط
    if "--retry" in sys.argv:
        if FAILED_FILE.exists():
            INPUT_FILE = FAILED_FILE
            OUTPUT_FILE = Path("all_cidrs_retry.txt")
            print(f"[+] Retry mode — reading from {FAILED_FILE}")
        else:
            print(f"[!] No failed file found")
            sys.exit(1)
    main()
