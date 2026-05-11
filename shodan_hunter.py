#!/usr/bin/env python3
"""
Shodan Hunter v1.0
Port / ASN / CVE / Company Search
Streaming Save + Checkpoint/Resume + Retry

Requirements:
  pip install shodan

Usage:
  python3 shodan_hunter.py -k YOUR_KEY --use-strategies
  python3 shodan_hunter.py -k YOUR_KEY --asn AS16509 --port 2087
  python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087
  python3 shodan_hunter.py -k YOUR_KEY --company "Hetzner Online" --port 2087
  python3 shodan_hunter.py -k YOUR_KEY --company-file companies.txt --port 2087
  python3 shodan_hunter.py -k YOUR_KEY --cve CVE-2023-29298
  python3 shodan_hunter.py -k YOUR_KEY --query 'asn:AS16509 port:2087'
  python3 shodan_hunter.py -k YOUR_KEY --asn-file asns.txt --port 2087 --test
"""

import argparse
import csv
import json
import sys
import time
import signal
from datetime import datetime, timezone
from pathlib import Path

try:
    import shodan
except ImportError:
    print("[!] Run: pip install shodan")
    sys.exit(1)

OUTPUT_ROOT     = Path("shodan_results")
CHECKPOINT_FILE = Path("shodan_checkpoint.json")
SAVE_EVERY      = 50
MAX_RETRIES     = 5
RETRY_WAIT      = 10
SLEEP_BETWEEN   = 1.0
PAGE_SIZE       = 100

STRATEGIES = {
    "port_2087": [
        "port:2087",
        "port:2087 product:cPanel",
        'port:2087 http.title:"WHM"',
        'port:2087 http.title:"WebHost Manager"',
        'port:2087 http.title:"cPanel"',
        "port:2087 http.component:cPanel",
        "port:2087 vuln:*",
        "port:2087 os:Linux",
        "port:2087 http.status:200",
        "port:2087 http.status:401",
        "port:2087 http.status:403",
        "port:2087 ssl:*",
    ],
    "port_2083": [
        "port:2083",
        "port:2083 product:cPanel",
        'port:2083 http.title:"cPanel"',
        "port:2083 http.component:cPanel",
        "port:2083 vuln:*",
        "port:2083 os:Linux",
        "port:2083 http.status:200",
        "port:2083 http.status:401",
        "port:2083 ssl:*",
    ],
}

def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def sanitize(s):
    for ch in [':', ' ', '/', '\\', '*', '?', '"', '<', '>', "'", '(', ')', '+']:
        s = s.replace(ch, '_')
    return s[:60].strip('_')

def sep(title=""):
    print(f"\n{'='*60}")
    if title:
        print(f"  >> {title}")
        print(f"{'='*60}")

def print_banner():
    print("""
  ███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗
  ██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗  ██║
  ███████╗███████║██║   ██║██║  ██║███████║██╔██╗ ██║
  ╚════██║██╔══██║██║   ██║██║  ██║██╔══██║██║╚██╗██║
  ███████║██║  ██║╚██████╔╝██████╔╝██║  ██║██║ ╚████║
  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
     Hunter v1.0 - Streaming Save - Checkpoint
    """)

def create_session_dir(label=""):
    ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    tag = f"_{sanitize(label)}" if label else ""
    d   = OUTPUT_ROOT / f"session_{ts}{tag}"
    d.mkdir(parents=True, exist_ok=True)
    return d

def is_network_error(e):
    s = str(e).lower()
    return any(x in s for x in ["timeout","connection","resolve","network","timed out","reset"])

CSV_FIELDS = [
    "ip","port","protocol","org","asn","country","city",
    "isp","hostnames","cves","product","version","os",
    "http_title","http_status","banner","source"
]

def item_to_row(item):
    cves = list(item.get("vulns", {}).keys()) if item.get("vulns") else []
    return {
        "ip":          item.get("ip_str",""),
        "port":        item.get("port",""),
        "protocol":    item.get("transport",""),
        "org":         item.get("org",""),
        "asn":         item.get("asn",""),
        "country":     item.get("location",{}).get("country_code",""),
        "city":        item.get("location",{}).get("city",""),
        "isp":         item.get("isp",""),
        "hostnames":   ", ".join(item.get("hostnames",[])),
        "cves":        ", ".join(cves),
        "product":     item.get("product",""),
        "version":     item.get("version",""),
        "os":          item.get("os",""),
        "http_title":  item.get("http",{}).get("title","") if item.get("http") else "",
        "http_status": item.get("http",{}).get("status","") if item.get("http") else "",
        "banner":      str(item.get("data",""))[:300].replace("\n"," "),
        "source":      item.get("_source",""),
    }

class StreamWriter:
    def __init__(self, session_dir, name):
        self.name     = sanitize(name)
        self.base     = session_dir / self.name
        self.count    = 0
        self.seen_ips = set()
        self._buf     = []
        self._cf      = open(f"{self.base}.csv","w",newline="",encoding="utf-8")
        self._cw      = csv.DictWriter(self._cf, fieldnames=CSV_FIELDS, extrasaction="ignore")
        self._cw.writeheader()
        self._cf.flush()
        self._ipf     = open(f"{self.base}_ips.txt","w",encoding="utf-8")

    def write(self, item):
        ip  = item.get("ip_str","")
        self._cw.writerow(item_to_row(item))
        if ip and ip not in self.seen_ips:
            self.seen_ips.add(ip)
            self._ipf.write(ip + "\n")
            self._ipf.flush()
        self._buf.append(item)
        self.count += 1
        if self.count % SAVE_EVERY == 0:
            self._cf.flush()
            self._save_json()
            print(f"    [*] {self.count:,} records on disk ...", end="\r", flush=True)

    def _save_json(self):
        with open(f"{self.base}.json","w",encoding="utf-8") as f:
            json.dump(self._buf, f, indent=2, default=str)

    def close(self):
        self._cf.flush(); self._cf.close()
        self._ipf.flush(); self._ipf.close()
        self._save_json()
        print(f"\n    [+] {self.name}: {self.count:,} records | {len(self.seen_ips):,} unique IPs")

class MasterWriter(StreamWriter):
    def __init__(self, session_dir):
        self.name     = "all_results"
        self.base     = session_dir / "all_results"
        self.count    = 0
        self.seen_ips = set()
        self._buf     = []
        self._cf      = open(session_dir / "all_results.csv","w",newline="",encoding="utf-8")
        self._cw      = csv.DictWriter(self._cf, fieldnames=CSV_FIELDS, extrasaction="ignore")
        self._cw.writeheader()
        self._cf.flush()
        self._ipf     = open(session_dir / "ips_only.txt","w",encoding="utf-8")

    def close(self):
        self._cf.flush(); self._cf.close()
        self._ipf.flush(); self._ipf.close()
        self._save_json()
        print(f"\n[+] MASTER: {self.count:,} total | {len(self.seen_ips):,} unique IPs")

class Checkpoint:
    def __init__(self, path=CHECKPOINT_FILE):
        self.path = Path(path)
        self.data = {
            "version":"1.0","started_at":utcnow(),"last_updated":utcnow(),
            "session_dir":"","completed_queries":[],"seen_keys":[],
            "total_records":0,"status":"running",
        }

    def load(self):
        if not self.path.exists(): return False
        try:
            saved = json.loads(self.path.read_text())
            if saved.get("status") == "done": return False
            self.data = saved
            print(f"\n{'='*60}")
            print(f"  RESUME - session incomplete!")
            print(f"  Started : {self.data.get('started_at','?')}")
            print(f"  Done    : {len(self.data['completed_queries'])} queries")
            print(f"  Records : {self.data['total_records']:,}")
            print(f"{'='*60}\n")
            return True
        except Exception as e:
            print(f"[!] Checkpoint error: {e}")
            return False

    def save(self):
        self.data["last_updated"] = utcnow()
        self.path.write_text(json.dumps(self.data, indent=2, default=str))

    def mark_done(self):
        self.data["status"] = "done"
        self.save()

    def mark_query_complete(self, query, n=0):
        if query not in self.data["completed_queries"]:
            self.data["completed_queries"].append(query)
        self.data["total_records"] += n
        self.save()

    def is_done(self, query):
        return query in self.data["completed_queries"]

    def set_session_dir(self, p):
        self.data["session_dir"] = str(p)
        self.save()

    def set_seen_keys(self, keys):
        self.data["seen_keys"] = list(keys)
        self.save()

    def get_seen_keys(self):
        return set(self.data.get("seen_keys",[]))

    def clear(self):
        if self.path.exists(): self.path.unlink()

def shodan_count(api, query):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = api.count(query)
            return result.get("total", 0)
        except shodan.APIError as e:
            if "No information available" in str(e): return 0
            if is_network_error(e):
                print(f"    [!] Network ({attempt}/{MAX_RETRIES}) - wait {RETRY_WAIT}s ...")
                time.sleep(RETRY_WAIT)
            else:
                print(f"    [!] Shodan: {e}")
                return -1
    return -1

def stream_search(api, query, label, seen_keys, query_writer, master_writer):
    new_count = 0
    page      = 1
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            while True:
                result  = api.search(query, page=page, limit=PAGE_SIZE)
                matches = result.get("matches", [])
                if not matches: break
                for item in matches:
                    item["_source"] = label
                    ip  = item.get("ip_str","")
                    key = f"{ip}:{item.get('port','')}"
                    if ip and key not in seen_keys:
                        seen_keys.add(key)
                        query_writer.write(item)
                        master_writer.write(item)
                        new_count += 1
                total         = result.get("total", 0)
                fetched       = (page - 1) * PAGE_SIZE + len(matches)
                print(f"    >> Page {page} - {fetched:,}/{total:,} ...", end="\r", flush=True)
                if fetched >= total or len(matches) < PAGE_SIZE: break
                page += 1
                time.sleep(SLEEP_BETWEEN)
            print(f"    >> +{new_count:,} new records saved              ")
            return new_count
        except shodan.APIError as e:
            err = str(e)
            if "No information available" in err or "empty" in err.lower():
                print(f"    >> 0 results")
                return 0
            if is_network_error(e):
                print(f"\n    [!] Network ({attempt}/{MAX_RETRIES}) - wait {RETRY_WAIT}s ...")
                time.sleep(RETRY_WAIT)
                page = 1
            else:
                print(f"\n    [!] Shodan: {e}")
                return new_count
    return new_count

def run_query(api, query, seen_keys, session_dir, master_writer, cp,
              group_writer=None, test_mode=False):
    if cp.is_done(query):
        print(f"  [SKIP] {query[:65]}")
        return 0
    total = shodan_count(api, query)
    print(f"\n  Query     : {query}")
    print(f"  Available : {total:,}" if total >= 0 else "  Available : ?")
    if total == 0:
        cp.mark_query_complete(query, 0)
        return 0
    if test_mode:
        print(f"  [TEST] OK - {total:,} results")
        cp.mark_query_complete(query, 0)
        return total
    q_writer = group_writer or StreamWriter(session_dir, sanitize(query))
    new = stream_search(api, query, query, seen_keys, q_writer, master_writer)
    if group_writer is None: q_writer.close()
    print(f"  Total unique: {len(seen_keys):,}")
    cp.set_seen_keys(seen_keys)
    cp.mark_query_complete(query, new)
    time.sleep(SLEEP_BETWEEN)
    return new

def run_port_group(api, group_name, queries, seen_keys,
                   session_dir, master_writer, cp, test_mode=False):
    sep(f"PORT GROUP: {group_name} ({len(queries)} queries)")
    if test_mode:
        run_query(api, queries[0], seen_keys, session_dir,
                  master_writer, cp, test_mode=True)
        return
    gw = StreamWriter(session_dir, group_name)
    for i, q in enumerate(queries, 1):
        print(f"\n  [{i:02d}/{len(queries):02d}]", end=" ")
        run_query(api, q, seen_keys, session_dir, master_writer, cp, gw)
    gw.close()

def harvest_asn(api, asn, port, seen_keys, session_dir,
                master_writer, cp, test_mode=False):
    asn_clean = str(asn).upper().replace("AS","")
    asn_str   = f"AS{asn_clean}"
    query     = f"asn:{asn_str} port:{port}" if port else f"asn:{asn_str}"
    label     = f"{asn_str}_port{port}" if port else f"{asn_str}_all"
    sep(f"ASN: {asn_str}" + (f"  Port:{port}" if port else "  ALL"))
    print(f"  Query : {query}")
    total = shodan_count(api, query)
    print(f"  Total : {total:,}" if total >= 0 else "  Total : ?")
    if test_mode:
        print(f"  [TEST] OK" if total and total > 0 else "  [TEST] 0 results")
        return
    if not total or total == 0:
        print(f"  -> No results")
        return
    w = StreamWriter(session_dir, label)
    run_query(api, query, seen_keys, session_dir, master_writer, cp, w)
    w.close()

def process_company(api, company, port, seen_keys, session_dir,
                    master_writer, cp, test_mode=False):
    sep(f"COMPANY: {company}")
    query = f'org:"{company}" port:{port}' if port else f'org:"{company}"'
    print(f"  Query : {query}")
    total = shodan_count(api, query)
    print(f"  Total : {total:,}" if total >= 0 else "  Total : ?")
    if test_mode:
        print(f"  [TEST] OK - {total:,}" if total and total > 0 else "  [TEST] try different name")
        return
    if not total or total == 0:
        print(f"  [!] No results")
        return
    w = StreamWriter(session_dir, f"company_{sanitize(company)}")
    run_query(api, query, seen_keys, session_dir, master_writer, cp, w)
    w.close()

def search_cve(api, cve_id, port, seen_keys, session_dir,
               master_writer, cp, test_mode=False):
    cve_upper = cve_id.upper()
    query     = f"vuln:{cve_upper} port:{port}" if port else f"vuln:{cve_upper}"
    sep(f"CVE: {cve_upper}")
    print(f"  Query : {query}")
    total = shodan_count(api, query)
    print(f"  Total : {total:,}" if total >= 0 else "  Total : ?")
    if test_mode:
        print(f"  [TEST] OK" if total and total > 0 else "  [TEST] 0 results")
        return
    if not total or total == 0: return
    w = StreamWriter(session_dir, f"cve_{sanitize(cve_upper)}")
    run_query(api, query, seen_keys, session_dir, master_writer, cp, w)
    w.close()

def print_stats(master, session_dir, cp):
    sep("FINAL SUMMARY")
    print(f"  TOTAL RECORDS  : {master.count:,}")
    print(f"  UNIQUE IPs     : {len(master.seen_ips):,}")
    print(f"  QUERIES DONE   : {len(cp.data['completed_queries'])}")
    print(f"  FINISHED AT    : {utcnow()}")
    print(f"\n  Output: {session_dir.resolve()}")
    print(f"    all_results.json / all_results.csv / ips_only.txt\n")
    cp.mark_done()

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Shodan Hunter v1.0")
    parser.add_argument("-k","--api-key",        required=True)
    parser.add_argument("--use-strategies",      action="store_true",
                        help="شغّل الـ STRATEGIES لـ 2087/2083")
    parser.add_argument("--no-2087",             action="store_true")
    parser.add_argument("--no-2083",             action="store_true")
    parser.add_argument("--ports",               nargs="+", type=int)
    parser.add_argument("--asn",                 nargs="+", metavar="ASN")
    parser.add_argument("--asn-file",            metavar="FILE")
    parser.add_argument("--port",                type=int,
                        help="فلتر بورت مع ASN/Company")
    parser.add_argument("--company",             metavar="NAME")
    parser.add_argument("--company-file",        metavar="FILE")
    parser.add_argument("--cve",                 nargs="+", metavar="CVE_ID")
    parser.add_argument("--query",               help="Raw Shodan query")
    parser.add_argument("--test",                action="store_true")
    parser.add_argument("--reset",               action="store_true")
    args = parser.parse_args()

    cp = Checkpoint()
    if args.reset:
        cp.clear()
        print("[+] Checkpoint cleared")

    resumed = cp.load()

    if resumed and cp.data.get("session_dir"):
        session_dir = Path(cp.data["session_dir"])
        session_dir.mkdir(parents=True, exist_ok=True)
        print(f"[+] Resuming: {session_dir}")
    else:
        session_dir = create_session_dir("test" if args.test else "")
        cp.set_session_dir(session_dir)
        print(f"[+] Session : {session_dir}")

    api = shodan.Shodan(args.api_key)
    try:
        info = api.info()
        print(f"[+] Plan    : {info.get('plan','?')}")
        print(f"[+] Credits : {info.get('query_credits',0):,} query / "
              f"{info.get('scan_credits',0):,} scan")
    except Exception as e:
        print(f"[!] API error: {e}")
        sys.exit(1)

    seen_keys     = cp.get_seen_keys()
    master_writer = MasterWriter(session_dir)

    def graceful_exit(sig, frame):
        print(f"\n\n  Interrupted!")
        try:
            master_writer._cf.flush()
            master_writer._ipf.flush()
        except Exception:
            pass
        cp.set_seen_keys(seen_keys)
        cp.save()
        print(f"  Saved - run again to resume")
        sys.exit(0)

    signal.signal(signal.SIGINT,  graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    asn_list = list(args.asn or [])
    if args.asn_file:
        try:
            for line in Path(args.asn_file).read_text().splitlines():
                line = line.split("#")[0].strip()
                if line: asn_list.append(line)
            print(f"[+] {len(asn_list)} ASNs from {args.asn_file}")
        except FileNotFoundError:
            print(f"[!] ASN file not found: {args.asn_file}")

    companies = []
    if args.company: companies.append(args.company)
    if args.company_file:
        try:
            for line in Path(args.company_file).read_text(encoding="utf-8").splitlines():
                line = line.split("#")[0].strip()
                if line: companies.append(line)
            print(f"[+] {len(companies)} companies from {args.company_file}")
        except FileNotFoundError:
            print(f"[!] Company file not found: {args.company_file}")

    print(f"\n  Mode : {'TEST' if args.test else ('RESUME' if resumed else 'NEW')}")
    print(f"  Save : every {SAVE_EVERY} records")

    # STRATEGIES
    if args.use_strategies:
        if not args.no_2087:
            run_port_group(api, "port_2087", STRATEGIES["port_2087"],
                           seen_keys, session_dir, master_writer, cp, args.test)
        if not args.no_2083:
            run_port_group(api, "port_2083", STRATEGIES["port_2083"],
                           seen_keys, session_dir, master_writer, cp, args.test)
        if args.ports:
            for p in args.ports:
                run_port_group(api, f"port_{p}",
                               [f"port:{p}", f"port:{p} os:Linux", f"port:{p} vuln:*"],
                               seen_keys, session_dir, master_writer, cp, args.test)

    # ASN
    for asn in asn_list:
        harvest_asn(api, asn, args.port, seen_keys,
                    session_dir, master_writer, cp, args.test)

    # COMPANY
    if companies:
        for i, company in enumerate(companies, 1):
            print(f"\n  [Company {i}/{len(companies)}] {company}")
            process_company(api, company, args.port, seen_keys,
                            session_dir, master_writer, cp, args.test)

    # CVE
    if args.cve:
        for cve_id in args.cve:
            search_cve(api, cve_id, args.port, seen_keys,
                       session_dir, master_writer, cp, args.test)

    # CUSTOM
    if args.query:
        sep(f"CUSTOM: {args.query}")
        run_query(api, args.query, seen_keys, session_dir,
                  master_writer, cp, test_mode=args.test)

    master_writer.close()
    if not args.test:
        print_stats(master_writer, session_dir, cp)
    else:
        print(f"\n  TEST done - run without --test to fetch data\n")
        cp.mark_done()

if __name__ == "__main__":
    main()
