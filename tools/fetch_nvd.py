#!/usr/bin/env python3
"""Fetch full NVD CVE dataset (bulk feeds, JSON 2.0) into pentest-dataset.

Output:
  data/raw/nvd/nvdcve-2.0-<YEAR>.json.gz     raw feeds (kept as-is)
  data/cves/CVE-<YEAR>-<ID>.json             full JSON per CVE
  data/indices/cve_index.jsonl               searchable one-line-per-CVE index

Usage:
  python3 fetch_nvd.py [--years 2002-2026] [--only-download]
"""
import argparse
import gzip
import io
import json
import os
import sys
import time
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE, "data", "raw", "nvd")
CVE_DIR = os.path.join(BASE, "data", "cves")
IDX_DIR = os.path.join(BASE, "data", "indices")
FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"

CURRENT_YEAR = time.localtime().tm_year
YEAR_FILE_CUTOFF = 2002  # feed file 2002 also contains 1999-2002 CVEs


def ensure_dirs():
    for d in (RAW_DIR, CVE_DIR, IDX_DIR):
        os.makedirs(d, exist_ok=True)


def download(url, dest):
    if os.path.exists(dest) and os.path.getsize(dest) > 100_000:
        return False
    req = urllib.request.Request(url, headers={"User-Agent": "pentest-dataset-builder/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
    return True


def parse_feed(path, index_writer, processed, year):
    count = 0
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        processed.add(cve_id)
        out = os.path.join(CVE_DIR, f"{cve_id}.json")
        if os.path.exists(out):
            count += 1
            continue
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(item, fh)
        index_writer.write(json.dumps(extract_index_fields(cve), ensure_ascii=False) + "\n")
        count += 1
    return count


def extract_index_fields(cve):
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cvss = None
    severity = None
    vector = None
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            cvss_data = arr[0].get("cvssData", {})
            cvss = cvss_data.get("baseScore")
            severity = arr[0].get("baseSeverity") or cvss_data.get("baseSeverity")
            vector = cvss_data.get("vectorString")
            break
    cwe = None
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe = val
                break
        if cwe:
            break
    refs = []
    tags = []
    for r in cve.get("references", []) or []:
        refs.append(r.get("url", ""))
        tags.extend(r.get("tags", []) or [])
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "severity": severity,
        "cvssScore": cvss,
        "cvssVector": vector,
        "cwe": cwe,
        "description": desc,
        "references": refs,
        "refTags": list(dict.fromkeys(tags)),
        "source": cve.get("sourceIdentifier"),
        "status": cve.get("vulnStatus"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--years", default=f"2002-{CURRENT_YEAR}", help="e.g. 2023-2026")
    ap.add_argument("--only-download", action="store_true", help="skip per-CVE extraction")
    ap.add_argument("--limit", type=int, default=0, help="stop after N total CVEs (dev)")
    args = ap.parse_args()

    y0, _, y1 = args.years.partition("-")
    years = list(range(max(int(y0), YEAR_FILE_CUTOFF), int(y1) + 1))
    ensure_dirs()

    # 1) download raw feeds
    for year in years:
        dest = os.path.join(RAW_DIR, f"nvdcve-2.0-{year}.json.gz")
        if os.path.exists(dest) and os.path.getsize(dest) > 100_000:
            print(f"[skip] feed {year} already present")
            continue
        url = FEED.format(year=year)
        print(f"[get]  {url}")
        try:
            download(url, dest)
        except Exception as e:
            print(f"[err]  {url}: {e}", file=sys.stderr)
        if args.limit:
            break

    if args.only_download:
        return

    # 2) extract + index
    os.makedirs(IDX_DIR, exist_ok=True)
    idx_path = os.path.join(IDX_DIR, "cve_index.jsonl")
    mode = "a" if os.path.exists(idx_path) else "w"
    processed = set()
    if os.path.exists(idx_path):
        with open(idx_path, "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    processed.add(json.loads(line)["id"])
                except Exception:
                    pass
    total = 0
    with open(idx_path, mode, encoding="utf-8") as idx:
        for year in years:
            path = os.path.join(RAW_DIR, f"nvdcve-2.0-{year}.json.gz")
            if not os.path.exists(path):
                continue
            print(f"[parse] {year}", flush=True)
            n = parse_feed(path, idx, processed, year)
            total += n
            print(f"[ok]   {year}: {n} new CVEs (cumulative {total})", flush=True)
            if args.limit and total >= args.limit:
                break
    print(f"done. index has {os.path.getsize(idx_path) / 1e6:.1f} MB, cves dir has "
          f"{len(os.listdir(CVE_DIR))} files")


if __name__ == "__main__":
    main()
