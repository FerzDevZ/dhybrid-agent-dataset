#!/usr/bin/env python3
"""Query interface for the pentest dataset. Machine-readable (JSON) by default.

Examples:
  python3 query.py --cve CVE-2024-3400
  python3 query.py --search "apache httpd rce" --severity critical --limit 10
  python3 query.py --search "wordpress" --top-k 10
  python3 query.py --cve CVE-2021-44228 --with-exploits
  python3 query.py --product "nginx" --cwe CWE-78 --since 2023
  python3 query.py --writeups "lateral movement"
  python3 query.py --stats
  python3 query.py --serve  (temporary: just prints usage; use --json)
"""
import argparse
import json
import os
import sqlite3
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(BASE, "data", "dataset.db")


def get_conn():
    if not os.path.exists(DB):
        sys.exit(f"[err] DB not found: {DB}. Run: python3 tools/build_index.py")
    return sqlite3.connect(DB)


def fmt(rows, cols, out=sys.stdout):
    for r in rows:
        out.write(json.dumps(dict(zip(cols, r)), ensure_ascii=False) + "\n")


def cmd_cve(cur, args):
    cve_id = args.cve.upper()
    rows = cur.execute(
        "SELECT id,published,severity,cvss,cwe,description,refs,ref_tags,source,status "
        "FROM cves WHERE id=?", (cve_id,)).fetchall()
    if not rows:
        print(json.dumps({"error": f"{cve_id} not in dataset"}))
        return
    cols = ["id", "published", "severity", "cvss", "cwe", "description",
            "references", "refTags", "source", "status"]
    for r in rows:
        d = dict(zip(cols, r))
        d["references"] = json.loads(d["references"]) if d["references"] else []
        d["refTags"] = json.loads(d["refTags"]) if d["refTags"] else []
        print(json.dumps(d, ensure_ascii=False))
    if args.with_exploits:
        ex = cur.execute(
            "SELECT id,description,type,platform,markdown,url FROM exploits "
            "WHERE cves LIKE ?", (f"%{cve_id}%",)).fetchall()
        if ex:
            print(json.dumps({"exploits": [{
                "exploitdb_id": r[0], "description": r[1], "type": r[2],
                "platform": r[3], "markdown": r[4], "url": r[5]} for r in ex]},
                ensure_ascii=False))


def cmd_search(cur, args):
    q = args.search
    if len(q) < 2:
        sys.exit("[err] --search needs >= 2 chars")
    sql = ("SELECT c.id,c.published,c.severity,c.cvss,c.cwe,c.description "
           "FROM cves_fts f JOIN cves c ON f.id = c.id")
    conds = ["cves_fts MATCH ?"]
    params = [q]
    if args.severity:
        sev = [s.strip().upper() for s in args.severity.split(",")]
        conds.append("c.severity IN (" + ",".join("?" * len(sev)) + ")")
        params += sev
    if args.cwe:
        cwes = [c.strip().upper() for c in args.cwe.split(",")]
        conds.append("(" + " OR ".join("c.cwe LIKE ?" for _ in cwes) + ")")
        params += [f"%{c}%" for c in cwes]
    if args.since:
        conds.append("substr(c.published,1,4) >= ?")
        params.append(str(args.since))
    if args.min_cvss:
        conds.append("c.cvss >= ?")
        params.append(float(args.min_cvss))
    sql += " WHERE " + " AND ".join(conds)
    sql += f" ORDER BY c.cvss DESC NULLS LAST LIMIT {args.limit}"
    try:
        rows = cur.execute(sql, params).fetchall()
    except sqlite3.OperationalError as e:
        sys.exit(f"[err] FTS query failed (quote the term as a phrase if needed): {e}")
    fmt(rows, ["id", "published", "severity", "cvss", "cwe", "description"])
    print(f"# total: {len(rows)}", file=sys.stderr)


def cmd_product(cur, args):
    sql = ("SELECT id,published,severity,cvss,cwe,description FROM cves "
           "WHERE lower(description) LIKE ?")
    params = [f"%{args.product.lower()}%"]
    if args.since:
        sql += " AND substr(published,1,4) >= ?"
        params.append(str(args.since))
    if args.severity:
        sev = [s.strip().upper() for s in args.severity.split(",")]
        sql += " AND severity IN (" + ",".join("?" * len(sev)) + ")"
        params += sev
    sql += f" ORDER BY cvss DESC NULLS LAST LIMIT {args.limit}"
    rows = cur.execute(sql, params).fetchall()
    fmt(rows, ["id", "published", "severity", "cvss", "cwe", "description"])


def cmd_writeups(cur, args):
    q = args.writeups.lower()
    rows = []
    for r in cur.execute("SELECT path,title,repo,size FROM writeups"):
        if q in r[1].lower() or q in r[0].lower() or q in r[2].lower():
            rows.append(r)
    rows = rows[: args.limit]
    fmt(rows, ["path", "title", "repo", "size"])
    print(f"# total: {len(rows)}", file=sys.stderr)


def cmd_exploits(cur, args):
    sql = "SELECT id,description,type,platform,cves,markdown,url FROM exploits"
    params = []
    if args.exploits:
        sql += " WHERE lower(description) LIKE ?"
        params.append(f"%{args.exploits.lower()}%")
    if args.platform:
        sql += " AND lower(platform) LIKE ?"
        params.append(f"%{args.platform.lower()}%")
    if args.limit:
        sql += f" LIMIT {args.limit}"
    rows = cur.execute(sql, params).fetchall()
    fmt(rows, ["id", "description", "type", "platform", "cves", "markdown", "url"])


def cmd_stats(cur):
    stats = {
        "cves": cur.execute("SELECT COUNT(*) FROM cves").fetchone()[0],
        "by_severity": dict(cur.execute(
            "SELECT severity, COUNT(*) FROM cves GROUP BY severity").fetchall()),
        "exploits": cur.execute("SELECT COUNT(*) FROM exploits").fetchone()[0],
        "writeups_files": cur.execute("SELECT COUNT(*) FROM writeups").fetchone()[0],
        "top_cwe": cur.execute(
            "SELECT cwe, COUNT(*) n FROM cves WHERE cwe IS NOT NULL "
            "GROUP BY cwe ORDER BY n DESC LIMIT 10").fetchall(),
        "top_products": cur.execute(
            "SELECT substr(description,1,60) FROM cves ORDER BY cvss DESC NULLS LAST "
            "LIMIT 5").fetchall(),
        "hf_tables": [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'hf_%'")],
    }
    print(json.dumps(stats, ensure_ascii=False, indent=2))


def cmd_hf(cur, args):
    q = args.hf.lower()
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'hf_%'")]
    found = 0
    for t in tables:
        cols = [r[1] for r in cur.execute(f'PRAGMA table_info("{t}")')]
        text_cols = [c for c in cols if c in ("id", "title", "description", "commit_message")]
        if not text_cols:
            text_cols = cols[:3]
        cond = " OR ".join(f'lower("{c}") LIKE ?' for c in text_cols)
        rows = cur.execute(
            f'SELECT "{text_cols[0]}", "{text_cols[1] if len(text_cols) > 1 else text_cols[0]}" '
            f'FROM "{t}" WHERE {cond} LIMIT ?',
            ([f"%{q}%"] * len(text_cols) + [args.limit])).fetchall()
        if rows:
            print(f"# {t}: {len(rows)}")
            for r in rows:
                print(json.dumps({text_cols[0]: r[0],
                                  text_cols[1] if len(text_cols) > 1 else text_cols[0]: r[1]},
                                 ensure_ascii=False))
            found += len(rows)
    print(f"# total: {found}", file=sys.stderr)


def cmd_patches(cur, args):
    q = args.patches.lower()
    rows = cur.execute(
        "SELECT id, title, patches, cwe FROM hf_vuln_patches "
        "WHERE lower(id) LIKE ? OR lower(coalesce(title,'')) LIKE ? "
        "OR lower(coalesce(patches,'')) LIKE ? OR lower(coalesce(cwe,'')) LIKE ? "
        "LIMIT ?",
        ([f"%{q}%"] * 4 + [args.limit])).fetchall()
    cols = ["id", "title", "patches", "cwe"]
    for r in rows:
        d = dict(zip(cols, r))
        if d["patches"]:
            try:
                d["patches"] = json.loads(d["patches"])
            except Exception:
                pass
        if d["cwe"]:
            try:
                d["cwe"] = json.loads(d["cwe"])
            except Exception:
                pass
        print(json.dumps(d, ensure_ascii=False))
    print(f"# total: {len(rows)}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cve", help="exact CVE id")
    ap.add_argument("--with-exploits", action="store_true", help="attach exploit-db rows to --cve")
    ap.add_argument("--search", help="full-text search over CVE descriptions")
    ap.add_argument("--product", help="substring search on CVE descriptions (e.g. nginx)")
    ap.add_argument("--writeups", help="search writeup repo files by keyword")
    ap.add_argument("--exploits", help="search exploit-db by keyword")
    ap.add_argument("--platform", default="", help="filter exploits by platform")
    ap.add_argument("--severity", default="", help="comma list: CRITICAL,HIGH,...")
    ap.add_argument("--cwe", default="", help="comma list: CWE-78,CWE-89")
    ap.add_argument("--since", type=int, default=0, help="published year >= N")
    ap.add_argument("--min-cvss", type=float, default=0.0)
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--hf", help="search HuggingFace-enriched tables (CIRCL etc.)")
    ap.add_argument("--patches", help="search patch-diff table by id/commit keyword")
    args = ap.parse_args()

    if not any([args.cve, args.search, args.product, args.writeups, args.exploits,
                args.stats, args.hf, args.patches]):
        ap.print_help()
        sys.exit(2)

    con = get_conn()
    cur = con.cursor()
    if args.stats:
        cmd_stats(cur)
    elif args.cve:
        cmd_cve(cur, args)
    elif args.search:
        cmd_search(cur, args)
    elif args.product:
        cmd_product(cur, args)
    elif args.writeups:
        cmd_writeups(cur, args)
    elif args.exploits:
        cmd_exploits(cur, args)
    elif args.hf:
        cmd_hf(cur, args)
    elif args.patches:
        cmd_patches(cur, args)
    con.close()


if __name__ == "__main__":
    main()
