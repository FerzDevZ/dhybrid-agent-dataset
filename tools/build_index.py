#!/usr/bin/env python3
"""Build a fast searchable SQLite database (with FTS5) from the raw JSONL indices.

Tables:
  cves      (id, published, severity, cvss_score, cwe, description, refs, ...)
  cves_fts  FTS5 over (id, description)
  exploits  (exploitdb_id, description, type, platform, cves, file, url, ...)
  writeups  (path, title, repo, size, ext) — every file under data/writeups

Usage:
  python3 build_index.py
"""
import json
import os
import sqlite3

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
IDX = os.path.join(DATA, "indices")
DB_PATH = os.path.join(DATA, "dataset.db")

TEXT_EXTS = {".md", ".txt", ".json", ".py", ".rb", ".sh", ".php", ".yaml",
             ".yml", ".xml", ".html", ".js", ".go", ".rs", ".c", ".java", ".sql"}


def connect():
    if os.path.exists(DB_PATH):
        con = sqlite3.connect(DB_PATH)
        for t in ("cves", "cves_fts", "exploits", "writeups"):
            con.execute(f"DROP TABLE IF EXISTS {t}")
        con.commit()
        con.close()
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("CREATE TABLE cves (id TEXT PRIMARY KEY, published TEXT, "
                "severity TEXT, cvss REAL, cwe TEXT, description TEXT, "
                "refs TEXT, ref_tags TEXT, source TEXT, status TEXT)")
    cur.execute("CREATE VIRTUAL TABLE cves_fts USING fts5(id, description, "
                "tokenize='porter unicode61')")
    cur.execute("CREATE TABLE exploits (id INTEGER PRIMARY KEY, description TEXT, "
                "date TEXT, author TEXT, type TEXT, platform TEXT, port TEXT, "
                "verified INTEGER, cves TEXT, tags TEXT, markdown TEXT, "
                "source TEXT, url TEXT)")
    cur.execute("CREATE TABLE writeups (path TEXT PRIMARY KEY, title TEXT, "
                "repo TEXT, size INTEGER, ext TEXT)")
    cur.execute("CREATE INDEX idx_cves_sev ON cves(severity)")
    cur.execute("CREATE INDEX idx_cves_cwe ON cves(cwe)")
    cur.execute("CREATE INDEX idx_exploits_cves ON exploits(cves)")
    con.commit()
    return con, cur


def restore_hf_tables(con, cur):
    """Re-import HuggingFace-derived tables so rebuilds keep them."""
    hf_dir = os.path.join(DATA, "hf")
    if not os.path.isdir(hf_dir):
        return
    for name in sorted(os.listdir(hf_dir)):
        if not name.endswith("_meta.json"):
            continue
        base = name[: -len("_meta.json")]
        jl = os.path.join(hf_dir, f"{base}.jsonl")
        meta_path = os.path.join(hf_dir, name)
        if not os.path.exists(jl):
            continue
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        table = meta.get("table")
        if not table:
            continue
        cur.execute(f"DROP TABLE IF EXISTS {table}")
        cols = set()
        with open(jl, "r", encoding="utf-8") as fh:
            for line in fh:
                d = json.loads(line)
                cols.update(d.keys())
        if not cols:
            continue
        coldefs = ", ".join(f'"{c}" TEXT' for c in sorted(cols))
        cur.execute(f'CREATE TABLE "{table}" ({coldefs})')
        batch = []

        def ser(v):
            if v is None or isinstance(v, (str, int, float, bool)):
                return v
            return json.dumps(v, ensure_ascii=False)

        with open(jl, "r", encoding="utf-8") as fh:
            for line in fh:
                d = json.loads(line)
                batch.append(tuple(ser(d.get(c)) for c in sorted(cols)))
                if len(batch) >= 5000:
                    cur.executemany(
                        f'INSERT INTO "{table}" VALUES ({",".join("?" * len(cols))})', batch)
                    batch = []
        if batch:
            cur.executemany(
                f'INSERT INTO "{table}" VALUES ({",".join("?" * len(cols))})', batch)
        n = cur.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        print(f"{table}: {n} (HF restored)")


def load_cves(con, cur):
    path = os.path.join(IDX, "cve_index.jsonl")
    if not os.path.exists(path):
        print("cve_index.jsonl not found; run fetch_nvd.py first")
        return 0
    rows = []
    fts = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                c = json.loads(line)
            except Exception:
                continue
            cid = c["id"]
            rows.append((cid, c.get("published"), c.get("severity"),
                         c.get("cvssScore"), c.get("cwe"), c.get("description"),
                         json.dumps(c.get("references", [])),
                         json.dumps(c.get("refTags", [])),
                         c.get("source"), c.get("status")))
            fts.append((cid, c.get("description") or ""))
    cur.executemany("INSERT INTO cves VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
    cur.executemany("INSERT INTO cves_fts(id, description) VALUES (?,?)", fts)
    return len(rows)


def load_exploits(con, cur):
    path = os.path.join(IDX, "exploitdb_index.jsonl")
    if not os.path.exists(path):
        print("exploitdb_index.jsonl not found; run fetch_exploitdb.py first")
        return 0
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except Exception:
                continue
            rows.append((e["id"], e.get("description"), e.get("date"),
                         e.get("author"), e.get("type"), e.get("platform"),
                         e.get("port"), 1 if e.get("verified") else 0,
                         json.dumps(e.get("cves", [])), json.dumps(e.get("tags", [])),
                         e.get("markdown"), e.get("source"), e.get("exploitdb_url")))
    cur.executemany("INSERT INTO exploits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return len(rows)


def load_writeups(con, cur):
    base = os.path.join(DATA, "writeups")
    n = 0
    for root, _dirs, files in os.walk(base):
        repo = os.path.relpath(root, base)
        for f in files:
            if f.startswith(".") or f == "_repos.json":
                continue
            full = os.path.join(root, f)
            ext = os.path.splitext(f)[1].lower()
            if ext not in TEXT_EXTS:
                continue
            title = ""
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if line.startswith("# "):
                            title = line[2:].strip()
                            break
                        if line:
                            title = line[:120]
                            break
                size = os.path.getsize(full)
            except OSError:
                continue
            rel = os.path.relpath(full, BASE)
            cur.execute("INSERT INTO writeups VALUES (?,?,?,?,?)",
                        (rel, title, repo, size, ext))
            n += 1
    return n


def main():
    con, cur = connect()
    n_cve = load_cves(con, cur)
    n_exp = load_exploits(con, cur)
    n_wu = load_writeups(con, cur)
    restore_hf_tables(con, cur)
    con.commit()
    for t in ("cves", "cves_fts", "exploits", "writeups"):
        print(f"{t}: {cur.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]}")
    print(f"db size: {os.path.getsize(DB_PATH) / 1e6:.1f} MB")
    con.close()


if __name__ == "__main__":
    main()
