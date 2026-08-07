#!/usr/bin/env python3
"""Fetch HuggingFace datasets into pentest-dataset via the Dataset Viewer API.

Two modes:
  parquet  (default) — download parquet shards (fast, whole dataset)
  rows     — paginate /rows (100/batch; only for small datasets)

Output:
  data/hf/<safe-name>.jsonl          one JSON object per row
  data/hf/<safe-name>_meta.json      provenance metadata
  dataset.db table <table>           SQLite table (name derived or --table)

Usage:
  python3 fetch_hf.py --dataset CIRCL/vulnerability-scores
  python3 fetch_hf.py --dataset CIRCL/vulnerability-cwe-patch --table hf_vuln_patches
  python3 fetch_hf.py --dataset X --mode rows
"""
import argparse
import json
import os
import sqlite3
import urllib.parse
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HF_DIR = os.path.join(BASE, "data", "hf")
DB = os.path.join(BASE, "data", "dataset.db")

VIEWER = "https://datasets-server.huggingface.co"


def get(url, timeout=180):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def safe_name(name):
    return name.replace("/", "__")


def fetch_parquet(dataset, out_jsonl):
    data = json.loads(get(f"{VIEWER}/parquet?dataset={urllib.parse.quote(dataset)}"))
    urls = [f["url"] for f in data.get("parquet_files", [])]
    if not urls:
        raise SystemExit("[err] no parquet files")
    import pyarrow.parquet as pq
    import tempfile
    n = 0
    with open(out_jsonl, "w", encoding="utf-8") as fh:
        for u in urls:
            print(f"[parquet] {u.split('/')[-1]}", flush=True)
            raw = get(u, timeout=600)
            with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as tf:
                tf.write(raw)
                tpath = tf.name
            try:
                tbl = pq.read_table(tpath)
            finally:
                os.unlink(tpath)
            cols = tbl.column_names
            for batch in tbl.to_batches():
                for i in range(batch.num_rows):
                    row = {}
                    for c in cols:
                        v = batch.column(c)[i].as_py()
                        row[c] = v
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                    n += 1
            print(f"  ... total rows {n}", flush=True)
    return n


def fetch_rows(dataset, out_jsonl, config, split, limit):
    n = 0
    offset = 0
    with open(out_jsonl, "w", encoding="utf-8") as fh:
        while True:
            params = urllib.parse.urlencode({
                "dataset": dataset, "config": config, "split": split,
                "offset": offset, "length": 100})
            data = json.loads(get(f"{VIEWER}/rows?{params}"))
            rows = data.get("rows", [])
            if not rows:
                break
            for r in rows:
                fh.write(json.dumps(r["row"], ensure_ascii=False) + "\n")
                n += 1
                if limit and n >= limit:
                    return n
            if data.get("partial") is False or len(rows) < 100:
                break
            offset += len(rows)
    return n


def to_sqlite(out_jsonl, table):
    if not os.path.exists(DB):
        raise SystemExit("[err] dataset.db missing; run build_index.py first")
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute(f"DROP TABLE IF EXISTS {table}")
    # first pass: discover string columns by sampling first 200 rows
    cols = set()
    with open(out_jsonl, "r", encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            cols.update(d.keys())
            if len(cols) > 40:
                break
    # restrict columns to safe names
    def safe(c):
        return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in c)[:60]
    colmap = {c: safe(c) for c in cols}
    for c, s in colmap.items():
        if c != s:
            raise SystemExit(f"[err] column '{c}' not ascii; add manual mapping")
    coldefs = ", ".join(f'"{c}" TEXT' for c in sorted(cols))
    cur.execute(f'CREATE TABLE "{table}" ({coldefs})')
    def ser(v):
        if v is None or isinstance(v, (str, int, float, bool)):
            return v
        return json.dumps(v, ensure_ascii=False)
    batch = []
    with open(out_jsonl, "r", encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            batch.append(tuple(ser(d.get(c)) for c in sorted(cols)))
            if len(batch) >= 5000:
                cur.executemany(
                    f'INSERT INTO "{table}" VALUES ({",".join("?" * len(cols))})', batch)
                batch = []
    if batch:
        cur.executemany(f'INSERT INTO "{table}" VALUES ({",".join("?" * len(cols))})', batch)
    con.commit()
    n = cur.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
    con.close()
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--mode", default="parquet", choices=["parquet", "rows"])
    ap.add_argument("--config", default="default")
    ap.add_argument("--split", default="train")
    ap.add_argument("--table", default="")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    os.makedirs(HF_DIR, exist_ok=True)
    name = safe_name(args.dataset)
    out_jsonl = os.path.join(HF_DIR, f"{name}.jsonl")
    table = args.table or f"hf_{name}"

    if args.mode == "parquet":
        n = fetch_parquet(args.dataset, out_jsonl)
    else:
        n = fetch_rows(args.dataset, out_jsonl, args.config, args.split, args.limit)
    print(f"[rows] {n}")

    meta = {
        "dataset": args.dataset, "mode": args.mode, "config": args.config,
        "split": args.split, "rows": n, "jsonl": os.path.relpath(out_jsonl, BASE),
        "table": table,
    }
    with open(os.path.join(HF_DIR, f"{name}_meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    db_n = to_sqlite(out_jsonl, table)
    print(f"[db] table {table}: {db_n} rows -> {DB}")


if __name__ == "__main__":
    main()
