#!/usr/bin/env python3
"""Export all SQLite tables to Parquet (zstd compressed) for Hugging Face Hub upload."""
import os
import sqlite3
import pyarrow as pa
import pyarrow.parquet as pq
import pandas as pd

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "dataset.db")
OUT = os.path.join(os.path.dirname(DB))

TABLES = {
    "cves": "cves", 
    "exploits": "exploits", 
    "writeups": "writeups", 
    "hf_vuln_scores": "scores", 
    "hf_vuln_patches": "patches"
}

def main():
    os.makedirs(OUT, exist_ok=True)
    con = sqlite3.connect(DB)
    total = 0
    for t_db, t_folder in TABLES.items():
        print(f"[export] {t_db} -> {t_folder} ...", flush=True)
        try:
            df = pd.read_sql_query(f"SELECT * FROM {t_db}", con)
        except Exception as e:
            print(f"  skip: {e}")
            continue
        table = pa.Table.from_pandas(df)
        tbl_dir = os.path.join(OUT, t_folder, "train")
        os.makedirs(tbl_dir, exist_ok=True)
        pq.write_table(table, os.path.join(tbl_dir, "data.parquet"),
                       compression="zstd", row_group_size=50_000)
        print(f"  {len(df):,} rows → {tbl_dir}/data.parquet ({os.path.getsize(os.path.join(tbl_dir, 'data.parquet')) / 1e9:.2f} GB)")
        total += len(df)
    con.close()
    print(f"\nDone. Total rows: {total:,}. Output: {OUT}")

if __name__ == "__main__":
    main()