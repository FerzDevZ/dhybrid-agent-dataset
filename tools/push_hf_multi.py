#!/usr/bin/env python3
"""Push each config separately to HF Hub using HfApi."""
import os
import pyarrow.parquet as pq
from datasets import Dataset
from huggingface_hub import HfApi

PARQUET_DIR = "/home/cyber/pentest-dataset/data/parquet_v3"
REPO_ID = "xelisme/pentest-dataset"

CONFIGS = {
    "cves": "cves/train/data.parquet",
    "exploits": "exploits/train/data.parquet",
    "writeups": "writeups/train/data.parquet",
    "hf_vuln_scores": "hf_vuln_scores/train/data.parquet",
    "hf_vuln_patches": "hf_vuln_patches/train/data.parquet",
}

def main():
    api = HfApi(token=True)
    
    for name, rel in CONFIGS.items():
        path = os.path.join(PARQUET_DIR, rel)
        print(f"[load] {name} ...", flush=True)
        table = pq.read_table(path)
        ds = Dataset(table)
        print(f"  {len(ds):,} rows, {len(ds.column_names)} cols")
        
        print(f"[push] {name} -> {REPO_ID} (config={name})", flush=True)
        ds.push_to_hub(
            REPO_ID, 
            config_name=name, 
            split="train", 
            private=False, 
            token=True,
            commit_message=f"Add {name} config"
        )
        print(f"  ✓ {name} pushed")

    print("\n[done] All configs pushed")

if __name__ == "__main__":
    main()