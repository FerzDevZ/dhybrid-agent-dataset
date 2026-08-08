#!/usr/bin/env python3
"""Push each config separately to HF Hub using HfApi."""
import os
import pyarrow.parquet as pq
from datasets import Dataset
from huggingface_hub import HfApi

PARQUET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
REPO_ID = "xelisme/pentest-dataset"

CONFIGS = [
    "cves",
    "exploits",
    "writeups",
    "scores",
    "patches",
]

def main():
    api = HfApi(token=True)
    
    for name in CONFIGS:
        # For scores, which has multiple parts, load_dataset or Dataset.from_parquet supports a folder
        path = os.path.join(PARQUET_DIR, name, "train")
        if not os.path.exists(path):
            print(f"[skip] {name} (not found: {path})")
            continue
            
        print(f"[load] {name} ...", flush=True)
        try:
            from datasets import load_dataset
            # Load all parquet files in the train directory
            ds = load_dataset("parquet", data_files=f"{path}/*.parquet", split="train")
        except Exception as e:
            print(f"  Error loading {name}: {e}")
            continue
            
        print(f"  {len(ds):,} rows, {len(ds.column_names)} cols")
        
        print(f"[push] {name} -> {REPO_ID} (config={name})", flush=True)
        ds.push_to_hub(
            REPO_ID, 
            config_name=name, 
            split="train", 
            private=False, 
            token=True,
            commit_message=f"Update {name} config"
        )
        print(f"  ✓ {name} pushed")

    print("\n[done] All configs pushed")

if __name__ == "__main__":
    main()