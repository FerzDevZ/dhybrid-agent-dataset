# pentest-dataset

Dataset lokal untuk **Agentic AI / pentest AI**: koleksi CVE lengkap (NVD full dump),
exploit/PoC Exploit-DB, dan repos writeup GitHub — terindeks dalam SQLite+FTS5 agar
agent bisa query cepat.

## Struktur

```
pentest-dataset/
├── README.md
├── tools/                        # script pembangun + query
│   ├── fetch_nvd.py              #   download + ekstrak full dump NVD
│   ├── fetch_exploitdb.py        #   fetch Exploit-DB (GitLab CSV) + PoC + markdown
│   ├── fetch_github_writeups.py  #   clone repo writeup GitHub (shallow)
│   ├── fetch_hf.py               #   fetch enrichment HuggingFace (CIRCL)
│   ├── build_index.py            #   bangun dataset.db (SQLite + FTS5)
│   ├── export_parquet.py         #   export SQLite → parquet (zstd)
│   ├── push_hf_multi.py          #   push parquet ke HuggingFace Hub
│   └── query.py                  #   interface query untuk agent (output JSON)
└── data/
    ├── cves/train/data.parquet               # ~373k CVE (NVD)
    ├── exploits/train/data.parquet           # ~46k exploit-db
    ├── patches/train/data.parquet            # patch diff + commit URL
    ├── scores/train/data_part{0..14}.parquet # enrichment CIRCL (15 part ≤13MB)
    └── writeups/train/data.parquet           # ~48k writeup
```

> Saat build lokal penuh, folder tambahan muncul: `dataset.db`, `hf/`, `cves/`,
> `writeups/`, `raw/`, `indices/`. Ini tidak di-commit ke GitHub (lihat `.gitignore`).

## Pipeline (build ulang)

```bash
python3 tools/fetch_nvd.py              # download feed (skip bila sudah ada) + ekstrak per-CVE + index
python3 tools/fetch_exploitdb.py        # metadata + PoC + markdown + index
python3 tools/fetch_github_writeups.py  # clone repos (shallow, butuh git)
python3 tools/fetch_hf.py --dataset CIRCL/vulnerability-scores --table hf_vuln_scores
python3 tools/fetch_hf.py --dataset CIRCL/vulnerability-cwe-patch --table hf_vuln_patches
python3 tools/build_index.py            # bangun data/dataset.db (mempertahankan tabel hf_*)
```

> `fetch_nvd.py --years 2002-2026` bisa diulang tanpa mendownload ulang; hanya CVE
> baru yang ditambahkan (idempotent, berbasis indeks).
>
> PoC Exploit-DB (46k file) tersedia lengkap di `data/raw/exploitdb/files/`
> (flat, nama = `exploitdb_id.ext`) dan clone git di `data/raw/exploitdb/repo/`
> (untuk update via `git pull`).

## Query (untuk agent)

Semua output JSON per baris (NDJSON), cocok diparse agent.

```bash
# cari CVE spesifik + exploit terkait
python3 tools/query.py --cve CVE-2024-3400 --with-exploits

# full-text search (FTS5) + filter
python3 tools/query.py --search "apache httpd" --severity critical --since 2023 --min-cvss 9.0 --limit 10

# cari produk
python3 tools/query.py --product nginx --cwe CWE-78

# cari writeup repo / exploit-db
python3 tools/query.py --writeups "lateral movement"
python3 tools/query.py --exploits "shellshock" --platform linux

# cari di tabel enrichment HuggingFace (CIRCL: CVE/CVSS v4/CPE + patch diff)
python3 tools/query.py --hf "nginx"          # id/description/CVSS/CPE (mencakup CVE baru > NVD dump)
python3 tools/query.py --patches "sql"       # patch diff (base64) + commit URL + CWE

# statistik dataset
python3 tools/query.py --stats
```

### Koneksi SQLite langsung (untuk RAG / embedding pipeline)

```python
import sqlite3
con = sqlite3.connect("data/dataset.db")
rows = con.execute(
    "SELECT c.id,c.severity,c.cvss,c.cwe,c.description "
    "FROM cves_fts f JOIN cves c ON f.id=c.id "
    "WHERE cves_fts MATCH ? ORDER BY c.cvss DESC LIMIT 20",
    ("log4j",)).fetchall()
```

Tabel: `cves`, `cves_fts` (FTS5), `exploits`, `writeups`, plus tabel `hf_*`
(dari HuggingFace: `hf_vuln_scores` = CVE/CVSS v4/CPE/patch-URL; `hf_vuln_patches` =
patch diff base64 + commit + CWE). Kolom `cves.refs`, `cves.ref_tags`,
`exploits.cves` dan `hf_*` berisi JSON array.

## Catatan hukum/etika

Dataset untuk **pengujian keamanan yang sah** (bug bounty, CTF, lab pribadi, riset
dengan izin). Exploit/PoC dari Exploit-DB hanya untuk keperluan authorized testing.
