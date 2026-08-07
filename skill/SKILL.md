---
name: hybrid-pentest
description: Hybrid pentest workflow combining the local pentest-dataset (CVE/exploit/writeup intelligence) with HexStrike MCP tools (active scanning/exploitation). Use when a security testing task needs both vulnerability intelligence lookup and live tool execution — e.g. research a CVE then scan/exploit a target, or enrich scan findings with exploit/PoC references. Requires the pentest dataset (query.py) and HexStrike MCP server.
---

# Hybrid Pentest

Combine **dataset intelligence** (offline CVE/exploit/writeup knowledge) with **HexStrike MCP** (live scanning and exploitation) into one workflow: **Research → Target → Exploit → Report**.

## When to use

- You have a target and want CVEs/exploits/writeups that apply to it.
- A scan found a product/version — look up relevant CVEs + PoCs in the dataset.
- You need a structured attack plan: recon → identify → exploit → report.

## Data sources

| Source | Path | Purpose |
|---|---|---|
| Pentest dataset (local) | `~/pentest-dataset/` | SQLite+FTS5: `cves`, `exploits`, `writeups`, `hf_*` tables |
| Dataset query tool | `~/pentest-dataset/tools/query.py` | JSON-ND output, agent-friendly |
| Parquet mirrors (GitHub/HF) | `FerzDevZ/dhybrid-agent-dataset`, `xelisme/pentest-dataset` | Same data, portable parquet |
| HexStrike MCP | `hexstrike` MCP server | 150+ tools: nmap, nuclei, sqlmap, metasploit, ffuf, ... |

## Phase 1 — Research (dataset first, no target needed)

Run `query.py` from the dataset directory. All output is NDJSON.

```bash
cd ~/pentest-dataset
python3 tools/query.py --stats                          # dataset overview
python3 tools/query.py --cve CVE-2024-3400 --with-exploits
python3 tools/query.py --search "apache httpd rce" --severity critical --min-cvss 9.0 --limit 20
python3 tools/query.py --product nginx --cwe CWE-78 --since 2023
python3 tools/query.py --exploits "shellshock" --platform linux
python3 tools/query.py --writeups "lateral movement"
python3 tools/query.py --hf "libreoffice"               # CIRCL enrichment (newer CVEs)
python3 tools/query.py --patches "log4j"                # patch diffs (base64) + commit URLs
```

Query flags: `--cve`, `--search` (FTS5), `--product`, `--writeups`, `--exploits`,
`--platform`, `--severity` (comma list), `--cwe`, `--since`, `--min-cvss`,
`--limit`, `--stats`, `--hf`, `--patches`, `--with-exploits`.

Direct SQLite (RAG/embedding use):

```python
import sqlite3
con = sqlite3.connect("~/pentest-dataset/data/dataset.db")
rows = con.execute(
    "SELECT id,severity,cvss,cwe,description FROM cves_fts f "
    "JOIN cves c ON f.id=c.id WHERE cves_fts MATCH ? "
    "ORDER BY c.cvss DESC LIMIT 20", ("log4j",)).fetchall()
```

## Phase 2 — Target (HexStrike MCP)

Verify the target is authorized, then enumerate and scan:

| Goal | Tool(s) |
|---|---|
| Port scan | `nmap_scan`, `nmap_advanced_scan`, `rustscan_fast_scan`, `masscan_high_speed` |
| Web discovery | `gobuster_scan`, `dirsearch_scan`, `feroxbuster_scan`, `ffuf_scan`, `katana_crawl`, `hakrawler_crawl` |
| Vuln scan | `nuclei_scan`, `nikto_scan`, `jaeles_vulnerability_scan`, `wpscan_analyze` (WordPress) |
| Tech/WAF detection | `httpx_probe`, `detect_technologies_ai`, `wafw00f_scan`, `analyze_target_intelligence` |
| SMB/AD | `smbmap_scan`, `enum4linux_scan`, `netexec_scan`, `rpcclient_enumeration`, `nbtscan_netbios` |
| Cloud/K8s | `prowler_scan`, `trivy_scan`, `scout_suite_assessment`, `kube_hunter_scan` |

## Phase 3 — Exploit

Cross-reference scan findings against the dataset, then test:

| Situation | Dataset query | HexStrike tool |
|---|---|---|
| CVE found on target version | `query.py --cve <id> --with-exploits` | `generate_exploit_from_cve`, `metasploit_run`, `pwntools_exploit` |
| SQLi param | `query.py --search "<product> sqli"` | `sqlmap_scan`, `ai_generate_payload`(sqli) |
| XSS | `query.py --search "<product> xss"` | `dalfox_xss_scan`, `xsser_scan`, `browser_agent_inspect` |
| Auth/JWT | `query.py --writeups "jwt auth bypass"` | `jwt_analyzer`, `bugbounty_authentication_bypass_testing` |
| Upload bypass | `query.py --writeups "file upload"` | `bugbounty_file_upload_testing` |
| Credential brute | `query.py --exploits "<service>" --platform linux` | `hydra_attack`, `hashcat_crack`, `john_crack` |
| Fuzzing endpoints | `query.py --writeups "<app> fuzz"` | `ffuf_scan`, `wfuzz_scan`, `http_intruder`, `api_fuzzer` |

Plan chaining: `create_attack_chain_ai` to sequence tools; `intelligent_smart_scan`
for AI-driven tool selection against a target.

## Phase 4 — Report

```bash
python3 tools/query.py --cve CVE-2024-3400 --with-exploits > /tmp/cve_context.json
python3 tools/query.py --search "<product>" --severity critical > /tmp/cve_pool.json
```

- Use `create_vulnerability_report` to render findings.
- Use `create_scan_summary` for a scan recap.
- If CTF: use the `ctf-writeup` skill to produce a submission writeup.

## Worked example

```
# 1. Research (no target yet)
python3 tools/query.py --search "libreoffice" --min-cvss 9.0 --limit 5

# 2. Enumerate target
nmap_scan(target=10.0.0.5, scan_type="-sV -sC")
gobuster_scan(url=http://10.0.0.5, wordlist=/usr/share/wordlists/dirb/common.txt)

# 3. Match findings to dataset
python3 tools/query.py --cve CVE-2024-1234 --with-exploits

# 4. Exploit + report
generate_exploit_from_cve(cve_id=CVE-2024-1234, target_os=linux, exploit_type=poc)
create_vulnerability_report(vulnerabilities=<findings>, target=10.0.0.5)
```

## Security / ethics

- Only test targets you own or are explicitly authorized to test (bug bounty scope, CTF, lab).
- Exploit/PoC material from Exploit-DB is for authorized testing only.
- Never push secrets/tokens into repos; keep authorization scoped and documented.
