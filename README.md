<h1 align="center">🔉 LANWhisper</h1>

<p align="center">
  <strong>Quietly map a corporate network with nothing but DNS.</strong><br>
  Point it at a domain (and optionally a DNS server), feed it a list of asset names, and it tells you what's live — A, AAAA, CNAME — fast or stealthy, your call.
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/osherassor/LANWhisper?style=for-the-badge&logo=github&color=ffd700" alt="Stars">
  <img src="https://img.shields.io/github/last-commit/osherassor/LANWhisper?style=for-the-badge&logo=git&color=00d4aa" alt="Last commit">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-informational?style=for-the-badge" alt="License">
</p>

---

## What is this?

A small Python CLI for **internal network discovery via DNS**. Drop it on your tester laptop, give it the corporate DNS server and a list of common internal asset names (`vcenter`, `idrac`, `cyberark`, `wazuh`, …), and it tells you which ones actually resolve. Output is JSON / CSV / HTML / TXT — pick what fits your report.

The point: instead of hammering the network with port scans on day one, ask DNS what's there. Quieter. Faster. Often more accurate, because devs reuse the same hostnames everywhere.

## 🚀 Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Zero flags — uses system resolvers + built-in default asset list
./lanwhisper.py
```

Each run creates `./output/run_YYYYMMDD_HHMMSS_<id>/` with `results.{json,csv,html,txt}` plus a console summary table.

## 📖 Common workflows

```bash
# Internal sweep against corp DNS, custom asset list
./lanwhisper.py --domain corp.local --server 10.0.0.53 --source ./list.txt

# External sweep, more workers
./lanwhisper.py --domain target.com --source ./list.txt --workers 128

# Tune timeouts and retries
./lanwhisper.py --domain corp.local --workers 128 --timeout 2.0 --retries 2

# Custom output location
./lanwhisper.py --domain corp.local --output /tmp/lanwhisper_out
```

## 🥷 Stealth mode

Tries hard to look like background traffic:

```bash
./lanwhisper.py --domain corp.local --stealth
```

In stealth:

- 🎲 **Randomized order** — no recognizable sequences hitting the resolver
- 🅰️ **A records only** — no CNAME chasing
- 🐌 **Low QPS with jitter** — default 3 qps, override with `--qps`
- 🔁 **No retries by default** — override with `--retries`

## 📤 Output files

| File | Contains |
|---|---|
| `results.json` | Everything, including failures (`exists=false`) |
| `results.csv` | Successful resolutions only — spreadsheet-ready |
| `results.html` | Successful resolutions, styled table — drop into client reports |
| `results.txt` | Plain-text table for terminal review |

## 🛠️ Notes

- `--domain` is optional. Without it, assets without a dot are queried as-is.
- `--server` / `--dns` is optional. Without it, system resolvers are used.
- Built-in asset list runs if you don't supply `--source`.
- Falls back to plain-text output if `rich` isn't installed.

## 🤝 Pairs well with

- 📚 **[AwesomeWL — `subdomains/subdomains.txt`](https://github.com/osherassor/AwesomeWL)** — the **companion wordlist**. 10,065 entries balanced for hybrid corp networks: classic AD targets, modern SaaS, AI products, env/region/cluster matrix. Built specifically to be fed into LANWhisper.
- 🏢 **[AD_Scanner_tool](https://github.com/osherassor/AD_Scanner_tool)** — once you've found the DCs and management hosts, point AD_Scanner at them.
- 🗂️ **[smb_files_scanner](https://github.com/osherassor/smb_files_scanner)** — when LANWhisper finds `fileserver`, `dfs`, `backup-01`, pipe them in for content discovery.

```bash
# Common combo
curl -sO https://raw.githubusercontent.com/osherassor/AwesomeWL/main/subdomains/subdomains.txt
./lanwhisper.py --domain corp.local --server 10.0.0.53 --source ./subdomains.txt --stealth
```

## ⚖️ Responsible use

Authorized engagements only. DNS recon is quiet, but it's still recon — make sure it's in scope.

## 📄 License

MIT
