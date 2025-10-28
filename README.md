## LANWhisper

Small Python CLI for internal network discovery: given optional DNS servers and a list of common asset hostnames, it resolves records (A/AAAA and CNAME) to quickly identify interesting services inside a corporate network.

### Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Quick start (no flags)

```bash
./lanwhisper.py
```

What happens:
- Uses system DNS resolvers.
- Uses built-in default asset list (common internal hostnames).
- Creates per-run output folder: `./output/run_YYYYMMDD_HHMMSS_<id>/` with `results.json`, `results.csv`, `results.html`, `results.txt`.
- Prints a summary table to the console.

From a file:

```bash
./lanwhisper.py --domain corp.local --source ./list.txt
```

Use a custom DNS server:

```bash
./lanwhisper.py --server 10.0.0.53 --domain corp.local
```

Write all outputs to a directory (per-run folder inside):

```bash
./lanwhisper.py --domain corp.local --output /tmp/lanwhisper_out
```

This creates a subfolder like `run_YYYYMMDD_HHMMSS_ab12cd34` containing: `results.json`, `results.csv`, `results.html`, `results.txt` (and prints a table to the console).

Concurrency and timeouts:

```bash
./lanwhisper.py --domain corp.local --workers 128 --timeout 2.0 --retries 2
```

```

### Defaults

- `--domain` is optional. If not provided, assets without a dot are queried as-is.
- If `--server`/`--dns` is not provided, system resolvers are used.
- The tool can run with no flags at all using built-in defaults or `list.txt` if you provide `--source`.

Use shipped list:

```bash
./lanwhisper.py --source ./list.txt
```

### Stealth mode (minimal DNS footprint)

Stealth mode randomizes order, limits queries to A records, avoids following CNAMEs, and applies a low global QPS with jitter to blend into background traffic.

```bash
# Basic stealth: A only, no CNAME follow, low QPS with jitter
./lanwhisper.py --domain corp.local --stealth

### Output files
- `results.json`: full results including failures (exists=false).
- `results.csv`: only successful resolutions (exists=true).
- `results.html`: only successful resolutions (exists=true), styled table.
- `results.txt`: plain-text table of all results for quick review.
```

Notes for stealth:
- Randomizes asset order to avoid recognizable sequences.
- Default QPS in `--stealth` is 3 unless you set `--qps`.
- Retries are disabled in `--stealth` unless you override `--retries`.
- No CNAME following in `--stealth` (set `--types` and omit `--stealth` if you need deeper resolution).

### Notes

- If `--domain` is given and an asset has no dot, it queries `asset.domain`.
- Without `--assets` or `--input`, a built-in list of common internal names is used.
- If `rich` isn't installed, fallback plain-text table is printed.

