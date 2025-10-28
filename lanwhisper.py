#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
import random
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional, Set, Tuple
import uuid

import dns.exception
import dns.name
import dns.resolver

try:
    from rich.console import Console
    from rich.table import Table
except Exception:  # pragma: no cover - rich is optional at runtime, but recommended
    Console = None
    Table = None


DEFAULT_ASSETS: Tuple[str, ...] = (
    "dc",
    "dc1",
    "dc2",
    "ldap",
    "ad",
    "git",
    "gitlab",
    "gitea",
    "bitbucket",
    "jira",
    "confluence",
    "jenkins",
    "artifactory",
    "jfrog",
    "nexus",
    "harbor",
    "registry",
    "k8s",
    "kubernetes",
    "rancher",
    "argocd",
    "vault",
    "grafana",
    "prometheus",
    "alertmanager",
    "splunk",
    "elastic",
    "elasticsearch",
    "kibana",
    "logstash",
    "zabbix",
    "nagios",
    "graylog",
    "sonarqube",
    "pg",
    "postgres",
    "mysql",
    "mssql",
    "oracle",
    "mongo",
    "redis",
    "rabbitmq",
    "minio",
    "nfs",
    "files",
    "fileserver",
    "vpn",
    "fw",
    "proxy",
    "sso",
    "okta",
    "keycloak",
)


@dataclass
class ResolveResult:
    asset: str
    fqdn: str
    exists: bool
    ipv4: List[str]
    ipv6: List[str]
    cname_chain: List[str]
    error: Optional[str] = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve common internal asset hostnames against a DNS server to discover internal services."
        )
    )
    parser.add_argument(
        "--server",
        dest="server",
        metavar="IP[,IP...]",
        help="DNS server IP(s) to query (comma-separated or single IP). Defaults to system resolvers",
    )
    parser.add_argument(
        "--domain",
        dest="domain",
        help=(
            "Optional domain suffix. If provided and an asset has no dot, we'll query asset.domain"
        ),
    )
    parser.add_argument(
        "--source",
        dest="source_file",
        help="Path to a file with asset names (one per line).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=64,
        help="Number of concurrent worker threads (default: 64)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.5,
        help="Per-query timeout in seconds (default: 2.5)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retry count for transient DNS failures (default: 2)",
    )
    parser.add_argument(
        "--output",
        dest="output_path",
        help=(
            "Base directory to write outputs. A per-run folder will be created inside "
            "(run_<timestamp>_<id>) containing results.json/csv/html/txt. Default: ./output"
        ),
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        help=(
            "Stealth mode: randomize order, query A only (unless overridden), do not follow CNAME, and apply QPS limiting with jitter."
        ),
    )
    return parser.parse_args()


def normalize_dns_servers(raw: Optional[str]) -> Optional[List[str]]:
    if not raw:
        return None
    servers: List[str] = []
    for part in raw.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            servers.append(candidate)
        except ValueError:
            raise SystemExit(f"Invalid DNS server IP: {candidate}")
    return servers or None


def build_resolver(dns_servers: Optional[List[str]], timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if dns_servers:
        resolver.nameservers = dns_servers
    return resolver


def read_assets(source_file: Optional[str]) -> List[str]:
    if source_file:
        with open(source_file, "r", encoding="utf-8") as f:
            items = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            return items
    return list(DEFAULT_ASSETS)


def to_fqdn(asset: str, domain: Optional[str]) -> str:
    if "." in asset:
        return asset.rstrip(".")
    if domain:
        return f"{asset.strip()}.{domain.strip().rstrip('.')}"
    return asset.strip()


def query_record(
    resolver: dns.resolver.Resolver,
    name: str,
    rtype: str,
    timeout: float,
    retries: int,
    rate_limiter: Optional["RateLimiter"] = None,
) -> Tuple[Optional[List[str]], Optional[str]]:
    attempts = 0
    last_error: Optional[str] = None
    while attempts <= retries:
        try:
            if rate_limiter is not None:
                rate_limiter.acquire()
            answers = resolver.resolve(name, rtype, lifetime=timeout)
            values = [str(rdata) for rdata in answers]
            return values, None
        except dns.resolver.NXDOMAIN:
            return None, "NXDOMAIN"
        except dns.resolver.NoAnswer:
            return [], None
        except (dns.resolver.Timeout, dns.resolver.YXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException) as e:
            last_error = f"{e.__class__.__name__}: {e}"
            attempts += 1
            continue
    return None, last_error


def resolve_asset(
    resolver: dns.resolver.Resolver,
    asset: str,
    domain: Optional[str],
    record_types: Iterable[str],
    timeout: float,
    retries: int,
    allow_cname_follow: bool,
    rate_limiter: Optional["RateLimiter"],
) -> ResolveResult:
    fqdn = to_fqdn(asset, domain)
    ipv4_set: Set[str] = set()
    ipv6_set: Set[str] = set()
    cname_chain: List[str] = []

    # Follow up to 5 CNAMEs to avoid loops
    current_name = fqdn
    max_cname_depth = 5
    depth = 0
    terminal_error: Optional[str] = None
    while depth <= max_cname_depth:
        # Query A/AAAA (and optionally other types)
        last_error = None
        for rtype in record_types:
            values, err = query_record(
                resolver, current_name, rtype, timeout, retries, rate_limiter
            )
            if err == "NXDOMAIN":
                terminal_error = err
                break
            if err:
                last_error = err
                continue
            if values is None:
                continue
            if rtype.upper() == "A":
                for v in values:
                    try:
                        ipaddress.IPv4Address(v)
                        ipv4_set.add(v)
                    except Exception:
                        pass
            elif rtype.upper() == "AAAA":
                for v in values:
                    try:
                        ipaddress.IPv6Address(v)
                        ipv6_set.add(v)
                    except Exception:
                        pass

        if terminal_error == "NXDOMAIN":
            break

        if not allow_cname_follow:
            break

        # Try to discover CNAME and follow it
        cname_values, cname_err = query_record(
            resolver, current_name, "CNAME", timeout, retries, rate_limiter
        )
        if cname_err == "NXDOMAIN":
            terminal_error = cname_err
            break
        if cname_values and len(cname_values) > 0:
            target = str(cname_values[0]).rstrip(".")
            cname_chain.append(f"{current_name} -> {target}")
            current_name = target
            depth += 1
            continue
        break

    exists = bool(ipv4_set or ipv6_set or cname_chain)
    return ResolveResult(
        asset=asset,
        fqdn=fqdn,
        exists=exists,
        ipv4=sorted(ipv4_set),
        ipv6=sorted(ipv6_set),
        cname_chain=cname_chain,
        error=terminal_error,
    )


class RateLimiter:
    def __init__(self, qps: float, jitter: float) -> None:
        self.interval = 1.0 / qps if qps > 0 else 0.0
        self.jitter = max(0.0, jitter)
        self._last_time: Optional[float] = None
        self._lock = dns.resolver._asyncbackend.threading.Lock() if hasattr(dns.resolver, "_asyncbackend") else None

    def acquire(self) -> None:
        if self.interval <= 0:
            if self.jitter > 0:
                time.sleep(random.uniform(0.0, self.jitter))
            return
        # Fallback lock if we didn't find a dns threading object
        if self._lock is None:
            import threading as _threading

            self._lock = _threading.Lock()
        with self._lock:  # type: ignore[attr-defined]
            now = time.monotonic()
            target = now if self._last_time is None else max(self._last_time + self.interval, now)
            self._last_time = target
        sleep_time = max(0.0, target - now) + (random.uniform(0.0, self.jitter) if self.jitter > 0 else 0.0)
        if sleep_time > 0:
            time.sleep(sleep_time)


def print_table(results: List[ResolveResult]) -> None:
    if Console is None or Table is None:
        for r in results:
            print(
                f"{r.asset:20} {r.fqdn:35} exists={r.exists} ipv4={','.join(r.ipv4)} ipv6={','.join(r.ipv6)} cname={'; '.join(r.cname_chain)} error={r.error or ''}"
            )
        return
    console = Console()
    table = Table(show_header=True, header_style="bold")
    table.add_column("Asset")
    table.add_column("FQDN")
    table.add_column("Exists")
    table.add_column("IPv4")
    table.add_column("IPv6")
    table.add_column("CNAME Chain")
    for r in results:
        table.add_row(
            r.asset,
            r.fqdn,
            "Yes" if r.exists else "No",
            ", ".join(r.ipv4),
            ", ".join(r.ipv6),
            " | ".join(r.cname_chain),
        )
    console.print(table)


def write_json(results: List[ResolveResult], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, ensure_ascii=False, indent=2)


def write_csv(results: List[ResolveResult], path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["asset", "fqdn", "exists", "ipv4", "ipv6", "cname_chain", "error"])
        for r in (r for r in results if r.exists):
            writer.writerow(
                [
                    r.asset,
                    r.fqdn,
                    "yes" if r.exists else "no",
                    ";".join(r.ipv4),
                    ";".join(r.ipv6),
                    ";".join(r.cname_chain),
                    r.error or "",
                ]
            )


def write_html(results: List[ResolveResult], path: str) -> None:
    html_head = (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>LANWhisper Results</title>"
        "<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,\n"
        "Cantarell,Noto Sans,sans-serif;line-height:1.4;margin:20px;background:#0b0c10;color:#d1d5db}"
        "table{border-collapse:collapse;width:100%;background:#111827;color:#e5e7eb;border-radius:8px;overflow:hidden}"
        "th,td{border-bottom:1px solid #374151;padding:10px 12px;text-align:left;font-size:14px}"
        "th{background:#1f2937;font-weight:600}"
        "tr:nth-child(even){background:#0f1623}"
        ".pill{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:12px}"
        ".yes{background:#065f46;color:#ecfdf5}.no{background:#7f1d1d;color:#fee2e2}"
        ".muted{color:#9ca3af}"
        "footer{margin-top:16px;color:#9ca3af;font-size:12px}"
        "</style></head><body>"
        "<h2>LANWhisper Results</h2>"
    )
    html_rows = []
    html_rows.append("<table><thead><tr><th>Asset</th><th>FQDN</th><th>Exists</th><th>IPv4</th><th>IPv6</th><th>CNAME Chain</th><th>Error</th></tr></thead><tbody>")
    for r in (r for r in results if r.exists):
        exists_pill = f"<span class='pill {'yes' if r.exists else 'no'}'>{'Yes' if r.exists else 'No'}</span>"
        ipv4 = ", ".join(r.ipv4) if r.ipv4 else "<span class='muted'>-</span>"
        ipv6 = ", ".join(r.ipv6) if r.ipv6 else "<span class='muted'>-</span>"
        cname = " | ".join(r.cname_chain) if r.cname_chain else "<span class='muted'>-</span>"
        err = (r.error or "") if r.error else "<span class='muted'>-</span>"
        html_rows.append(
            f"<tr><td>{r.asset}</td><td>{r.fqdn}</td><td>{exists_pill}</td><td>{ipv4}</td><td>{ipv6}</td><td>{cname}</td><td>{err}</td></tr>"
        )
    html_rows.append("</tbody></table>")
    html_footer = "<footer>Generated by LANWhisper</footer></body></html>"
    content = html_head + "".join(html_rows) + html_footer
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def render_plain_table(results: List[ResolveResult]) -> str:
    headers = ("Asset", "FQDN", "Exists", "IPv4", "IPv6", "CNAME Chain", "Error")
    lines: List[str] = []
    lines.append(
        f"{headers[0]:20} {headers[1]:35} {headers[2]:6} {headers[3]:30} {headers[4]:30} {headers[5]:40} {headers[6]}"
    )
    lines.append("-" * 180)
    for r in results:
        ipv4 = ",".join(r.ipv4)
        ipv6 = ",".join(r.ipv6)
        cname = " | ".join(r.cname_chain)
        error = r.error or ""
        lines.append(
            f"{r.asset:20} {r.fqdn:35} {('Yes' if r.exists else 'No'):6} {ipv4:30} {ipv6:30} {cname:40} {error}"
        )
    return "\n".join(lines) + "\n"


def write_txt(results: List[ResolveResult], path: str) -> None:
    text = render_plain_table(results)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def main() -> None:
    args = parse_args()
    DEFAULT_RECORD_TYPES = ["A", "AAAA"]
    DEFAULT_RETRIES = 2
    # DNS server selection
    dns_servers = normalize_dns_servers(args.server)
    resolver = build_resolver(dns_servers, args.timeout)

    assets = read_assets(args.source_file)
    if args.stealth:
        random.shuffle(assets)

    # Stealth adjustments: A only and no CNAME following, unless user overrode types
    allow_cname_follow = not args.stealth
    record_types = ["A"] if args.stealth else DEFAULT_RECORD_TYPES

    # Reduce retries in stealth if user didn't override
    retries = args.retries
    if args.stealth and retries == DEFAULT_RETRIES:
        retries = 0

    # Global rate limiter (fixed defaults in stealth)
    DEFAULT_STEALTH_QPS = 3.0
    DEFAULT_JITTER = 0.15
    rate_limiter = RateLimiter(DEFAULT_STEALTH_QPS, DEFAULT_JITTER) if args.stealth else None

    results: List[ResolveResult] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_asset = {
            executor.submit(
                resolve_asset,
                resolver,
                asset,
                args.domain,
                record_types,
                args.timeout,
                retries,
                allow_cname_follow,
                rate_limiter,
            ): asset
            for asset in assets
        }
        for future in as_completed(future_to_asset):
            try:
                results.append(future.result())
            except Exception as e:
                asset = future_to_asset[future]
                results.append(
                    ResolveResult(
                        asset=asset,
                        fqdn=to_fqdn(asset, args.domain),
                        exists=False,
                        ipv4=[],
                        ipv6=[],
                        cname_chain=[],
                        error=f"UnexpectedError: {e}",
                    )
                )

    results.sort(key=lambda r: (not r.exists, r.asset))

    base_dir = Path(args.output_path) if args.output_path else (Path.cwd() / "output")
    run_dir = base_dir / (time.strftime("run_%Y%m%d_%H%M%S") + f"_{uuid.uuid4().hex[:8]}")
    run_dir.mkdir(parents=True, exist_ok=True)

    write_json(results, str(run_dir / "results.json"))
    write_csv(results, str(run_dir / "results.csv"))
    write_html(results, str(run_dir / "results.html"))
    write_txt(results, str(run_dir / "results.txt"))
    print_table(results)
    print(f"Wrote outputs to {run_dir} (results.json, results.csv, results.html, results.txt)")


if __name__ == "__main__":
    main()


