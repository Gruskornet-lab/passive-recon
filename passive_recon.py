#!/usr/bin/env python3
"""Passive recon tool for bug bounty programs.

Queries public data sources only — no direct requests to target infrastructure.
"""
import asyncio
import argparse
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from rich.console import Console

from src.scope import parse_targets, matches_scope, get_query_bases
from src.models import ReconResult, BaseResult, Subdomain
from src.cache import Cache
from src.dns_resolver import resolve_all
from src.sources.crtsh import query_crtsh_with_retry
from src.sources.certspotter import query_certspotter
from src.sources.alienvault import query_alienvault
from src.sources.hackertarget import query_hackertarget
from src.sources.rapiddns import query_rapiddns
from src.sources.anubis import query_anubis
from src.sources.wayback import query_wayback
from src.analysis.interesting_urls import find_interesting_urls
from src.analysis.tech_fingerprint import fingerprint_tech
from src.analysis.takeover import check_takeover_candidates, load_fingerprints
from src.analysis.parameter_mining import mine_parameters
from src.report.markdown import render_markdown
from src.report.json_output import render_json

VERSION = "1.0"
console = Console(stderr=True)

SUBDOMAIN_SOURCES = [
    ("crt.sh", query_crtsh_with_retry),
    ("certspotter", query_certspotter),
    ("alienvault", query_alienvault),
    ("hackertarget", query_hackertarget),
    ("rapiddns", query_rapiddns),
    ("anubis", query_anubis),
]


async def process_base(
    client: httpx.AsyncClient,
    base: str,
    scope_patterns: list[str],
    wayback_limit: int,
    cache: Cache,
    dns_sem: asyncio.Semaphore,
    takeover_fingerprints: list[dict],
    result: ReconResult,
) -> BaseResult:
    base_result = BaseResult(base=base)
    host_sources: dict[str, set[str]] = {}

    async def _query_sources(target: str, label: str) -> None:
        for source_name, query_fn in SUBDOMAIN_SOURCES:
            cache_key_prefix = f"{source_name}:{target}"
            try:
                cached = cache.get(source_name, target)
                if cached is not None:
                    hosts: set[str] = set(cached)
                    console.print(f"    [dim]↑ {source_name}/{label}: {len(hosts)} (cached)[/dim]")
                else:
                    hosts = await query_fn(client, target)
                    cache.set(source_name, target, list(hosts))
                    console.print(f"    [green]✓[/green] {source_name}/{label}: {len(hosts)}")

                for h in hosts:
                    h = h.lower().strip().rstrip(".")
                    if not h:
                        continue
                    if matches_scope(h, scope_patterns):
                        host_sources.setdefault(h, set()).add(source_name)
                    elif h not in base_result.out_of_scope:
                        base_result.out_of_scope.append(h)

                result.source_stats[source_name] = result.source_stats.get(source_name, True)

            except Exception as e:
                result.source_stats[source_name] = False
                result.errors.append(f"{source_name}/{target}: {e}")
                console.print(f"    [yellow]✗[/yellow] {source_name}/{label}: {e}")

    # Query all sources for the base domain
    await _query_sources(base, base)

    # Also query each exact scope target that belongs to this base.
    # Discovers deeper subdomains (v1.api.example.com) and richer passive DNS.
    exact_targets = [
        p for p in scope_patterns
        if not p.startswith("*.")
        and p != base
        and (p.endswith("." + base))
    ]
    if exact_targets:
        console.print(f"  [*] Querying sources for {len(exact_targets)} exact scope targets...")
        for target in exact_targets:
            await _query_sources(target, target)

    if matches_scope(base, scope_patterns):
        host_sources.setdefault(base, set())

    all_hosts = list(host_sources.keys())
    console.print(f"  [*] DNS resolving {len(all_hosts)} hosts...")
    dns_records = await resolve_all(all_hosts, dns_sem)

    for host, dns_record in dns_records.items():
        sub = Subdomain(
            host=host,
            dns=dns_record,
            sources=sorted(host_sources.get(host, set())),
        )
        tc = check_takeover_candidates(sub, takeover_fingerprints)
        if tc:
            sub.takeover_candidate = tc
        base_result.subdomains.append(sub)

    base_result.subdomains.sort(key=lambda s: s.host)

    console.print(f"  [*] Querying Wayback Machine (limit: {wayback_limit:,})...")
    raw_urls_set: set[str] = set()
    raw_urls: list[str] = []

    async def _wayback_fetch(target: str, limit: int) -> list[str]:
        cache_key = f"{target}_{limit}"
        cached_wb = cache.get("wayback", cache_key)
        if cached_wb is not None:
            console.print(f"    [dim]↑ wayback/{target}: {len(cached_wb):,} (cached)[/dim]")
            return cached_wb
        urls = await query_wayback(client, target, limit=limit)
        cache.set("wayback", cache_key, urls)
        console.print(f"    [green]✓[/green] wayback/{target}: {len(urls):,} URLs")
        return urls

    try:
        # Query the base domain (covers all subdomains via matchType=domain)
        base_urls = await _wayback_fetch(base, wayback_limit)
        for u in base_urls:
            if u not in raw_urls_set:
                raw_urls_set.add(u)
                raw_urls.append(u)

        result.source_stats["wayback"] = True

        # Also query each individual in-scope host that isn't the base itself.
        # This is important when scope is exact hostnames — Wayback may have
        # per-subdomain history not returned by the domain-level query.
        per_sub_limit = min(10000, wayback_limit // max(len(base_result.subdomains), 1))
        for sub in base_result.subdomains:
            if sub.host == base:
                continue
            try:
                sub_urls = await _wayback_fetch(sub.host, per_sub_limit)
                for u in sub_urls:
                    if u not in raw_urls_set:
                        raw_urls_set.add(u)
                        raw_urls.append(u)
            except Exception as e:
                result.errors.append(f"wayback/{sub.host}: {e}")

    except Exception as e:
        result.source_stats["wayback"] = False
        result.errors.append(f"wayback/{base}: {e}")
        console.print(f"    [yellow]✗[/yellow] wayback/{base}: {e}")

    scoped: list[str] = []
    for url in raw_urls:
        try:
            h = urlparse(url).netloc.lower().strip()
            if h and matches_scope(h, scope_patterns):
                scoped.append(url)
        except Exception:
            pass
    base_result.raw_urls = scoped

    base_result.interesting_urls = find_interesting_urls(base_result.raw_urls)
    base_result.tech_stack = fingerprint_tech(base_result.raw_urls)
    base_result.parameters = mine_parameters(base_result.raw_urls)

    dns_verified = sum(1 for s in base_result.subdomains if s.dns.resolved)
    takeovers = sum(1 for s in base_result.subdomains if s.takeover_candidate)
    console.print(
        f"  [bold green]✓[/bold green] {base}: "
        f"{len(base_result.subdomains)} subs ({dns_verified} DNS-verified), "
        f"{len(base_result.interesting_urls)} interesting, "
        f"{takeovers} takeover candidates"
    )

    return base_result


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Passive recon for bug bounty programs (no direct target requests)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--file", "-f", required=True, help="Targets file (one per line)")
    parser.add_argument("--name", "-n", default="", help="Program name (used in output filename)")
    parser.add_argument("--output", "-o", default="reports/", help="Output directory")
    parser.add_argument(
        "--wayback-limit",
        type=int,
        default=50000,
        help="Max Wayback URLs per base domain (default: 50000)",
    )
    parser.add_argument("--no-cache", action="store_true", help="Bypass filesystem cache")
    args = parser.parse_args()

    target_file = Path(args.file)
    if not target_file.exists():
        console.print(f"[red][!] Targets file not found: {args.file}[/red]")
        sys.exit(1)

    lines = target_file.read_text(encoding="utf-8").splitlines()
    scope_patterns = parse_targets(lines)

    if not scope_patterns:
        console.print("[red][!] No valid in-scope targets found in file[/red]")
        sys.exit(1)

    bases = get_query_bases(scope_patterns)

    console.print(f"[bold green]Passive Recon v{VERSION}[/bold green]")
    console.print(f"Program:  {args.name or '(unnamed)'}")
    console.print(f"Scope:    {', '.join(scope_patterns)}")
    console.print(f"Bases:    {', '.join(bases)}")
    console.print()

    cache = Cache(Path(".cache"), ttl_hours=24)
    if args.no_cache:
        cache.enabled = False
        console.print("[yellow]Cache disabled[/yellow]\n")

    run_id = uuid.uuid4().hex[:8]
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = ReconResult(
        version=VERSION,
        generated_at=generated_at,
        scope=scope_patterns,
        program_name=args.name,
        run_id=run_id,
    )

    takeover_fingerprints = load_fingerprints()
    dns_sem = asyncio.Semaphore(20)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0),
        headers={"User-Agent": f"passive-recon/{VERSION} (security-research)"},
        follow_redirects=True,
    ) as client:
        for base in bases:
            console.print(f"[cyan][*] Processing: {base}[/cyan]")
            base_result = await process_base(
                client=client,
                base=base,
                scope_patterns=scope_patterns,
                wayback_limit=args.wayback_limit,
                cache=cache,
                dns_sem=dns_sem,
                takeover_fingerprints=takeover_fingerprints,
                result=result,
            )
            result.bases.append(base_result)
            console.print()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    slug = (
        args.name.lower().replace(" ", "-").replace("/", "-")
        if args.name
        else run_id
    )
    md_path = output_dir / f"{date_str}-{slug}.md"
    json_path = output_dir / f"{date_str}-{slug}.json"

    md_path.write_text(render_markdown(result), encoding="utf-8")
    json_path.write_text(render_json(result), encoding="utf-8")

    total_subs = sum(len(b.subdomains) for b in result.bases)
    total_dns = sum(
        sum(1 for s in b.subdomains if s.dns.resolved) for b in result.bases
    )
    total_interesting = sum(len(b.interesting_urls) for b in result.bases)
    total_takeovers = sum(
        sum(1 for s in b.subdomains if s.takeover_candidate) for b in result.bases
    )
    sources_ok = sum(1 for v in result.source_stats.values() if v)

    console.print("[bold green]Done![/bold green]")
    console.print(f"  Markdown:  {md_path}")
    console.print(f"  JSON:      {json_path}")
    console.print()
    console.print(f"  Subdomains in scope:   {total_subs}")
    console.print(f"  DNS verified:          {total_dns}")
    console.print(f"  Interesting URLs:      {total_interesting}")
    console.print(f"  Takeover candidates:   {total_takeovers}")
    console.print(f"  Sources OK:            {sources_ok}/{len(result.source_stats)}")
    if result.errors:
        console.print(f"  [yellow]Errors: {len(result.errors)}[/yellow]")
        for err in result.errors[:5]:
            console.print(f"    [dim]{err}[/dim]")


if __name__ == "__main__":
    asyncio.run(main())
