from src.models import ReconResult, BaseResult, Subdomain, InterestingURL


def _dns_badge(sub: Subdomain) -> str:
    if sub.takeover_candidate:
        return "🚨 TAKEOVER?"
    if sub.dns.resolved:
        return "✅ Live"
    return "❌ Dead / No DNS"


def _category_icon(category: str) -> str:
    return {
        "takeover": "🚨",
        "sensitive-file": "🔴",
        "exposed-git": "🔴",
        "exposed-env": "🔴",
        "backup": "🔴",
        "admin-panel": "🟠",
        "phpmyadmin": "🟠",
        "debug": "🟠",
        "openapi": "🟡",
        "graphql": "🟡",
        "spring-actuator": "🟡",
        "wordpress-admin": "🟠",
        "idor": "🟡",
        "redirect": "🟡",
        "lfi": "🟡",
        "secrets": "🔴",
    }.get(category, "🔵")


def render_markdown(result: ReconResult) -> str:
    L: list[str] = []
    program = result.program_name or "Unknown Program"

    # ── Header ────────────────────────────────────────────────────────────────
    L += [
        f"# Passive Recon — {program}",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Datum** | {result.generated_at} |",
        f"| **Program** | {program} |",
        f"| **Körning** | `{result.run_id}` |",
        f"| **Verktyg** | passive-recon v{result.version} |",
        "",
        "---",
        "",
    ]

    # ── Scope-tabell ──────────────────────────────────────────────────────────
    # Bygg en flat dict: host → Subdomain för snabb lookup
    all_subs: dict[str, Subdomain] = {}
    for b in result.bases:
        for s in b.subdomains:
            all_subs[s.host] = s

    L += ["## Scope & Status", ""]
    L.append("| Target | Status | IP | CNAME |")
    L.append("|---|---|---|---|")
    for pattern in result.scope:
        host = pattern.lstrip("*.")
        sub = all_subs.get(host)
        if sub:
            badge = _dns_badge(sub)
            ip = ", ".join(sub.dns.a[:2]) if sub.dns.a else "—"
            cname = ", ".join(sub.dns.cname) if sub.dns.cname else "—"
        else:
            badge = "❓ Ej hittad"
            ip = "—"
            cname = "—"
        L.append(f"| `{pattern}` | {badge} | {ip} | {cname} |")
    L += ["", "---", ""]

    # ── Exekutiv sammanfattning ────────────────────────────────────────────────
    total_disc = sum(len(b.subdomains) + len(b.out_of_scope) for b in result.bases)
    total_scope = sum(len(b.subdomains) for b in result.bases)
    total_dns = sum(
        sum(1 for s in b.subdomains if s.dns.resolved) for b in result.bases
    )
    total_urls = sum(len(b.raw_urls) for b in result.bases)
    total_interesting = sum(len(b.interesting_urls) for b in result.bases)
    total_takeovers = sum(
        sum(1 for s in b.subdomains if s.takeover_candidate) for b in result.bases
    )
    total_oos = sum(len(set(b.out_of_scope)) for b in result.bases)
    sources_ok = sum(1 for v in result.source_stats.values() if v)
    sources_total = len(result.source_stats)

    L += [
        "## Sammanfattning",
        "",
        "| Metrik | Värde |",
        "|---|---|",
        f"| In-scope targets | {total_scope} |",
        f"| DNS-verifierade (live) | {total_dns} |",
        f"| Subdomäner totalt hittade | {total_disc} |",
        f"| Varav utanför scope | {total_oos} |",
        f"| Historiska URLs analyserade | {total_urls:,} |",
        f"| Intressanta endpoints | {total_interesting} |",
        f"| Takeover-kandidater | {total_takeovers} |",
        f"| Datakällor som svarade | {sources_ok}/{sources_total} |",
        "",
    ]

    # ── Quick wins ────────────────────────────────────────────────────────────
    L += ["### 🎯 Quick Wins", ""]
    quick_wins: list[str] = []

    for b in result.bases:
        for s in b.subdomains:
            if s.takeover_candidate:
                tc = s.takeover_candidate
                quick_wins.append(
                    f"🚨 **Takeover-kandidat:** `{s.host}` → `{tc.cname_target}` ({tc.service})"
                )
    for b in result.bases:
        for iu in b.interesting_urls:
            if iu.category in ("sensitive-file", "exposed-git", "exposed-env", "secrets", "backup"):
                quick_wins.append(
                    f"🔴 **{iu.category}** på `{iu.host}`: "
                    f"[`{iu.url[:70]}`]({iu.wayback_link})"
                )
    for b in result.bases:
        for iu in b.interesting_urls:
            if iu.category in ("admin-panel", "phpmyadmin", "debug"):
                quick_wins.append(
                    f"🟠 **{iu.category}** på `{iu.host}`: "
                    f"[`{iu.url[:70]}`]({iu.wayback_link})"
                )
    for b in result.bases:
        for iu in b.interesting_urls:
            if iu.category in ("idor", "redirect", "lfi", "openapi", "graphql"):
                quick_wins.append(
                    f"🟡 **{iu.category}** på `{iu.host}`: "
                    f"[`{iu.url[:70]}`]({iu.wayback_link}) — {iu.reason}"
                )

    if quick_wins:
        for qw in quick_wins[:15]:
            L.append(f"- {qw}")
    else:
        L.append("_Inga högt prioriterade fynd._")
    L += ["", "---", ""]

    # ── Per scope-target ──────────────────────────────────────────────────────
    L += ["## In-Scope Targets", ""]

    # Bygg lookup: host → interesting URLs (från rätt bas)
    host_to_urls: dict[str, list[InterestingURL]] = {}
    for b in result.bases:
        for iu in b.interesting_urls:
            host_to_urls.setdefault(iu.host, []).append(iu)

    # Bygg lookup: host → bas
    host_to_base: dict[str, BaseResult] = {}
    for b in result.bases:
        for s in b.subdomains:
            host_to_base[s.host] = b

    for pattern in result.scope:
        host = pattern.lstrip("*.")
        sub = all_subs.get(host)

        if sub:
            badge = _dns_badge(sub)
        else:
            badge = "❓ Ej hittad"

        L += [f"### `{pattern}` — {badge}", ""]

        if not sub:
            L += [
                "> ❓ Hosten matchade scopet men hittades inte i någon datakälla.",
                "",
            ]
            continue

        # DNS-block
        L.append("**DNS:**")
        if sub.dns.a:
            L.append(f"- A: `{', '.join(sub.dns.a)}`")
        if sub.dns.aaaa:
            L.append(f"- AAAA: `{', '.join(sub.dns.aaaa)}`")
        if sub.dns.cname:
            L.append(f"- CNAME: `{', '.join(sub.dns.cname)}`")
        if sub.dns.mx:
            L.append(f"- MX: `{', '.join(sub.dns.mx)}`")
        if sub.dns.ns:
            L.append(f"- NS: `{', '.join(sub.dns.ns)}`")
        if sub.dns.txt:
            L.append("- TXT:")
            for txt in sub.dns.txt[:5]:
                short = txt[:120] + ("..." if len(txt) > 120 else "")
                L.append(f"  - `{short}`")
        if not sub.dns.resolved:
            L.append("- _Ingen DNS-respons_")

        if sub.sources:
            L.append(f"\n**Hittad via:** {', '.join(sub.sources)}")
        L.append("")

        # Takeover
        if sub.takeover_candidate:
            tc = sub.takeover_candidate
            L += [
                "#### 🚨 Takeover-kandidat",
                "",
                f"| Fält | Värde |",
                f"|---|---|",
                f"| CNAME pekar på | `{tc.cname_target}` |",
                f"| Sårbar tjänst | {tc.service} |",
                f"| Notering | {tc.notes} |",
                "",
                "> Manuell verifiering krävs — detta är en **kandidat**, inte en bekräftad takeover.",
                "",
            ]

        # Intressanta endpoints för denna host
        urls_for_host = host_to_urls.get(host, [])
        if urls_for_host:
            L += [f"#### Intressanta endpoints ({len(urls_for_host)})", ""]
            for iu in urls_for_host[:50]:
                icon = _category_icon(iu.category)
                L.append(
                    f"- {icon} `{iu.category}` — "
                    f"[`{iu.url[:90]}`]({iu.wayback_link})  \n"
                    f"  _{iu.reason}_"
                )
            if len(urls_for_host) > 50:
                L.append(f"- _(+ {len(urls_for_host) - 50} till)_")
            L.append("")

        # Tech stack för denna host
        base_obj = host_to_base.get(host)
        if base_obj and base_obj.tech_stack:
            tech_for_host = [
                ts for ts in base_obj.tech_stack
                if any(host in ev for ev in ts.evidence_urls)
            ]
            if tech_for_host:
                L.append("#### Teknisk stack")
                L.append("")
                for ts in tech_for_host:
                    ev_urls = [ev for ev in ts.evidence_urls if host in ev]
                    L.append(f"- **{ts.tech}**")
                    for ev in ev_urls[:2]:
                        L.append(f"  - `{ev[:100]}`")
                L.append("")

        L.append("---")
        L.append("")

    # ── Parameter mining (aggregerat) ─────────────────────────────────────────
    has_params = any(
        b.parameters and any([
            b.parameters.idor, b.parameters.redirect_ssrf,
            b.parameters.lfi, b.parameters.cmd_injection,
            b.parameters.secrets, b.parameters.xss,
        ])
        for b in result.bases
    )
    if has_params:
        L += ["## Parameter Mining", ""]
        L.append("Parametrar observerade i historiska URLs, grupperade efter risknivå:")
        L.append("")

        all_idor: set[str] = set()
        all_redirect: set[str] = set()
        all_lfi: set[str] = set()
        all_cmd: set[str] = set()
        all_secrets: set[str] = set()
        all_xss: set[str] = set()
        for b in result.bases:
            if b.parameters:
                all_idor.update(b.parameters.idor)
                all_redirect.update(b.parameters.redirect_ssrf)
                all_lfi.update(b.parameters.lfi)
                all_cmd.update(b.parameters.cmd_injection)
                all_secrets.update(b.parameters.secrets)
                all_xss.update(b.parameters.xss)

        if all_idor:
            L.append(f"🟡 **IDOR:** {', '.join(f'`{x}`' for x in sorted(all_idor))}")
        if all_redirect:
            L.append(f"🟡 **Open redirect / SSRF:** {', '.join(f'`{x}`' for x in sorted(all_redirect))}")
        if all_lfi:
            L.append(f"🟡 **LFI / Path traversal:** {', '.join(f'`{x}`' for x in sorted(all_lfi))}")
        if all_cmd:
            L.append(f"🟠 **Cmd injection:** {', '.join(f'`{x}`' for x in sorted(all_cmd))}")
        if all_secrets:
            L.append(f"🔴 **Secrets i URL:** {', '.join(f'`{x}`' for x in sorted(all_secrets))}")
        if all_xss:
            L.append(f"🔵 **XSS-kontext:** {', '.join(f'`{x}`' for x in sorted(all_xss))}")
        L += ["", "---", ""]

    # ── Övriga fynd utanför scope ──────────────────────────────────────────────
    all_oos: list[str] = []
    for b in result.bases:
        all_oos.extend(b.out_of_scope)
    deduped_oos = sorted(set(all_oos))

    if deduped_oos:
        L += [
            "## Övriga fynd (utanför scope)",
            "",
            f"Hittades under recon men matchar inte in-scope patterns ({len(deduped_oos)} hosts).",
            "Kan indikera okänd infrastruktur — kontrollera om scope bör utökas.",
            "",
            "<details><summary>Visa alla utanför scope</summary>",
            "",
        ]
        for h in deduped_oos[:150]:
            L.append(f"- `{h}`")
        if len(deduped_oos) > 150:
            L.append(f"- _(+ {len(deduped_oos) - 150} till)_")
        L += ["", "</details>", "", "---", ""]

    # ── Metodik ───────────────────────────────────────────────────────────────
    L += [
        "## Metodik",
        "",
        "| Datakälla | Status |",
        "|---|---|",
    ]
    for source, ok in sorted(result.source_stats.items()):
        L.append(f"| {source} | {'✅ OK' if ok else '❌ Fel'} |")
    L += [
        "",
        "**DNS-resolvers:** Cloudflare 1.1.1.1 · Google 8.8.8.8 · Quad9 9.9.9.9",
        "",
        "Inga requests skickades direkt till target-domänerna under recon.",
        "",
    ]

    if result.errors:
        L += ["## Fel och varningar", ""]
        for err in result.errors:
            L.append(f"- `{err}`")
        L.append("")

    L += [
        "---",
        f"_Rapport genererad {result.generated_at} · passive-recon v{result.version} · "
        "Alla datakällor är publika · Inga direkta requests till targeten_",
    ]

    return "\n".join(L)