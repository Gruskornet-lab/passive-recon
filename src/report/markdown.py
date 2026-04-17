from src.models import ReconResult, InterestingURL


def render_markdown(result: ReconResult) -> str:
    L: list[str] = []
    program = result.program_name or "Unknown Program"

    L += [
        f"# Passive Recon-rapport — {program}",
        "",
        f"**Datum:** {result.generated_at}",
        f"**Genererad av:** passive-recon v{result.version}",
        f"**Körning:** {result.run_id}",
        "",
        "## Scope",
        "",
        "Följande in-scope patterns användes:",
    ]
    for p in result.scope:
        L.append(f"- `{p}`")
    L.append("")

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
    sources_ok = sum(1 for v in result.source_stats.values() if v)
    sources_total = len(result.source_stats)

    L += [
        "## Exekutiv sammanfattning",
        "",
        "| Metrik | Värde |",
        "|---|---|",
        f"| Base-domäner undersökta | {len(result.bases)} |",
        f"| Subdomäner upptäckta (totalt) | {total_disc} |",
        f"| Subdomäner in-scope | {total_scope} |",
        f"| Subdomäner DNS-verifierade | {total_dns} |",
        f"| Historiska URLs (totalt) | {total_urls:,} |",
        f"| Intressanta endpoints | {total_interesting} |",
        f"| Potentiella takeover-kandidater | {total_takeovers} |",
        f"| Datakällor som svarade | {sources_ok}/{sources_total} |",
        "",
        "### Prioriterade quick wins",
        "",
    ]

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
            if iu.category in ("sensitive-file", "exposed-git", "exposed-env"):
                quick_wins.append(
                    f"⚠️ **{iu.category}:** [`{iu.url[:80]}`]({iu.wayback_link}) — {iu.reason}"
                )
    for b in result.bases:
        for iu in b.interesting_urls:
            if iu.category == "admin-panel":
                quick_wins.append(
                    f"🔑 **Admin panel:** [`{iu.url[:80]}`]({iu.wayback_link})"
                )
    for b in result.bases:
        for iu in b.interesting_urls:
            if iu.category in ("idor", "redirect", "lfi"):
                quick_wins.append(
                    f"🔍 **{iu.category.upper()}:** [`{iu.url[:80]}`]({iu.wayback_link}) — {iu.reason}"
                )

    if quick_wins:
        for qw in quick_wins[:10]:
            L.append(f"- {qw}")
    else:
        L.append("_Inga högt prioriterade fynd._")
    L.append("")

    L += ["## Per base-domän", ""]

    for b in result.bases:
        L += [f"### `{b.base}`", ""]

        L += ["#### Bekräftade subdomäner", ""]
        if b.subdomains:
            L.append("| Subdomän | A | CNAME | DNS | Källor |")
            L.append("|---|---|---|---|---|")
            for s in sorted(b.subdomains, key=lambda x: x.host):
                a = ", ".join(s.dns.a[:2]) if s.dns.a else "—"
                cname = ", ".join(s.dns.cname) if s.dns.cname else "—"
                dns_ok = "✓" if s.dns.resolved else "—"
                sources = ", ".join(s.sources) if s.sources else "—"
                L.append(f"| `{s.host}` | {a} | {cname} | {dns_ok} | {sources} |")
        else:
            L.append("_Inga subdomäner hittades._")
        L.append("")

        takeover_subs = [s for s in b.subdomains if s.takeover_candidate]
        if takeover_subs:
            L += [
                "#### Takeover-kandidater",
                "",
                "| Subdomän | CNAME-mål | Tjänst | Notering |",
                "|---|---|---|---|",
            ]
            for s in takeover_subs:
                tc = s.takeover_candidate
                L.append(
                    f"| `{s.host}` | `{tc.cname_target}` | {tc.service} | {tc.notes} |"
                )
            L += [
                "",
                "> ⚠️ Dessa är **kandidater** — inte bekräftade takeovers. Manuell verifiering krävs.",
                "",
            ]

        L += ["#### DNS-insikter", ""]
        mx_all: set[str] = set()
        txt_all: set[str] = set()
        ns_all: set[str] = set()
        for s in b.subdomains:
            mx_all.update(s.dns.mx)
            txt_all.update(s.dns.txt)
            ns_all.update(s.dns.ns)

        if mx_all:
            L.append("**MX (mail-infrastruktur):**")
            for mx in sorted(mx_all):
                L.append(f"- `{mx}`")
        if txt_all:
            L.append("")
            L.append("**TXT (SPF, DKIM, SaaS-integrationer):**")
            for txt in sorted(txt_all)[:20]:
                short = txt[:120] + ("..." if len(txt) > 120 else "")
                L.append(f"- `{short}`")
        if ns_all:
            L.append("")
            L.append("**NS (auktoritativa namnservrar):**")
            for ns in sorted(ns_all):
                L.append(f"- `{ns}`")
        if not (mx_all or txt_all or ns_all):
            L.append("_Inga DNS-insikter._")
        L.append("")

        L += ["#### Intressanta historiska endpoints", ""]
        if b.interesting_urls:
            by_host: dict[str, list[InterestingURL]] = {}
            for iu in b.interesting_urls:
                by_host.setdefault(iu.host, []).append(iu)
            for host, urls in sorted(by_host.items()):
                L.append(
                    f"<details><summary><strong><code>{host}</code></strong> ({len(urls)} URLs)</summary>"
                )
                L.append("")
                for iu in urls[:50]:
                    L.append(
                        f"- [`{iu.url[:100]}`]({iu.wayback_link}) — {iu.reason}"
                    )
                if len(urls) > 50:
                    L.append(f"- _(+ {len(urls) - 50} till)_")
                L += ["", "</details>", ""]
        else:
            L.append("_Inga intressanta endpoints hittades._")
            L.append("")

        if b.tech_stack:
            L += ["#### Teknisk stack (från URL-patterns)", ""]
            for ts in b.tech_stack:
                L.append(f"**{ts.tech}**")
                for ev in ts.evidence_urls[:2]:
                    L.append(f"  - `{ev[:100]}`")
            L.append("")

        if b.parameters:
            p = b.parameters
            has = any([p.idor, p.redirect_ssrf, p.lfi, p.cmd_injection, p.secrets, p.xss])
            if has:
                L += ["#### Mining av parametrar", ""]
                if p.idor:
                    L.append(
                        f"**IDOR-kandidater:** {', '.join(f'`{x}`' for x in sorted(p.idor))}"
                    )
                if p.redirect_ssrf:
                    L.append(
                        f"**Open redirect / SSRF:** {', '.join(f'`{x}`' for x in sorted(p.redirect_ssrf))}"
                    )
                if p.lfi:
                    L.append(
                        f"**LFI / Path traversal:** {', '.join(f'`{x}`' for x in sorted(p.lfi))}"
                    )
                if p.cmd_injection:
                    L.append(
                        f"**Cmd injection:** {', '.join(f'`{x}`' for x in sorted(p.cmd_injection))}"
                    )
                if p.secrets:
                    L.append(
                        f"**Secrets (dataläckor):** {', '.join(f'`{x}`' for x in sorted(p.secrets))}"
                    )
                if p.xss:
                    L.append(
                        f"**XSS-kontext:** {', '.join(f'`{x}`' for x in sorted(p.xss))}"
                    )
                L.append("")

        if b.out_of_scope:
            deduped = sorted(set(b.out_of_scope))
            L += [
                "#### Filtrerade bort (utanför scope)",
                "",
                "<details><summary>Visa filtrerade hosts</summary>",
                "",
            ]
            for h in deduped[:100]:
                L.append(f"- `{h}`")
            if len(deduped) > 100:
                L.append(f"- _(+ {len(deduped) - 100} till)_")
            L += ["", "</details>", ""]

    L += [
        "## Metodik",
        "",
        "Passiv recon utförd med följande datakällor:",
        "",
        "| Källa | Status |",
        "|---|---|",
    ]
    for source, ok in sorted(result.source_stats.items()):
        L.append(f"| {source} | {'✓ OK' if ok else '✗ Fel'} |")
    L += [
        "",
        "**DNS-resolvers:** Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9)",
        "",
        "Inga requests skickades direkt till target-domänerna.",
        "",
    ]

    if result.errors:
        L += ["## Fel och varningar", ""]
        for err in result.errors:
            L.append(f"- `{err}`")
        L.append("")

    L += [
        "---",
        f"_Rapport genererad {result.generated_at}. "
        "Alla datakällor är publika. "
        "Inga requests skickades direkt till targeten._",
    ]

    return "\n".join(L)
