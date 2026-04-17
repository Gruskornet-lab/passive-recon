import json

from src.models import ReconResult


def render_json(result: ReconResult) -> str:
    bases_data = []
    for b in result.bases:
        subs = []
        for s in b.subdomains:
            sub_data: dict = {
                "host": s.host,
                "dns": {
                    "a": s.dns.a,
                    "aaaa": s.dns.aaaa,
                    "cname": s.dns.cname,
                    "mx": s.dns.mx,
                    "txt": s.dns.txt,
                    "ns": s.dns.ns,
                    "resolved": s.dns.resolved,
                },
                "sources": s.sources,
                "takeover_candidate": None,
            }
            if s.takeover_candidate:
                tc = s.takeover_candidate
                sub_data["takeover_candidate"] = {
                    "cname_target": tc.cname_target,
                    "service": tc.service,
                    "notes": tc.notes,
                }
            subs.append(sub_data)

        params = None
        if b.parameters:
            p = b.parameters
            params = {
                "idor": p.idor,
                "redirect_ssrf": p.redirect_ssrf,
                "lfi": p.lfi,
                "cmd_injection": p.cmd_injection,
                "secrets": p.secrets,
                "xss": p.xss,
                "other": p.other[:50],
            }

        bases_data.append(
            {
                "base": b.base,
                "subdomains": subs,
                "interesting_urls": [
                    {
                        "url": iu.url,
                        "host": iu.host,
                        "reason": iu.reason,
                        "wayback_link": iu.wayback_link,
                        "category": iu.category,
                    }
                    for iu in b.interesting_urls
                ],
                "out_of_scope": sorted(set(b.out_of_scope)),
                "tech_stack": [
                    {"tech": ts.tech, "evidence": ts.evidence_urls}
                    for ts in b.tech_stack
                ],
                "parameters": params,
            }
        )

    total_scope = sum(len(b.subdomains) for b in result.bases)
    data = {
        "version": result.version,
        "generated_at": result.generated_at,
        "program_name": result.program_name,
        "run_id": result.run_id,
        "scope": result.scope,
        "bases": bases_data,
        "stats": {
            "bases_count": len(result.bases),
            "subdomains_in_scope": total_scope,
            "subdomains_dns_verified": sum(
                sum(1 for s in b.subdomains if s.dns.resolved) for b in result.bases
            ),
            "interesting_urls": sum(len(b.interesting_urls) for b in result.bases),
            "takeover_candidates": sum(
                sum(1 for s in b.subdomains if s.takeover_candidate)
                for b in result.bases
            ),
            "sources": result.source_stats,
        },
        "errors": result.errors,
    }

    return json.dumps(data, indent=2, ensure_ascii=False)
