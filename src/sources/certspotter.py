import httpx


async def query_certspotter(client: httpx.AsyncClient, base: str) -> set[str]:
    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={base}&include_subdomains=true&expand=dns_names"
    )
    resp = await client.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    results: set[str] = set()
    for cert in data:
        for name in cert.get("dns_names", []):
            name = name.lower().strip().lstrip("*.")
            if name:
                results.add(name)
    return results
