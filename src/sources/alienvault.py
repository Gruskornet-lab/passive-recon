import httpx


async def query_alienvault(client: httpx.AsyncClient, base: str) -> set[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{base}/passive_dns"
    resp = await client.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    results: set[str] = set()
    for record in data.get("passive_dns", []):
        hostname = record.get("hostname", "").lower().strip()
        if hostname:
            results.add(hostname)
    return results
