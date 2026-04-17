import httpx


async def query_hackertarget(client: httpx.AsyncClient, base: str) -> set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={base}"
    resp = await client.get(url, timeout=30)
    if resp.status_code == 429:
        raise Exception("HackerTarget rate limit reached (100 requests/day free tier)")
    resp.raise_for_status()
    results: set[str] = set()
    for line in resp.text.splitlines():
        if "," in line:
            host = line.split(",")[0].strip().lower()
            if host:
                results.add(host)
    return results
