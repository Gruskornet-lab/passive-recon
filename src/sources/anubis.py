import httpx


async def query_anubis(client: httpx.AsyncClient, base: str) -> set[str]:
    url = f"https://jldc.me/anubis/subdomains/{base}"
    resp = await client.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {h.lower().strip() for h in data if isinstance(h, str) and h.strip()}
