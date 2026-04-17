import re

import httpx


async def query_rapiddns(client: httpx.AsyncClient, base: str) -> set[str]:
    url = f"https://rapiddns.io/subdomain/{base}?full=1"
    resp = await client.get(url, timeout=30)
    resp.raise_for_status()
    pattern = re.compile(r"(?:[\w\-]+\.)*" + re.escape(base), re.IGNORECASE)
    return {m.lower() for m in pattern.findall(resp.text)}
