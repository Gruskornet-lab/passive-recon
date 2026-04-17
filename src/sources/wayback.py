import httpx


async def query_wayback(
    client: httpx.AsyncClient, base: str, limit: int = 50000
) -> list[str]:
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{base}&matchType=domain&output=json"
        f"&collapse=urlkey&fl=original&limit={limit}"
    )
    resp = await client.get(url, timeout=httpx.Timeout(120.0))
    resp.raise_for_status()
    data = resp.json()
    if not data or len(data) < 2:
        return []
    return [row[0] for row in data[1:] if row and row[0]]
