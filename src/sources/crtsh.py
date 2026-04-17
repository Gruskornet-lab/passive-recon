import asyncio
import sys

import httpx


async def _query_crtsh(client: httpx.AsyncClient, base: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{base}&output=json"
    resp = await client.get(url, timeout=httpx.Timeout(60.0))
    resp.raise_for_status()
    data = resp.json()
    results: set[str] = set()
    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.lower().strip().lstrip("*.")
            if name:
                results.add(name)
    return results


async def query_crtsh_with_retry(
    client: httpx.AsyncClient, base: str, max_attempts: int = 3
) -> set[str]:
    for attempt in range(max_attempts):
        try:
            return await _query_crtsh(client, base)
        except (httpx.TimeoutException, httpx.HTTPError) as e:
            if attempt == max_attempts - 1:
                raise
            wait = 2**attempt
            print(
                f"[!] crt.sh retry {attempt + 1}/{max_attempts} in {wait}s: {e}",
                file=sys.stderr,
            )
            await asyncio.sleep(wait)
    return set()
