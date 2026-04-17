import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver

from src.models import DNSRecord

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

_RECORD_TYPES = [
    ("A", "a"),
    ("AAAA", "aaaa"),
    ("CNAME", "cname"),
    ("MX", "mx"),
    ("TXT", "txt"),
    ("NS", "ns"),
]


def _make_resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.nameservers = RESOLVERS
    r.timeout = 5.0
    r.lifetime = 10.0
    return r


async def resolve_host(host: str, sem: asyncio.Semaphore) -> DNSRecord:
    record = DNSRecord()
    resolver = _make_resolver()

    async with sem:
        for rtype, attr in _RECORD_TYPES:
            try:
                answers = await resolver.resolve(host, rtype)
                values: list[str] = []
                if rtype == "A":
                    values = [r.address for r in answers]
                elif rtype == "AAAA":
                    values = [r.address for r in answers]
                elif rtype == "CNAME":
                    values = [str(r.target).rstrip(".") for r in answers]
                elif rtype == "MX":
                    values = [str(r.exchange).rstrip(".") for r in answers]
                elif rtype == "TXT":
                    values = [
                        b"".join(r.strings).decode("utf-8", errors="replace")
                        for r in answers
                    ]
                elif rtype == "NS":
                    values = [str(r.target).rstrip(".") for r in answers]
                if values:
                    setattr(record, attr, values)
                    record.resolved = True
            except (
                dns.exception.DNSException,
                dns.resolver.NoNameservers,
                Exception,
            ):
                pass

    return record


async def resolve_all(
    hosts: list[str], sem: asyncio.Semaphore
) -> dict[str, DNSRecord]:
    tasks = [asyncio.create_task(resolve_host(h, sem)) for h in hosts]
    records = await asyncio.gather(*tasks, return_exceptions=True)
    return {
        host: (rec if not isinstance(rec, Exception) else DNSRecord())
        for host, rec in zip(hosts, records)
    }
