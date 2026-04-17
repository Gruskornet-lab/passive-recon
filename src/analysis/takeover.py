import json
from pathlib import Path
from typing import Optional

from src.models import Subdomain, TakeoverCandidate

_FINGERPRINTS_PATH = Path(__file__).parent.parent.parent / "takeover_fingerprints.json"

_VULNERABLE_STATUSES = {"vulnerable", "edge case"}


def load_fingerprints() -> list[dict]:
    if not _FINGERPRINTS_PATH.exists():
        return []
    try:
        return json.loads(_FINGERPRINTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


def check_takeover_candidates(
    sub: Subdomain, fingerprints: list[dict]
) -> Optional[TakeoverCandidate]:
    if not sub.dns.cname:
        return None

    for cname in sub.dns.cname:
        cname_lower = cname.lower()
        for fp in fingerprints:
            if fp.get("status", "").lower() not in _VULNERABLE_STATUSES:
                continue
            for cname_pattern in fp.get("cname", []):
                suffix = cname_pattern.lower().lstrip("*")
                if cname_lower == suffix.lstrip(".") or cname_lower.endswith(suffix):
                    return TakeoverCandidate(
                        host=sub.host,
                        cname_target=cname,
                        service=fp.get("service", "Unknown"),
                        notes=fp.get("notes", ""),
                    )

    return None
