from urllib.parse import urlparse

_DANGEROUS_BROAD = {
    "*.com", "*.net", "*.org", "*.io", "*.co", "*.se", "*.de",
    "*.uk", "*.us", "*.ca", "*.au", "*.fr", "*.nl",
}


def matches_scope(host: str, scope_patterns: list[str]) -> bool:
    host = host.lower().strip().rstrip(".")
    if not host:
        return False
    for pattern in scope_patterns:
        pattern = pattern.lower().strip()
        if pattern.startswith("*."):
            base = pattern[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == pattern:
            return True
    return False


def parse_targets(lines: list[str]) -> list[str]:
    results: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line[: line.index("#")].strip()
        if not line:
            continue
        if "://" in line:
            parsed = urlparse(line)
            line = parsed.netloc or parsed.path
        if ":" in line and not line.startswith("*."):
            line = line.split(":")[0]
        line = line.split("/")[0].lower().strip()
        if not line:
            continue
        if " " in line:
            continue
        if "." not in line:
            continue
        if line in _DANGEROUS_BROAD:
            continue
        if line.startswith("*.") and line.count(".") == 1:
            continue
        results.add(line)
    return sorted(results)


def get_query_bases(targets: list[str]) -> list[str]:
    bases: set[str] = set()
    for target in targets:
        if target.startswith("*."):
            bases.add(target[2:])
        else:
            parts = target.split(".")
            if len(parts) >= 2:
                bases.add(".".join(parts[-2:]))
    return sorted(bases)
