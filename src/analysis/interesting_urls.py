from urllib.parse import urlparse, parse_qs, urlencode

from src.models import InterestingURL

SENSITIVE_EXTENSIONS = {
    ".sql", ".bak", ".backup", ".zip", ".tar", ".gz", ".tgz",
    ".env", ".config", ".conf", ".xml", ".csv", ".db", ".sqlite",
    ".key", ".pem", ".crt", ".p12", ".pfx", ".log", ".dump",
    ".DS_Store", ".htpasswd", ".htaccess", ".ovpn",
}

_INTERESTING_PATHS: list[tuple[str, str]] = [
    ("/.git/", "exposed-git"),
    ("/.env", "exposed-env"),
    ("/backup", "backup"),
    ("/phpmyadmin", "phpmyadmin"),
    ("/pma/", "phpmyadmin"),
    ("/admin", "admin-panel"),
    ("/administrator", "admin-panel"),
    ("/graphql", "graphql"),
    ("/graphiql", "graphql"),
    ("/swagger", "openapi"),
    ("/api-docs", "openapi"),
    ("/openapi.json", "openapi"),
    ("/openapi.yaml", "openapi"),
    ("/actuator", "spring-actuator"),
    ("/spring-boot", "spring-actuator"),
    ("/wp-admin", "wordpress-admin"),
    ("/wp-json", "wordpress-api"),
    ("/xmlrpc.php", "wordpress-xmlrpc"),
    ("/.DS_Store", "exposed-dsstore"),
    ("/.htaccess", "exposed-htaccess"),
    ("/.htpasswd", "exposed-htpasswd"),
    ("/server-status", "apache-status"),
    ("/server-info", "apache-info"),
    ("/debug", "debug"),
    ("/__debug__", "debug"),
    ("/console", "debug-console"),
    ("/.idea/", "exposed-ide"),
    ("/.vscode/", "exposed-ide"),
    ("/user/login?destination=", "drupal-redirect"),
    ("/sites/default/", "drupal"),
    ("/jenkins", "jenkins"),
    ("/jira", "jira"),
    ("/confluence", "confluence"),
]

SENSITIVE_PARAMS = {
    "token", "auth", "authorization", "api_key", "apikey", "key",
    "secret", "session", "sessionid", "jwt", "access_token",
    "refresh_token", "csrf", "csrfmiddlewaretoken", "password", "passwd",
}

IDOR_PARAMS = {
    "id", "user", "user_id", "userid", "uid", "account", "account_id",
    "order", "order_id", "invoice", "invoice_id", "ticket", "doc",
    "doc_id", "document", "document_id", "record", "record_id",
    "profile", "profile_id", "customer", "customer_id", "org", "org_id",
    "team_id", "project_id", "file_id",
}

REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "redir", "return",
    "returnurl", "return_url", "returnto", "next", "continue",
    "dest", "destination", "url", "u", "callback", "jsonp", "go",
    "to", "link", "site", "target", "image_url", "image", "imgurl",
}

LFI_PARAMS = {
    "file", "path", "filename", "filepath", "download", "load",
    "include", "template", "module", "folder", "dir",
}


def _wayback_link(url: str) -> str:
    return f"https://web.archive.org/web/*/{url}"


def redact_sensitive_params(url: str) -> str:
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        params = parse_qs(parsed.query, keep_blank_values=True)
        modified = False
        for key in list(params.keys()):
            if key.lower() in SENSITIVE_PARAMS:
                params[key] = ["[REDACTED]"]
                modified = True
        if not modified:
            return url
        new_query = urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl().replace(
            "%5BREDACTED%5D", "[REDACTED]"
        )
    except Exception:
        return url


def find_interesting_urls(urls: list[str]) -> list[InterestingURL]:
    results: list[InterestingURL] = []
    seen: set[str] = set()

    for url in urls:
        if url in seen:
            continue
        seen.add(url)

        try:
            parsed = urlparse(url)
        except Exception:
            continue

        path = parsed.path.lower()
        host = parsed.netloc.lower()

        reasons: list[str] = []
        categories: list[str] = []

        for ext in SENSITIVE_EXTENSIONS:
            if (
                path.endswith(ext)
                or f"{ext}?" in path
                or f"{ext}." in path.rstrip(".")
            ):
                reasons.append(f"sensitive file ({ext})")
                categories.append("sensitive-file")
                break

        for pattern, category in _INTERESTING_PATHS:
            if pattern.lower() in path:
                reasons.append(f"interesting path ({pattern.rstrip('/')})")
                categories.append(category)
                break

        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            keys_lower = {k.lower() for k in params.keys()}

            if hit := keys_lower & IDOR_PARAMS:
                reasons.append(f"IDOR params: {', '.join(sorted(hit))}")
                categories.append("idor")

            if hit := keys_lower & REDIRECT_PARAMS:
                reasons.append(f"open-redirect/SSRF params: {', '.join(sorted(hit))}")
                categories.append("redirect")

            if hit := keys_lower & LFI_PARAMS:
                reasons.append(f"LFI params: {', '.join(sorted(hit))}")
                categories.append("lfi")

            if hit := keys_lower & SENSITIVE_PARAMS:
                reasons.append(f"secrets in URL: {', '.join(sorted(hit))}")
                categories.append("secrets")

        if reasons:
            display_url = redact_sensitive_params(url)
            results.append(
                InterestingURL(
                    url=display_url,
                    host=host,
                    reason="; ".join(reasons),
                    wayback_link=_wayback_link(url),
                    category=categories[0],
                )
            )

    return results
