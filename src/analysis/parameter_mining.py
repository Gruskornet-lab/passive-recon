from urllib.parse import urlparse, parse_qs

from src.models import ParameterFindings

_IDOR = {
    "id", "user", "user_id", "userid", "uid", "account", "account_id",
    "order", "order_id", "invoice", "invoice_id", "ticket", "doc",
    "doc_id", "document", "document_id", "record", "record_id",
    "profile", "profile_id", "customer", "customer_id", "org", "org_id",
    "team_id", "project_id", "file_id",
}

_REDIRECT_SSRF = {
    "redirect", "redirect_uri", "redirect_url", "redir", "return",
    "returnurl", "return_url", "returnto", "next", "continue",
    "dest", "destination", "url", "u", "callback", "jsonp", "go",
    "to", "link", "site", "target", "image_url", "image", "imgurl",
}

_LFI = {
    "file", "path", "filename", "filepath", "download", "load",
    "include", "template", "module", "folder", "dir",
}

_CMD = {"cmd", "exec", "command", "payload", "action", "do", "run"}

_SECRETS = {
    "token", "auth", "authorization", "api_key", "apikey", "key",
    "secret", "session", "sessionid", "jwt", "access_token",
    "refresh_token", "csrf", "csrfmiddlewaretoken",
}

_XSS = {
    "q", "query", "search", "s", "keyword", "term", "filter", "sort",
    "order_by", "msg", "message", "name", "title",
}

_ALL_KNOWN = _IDOR | _REDIRECT_SSRF | _LFI | _CMD | _SECRETS | _XSS


def mine_parameters(urls: list[str]) -> ParameterFindings:
    findings = ParameterFindings()
    seen: dict[str, set[str]] = {
        "idor": set(), "redirect": set(), "lfi": set(),
        "cmd": set(), "secrets": set(), "xss": set(), "other": set(),
    }

    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True)}
        except Exception:
            continue

        for p in keys:
            if p in _IDOR and p not in seen["idor"]:
                findings.idor.append(p)
                seen["idor"].add(p)
            elif p in _REDIRECT_SSRF and p not in seen["redirect"]:
                findings.redirect_ssrf.append(p)
                seen["redirect"].add(p)
            elif p in _LFI and p not in seen["lfi"]:
                findings.lfi.append(p)
                seen["lfi"].add(p)
            elif p in _CMD and p not in seen["cmd"]:
                findings.cmd_injection.append(p)
                seen["cmd"].add(p)
            elif p in _SECRETS and p not in seen["secrets"]:
                findings.secrets.append(p)
                seen["secrets"].add(p)
            elif p in _XSS and p not in seen["xss"]:
                findings.xss.append(p)
                seen["xss"].add(p)
            elif p not in _ALL_KNOWN and p not in seen["other"]:
                findings.other.append(p)
                seen["other"].add(p)

    return findings
