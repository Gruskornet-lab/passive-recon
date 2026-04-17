import pytest
from src.analysis.interesting_urls import find_interesting_urls, redact_sensitive_params


class TestInterestingURLs:
    def test_finds_env_file(self):
        urls = ["https://api.example.com/.env"]
        results = find_interesting_urls(urls)
        assert len(results) > 0
        assert any("env" in r.reason.lower() or "env" in r.category for r in results)

    def test_finds_git_dir(self):
        urls = ["https://api.example.com/.git/config"]
        results = find_interesting_urls(urls)
        assert len(results) > 0

    def test_finds_sql_backup(self):
        urls = ["https://example.com/db/backup.sql"]
        results = find_interesting_urls(urls)
        assert len(results) > 0
        assert any("sql" in r.reason for r in results)

    def test_finds_idor_param(self):
        urls = ["https://api.example.com/users?id=123"]
        results = find_interesting_urls(urls)
        assert any(r.category == "idor" for r in results)

    def test_finds_redirect_param(self):
        urls = ["https://example.com/login?redirect=https://evil.com"]
        results = find_interesting_urls(urls)
        assert any(r.category == "redirect" for r in results)

    def test_finds_lfi_param(self):
        urls = ["https://example.com/load?file=../../etc/passwd"]
        results = find_interesting_urls(urls)
        assert any(r.category == "lfi" for r in results)

    def test_finds_admin_panel(self):
        urls = ["https://example.com/admin/dashboard"]
        results = find_interesting_urls(urls)
        assert any(r.category == "admin-panel" for r in results)

    def test_finds_swagger(self):
        urls = ["https://api.example.com/swagger/index.html"]
        results = find_interesting_urls(urls)
        assert len(results) > 0

    def test_empty_urls(self):
        assert find_interesting_urls([]) == []

    def test_safe_url_not_flagged(self):
        urls = ["https://example.com/about", "https://example.com/contact"]
        results = find_interesting_urls(urls)
        assert len(results) == 0

    def test_deduplicates(self):
        url = "https://api.example.com/.env"
        results = find_interesting_urls([url, url, url])
        assert len(results) == 1


class TestRedactSensitiveParams:
    def test_redacts_token(self):
        url = "https://api.example.com/auth?token=supersecret123"
        result = redact_sensitive_params(url)
        assert "supersecret123" not in result
        assert "[REDACTED]" in result

    def test_redacts_api_key(self):
        url = "https://api.example.com/data?api_key=abc123xyz"
        result = redact_sensitive_params(url)
        assert "abc123xyz" not in result

    def test_preserves_safe_params(self):
        url = "https://api.example.com/search?q=hello&page=2"
        result = redact_sensitive_params(url)
        assert "hello" in result
        assert "page=2" in result

    def test_no_query_string_unchanged(self):
        url = "https://api.example.com/users"
        assert redact_sensitive_params(url) == url

    def test_redacts_jwt(self):
        url = "https://example.com/cb?jwt=eyJhbGciOiJIUzI1NiJ9.payload.sig"
        result = redact_sensitive_params(url)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
