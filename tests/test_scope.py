import pytest
from src.scope import matches_scope, parse_targets, get_query_bases


class TestMatchesScope:
    def test_wildcard_matches_apex(self):
        assert matches_scope("example.com", ["*.example.com"])

    def test_wildcard_matches_subdomain(self):
        assert matches_scope("api.example.com", ["*.example.com"])

    def test_wildcard_matches_deep_subdomain(self):
        assert matches_scope("a.b.c.example.com", ["*.example.com"])

    def test_prefix_injection_rejected(self):
        assert not matches_scope("examplefake.com", ["*.example.com"])

    def test_suffix_injection_rejected(self):
        assert not matches_scope("example.com.evil.com", ["*.example.com"])

    def test_exact_match(self):
        assert matches_scope("api.example.com", ["api.example.com"])

    def test_exact_does_not_match_sibling(self):
        assert not matches_scope("admin.example.com", ["api.example.com"])

    def test_exact_does_not_match_child(self):
        assert not matches_scope("v1.api.example.com", ["api.example.com"])

    def test_case_insensitive(self):
        assert matches_scope("API.EXAMPLE.COM", ["*.example.com"])

    def test_trailing_dot_stripped(self):
        assert matches_scope("api.example.com.", ["*.example.com"])

    def test_empty_host(self):
        assert not matches_scope("", ["*.example.com"])

    def test_multiple_patterns(self):
        patterns = ["*.example.com", "api.other.com"]
        assert matches_scope("foo.example.com", patterns)
        assert matches_scope("api.other.com", patterns)
        assert not matches_scope("admin.other.com", patterns)

    def test_no_partial_base_match(self):
        assert not matches_scope("notexample.com", ["*.example.com"])

    def test_wildcard_two_levels(self):
        assert matches_scope("dev.api.example.com", ["*.example.com"])


class TestParseTargets:
    def test_strips_protocol(self):
        assert "example.com" in parse_targets(["https://example.com/path"])

    def test_ignores_comments(self):
        assert parse_targets(["# comment", "example.com"]) == ["example.com"]

    def test_deduplicates(self):
        result = parse_targets(["example.com", "EXAMPLE.COM"])
        assert result == ["example.com"]

    def test_rejects_spaces(self):
        assert parse_targets(["bad input"]) == []

    def test_rejects_missing_tld(self):
        assert parse_targets(["example"]) == []

    def test_accepts_wildcard(self):
        result = parse_targets(["*.example.com"])
        assert "*.example.com" in result

    def test_strips_inline_comment(self):
        result = parse_targets(["example.com  # this is the target"])
        assert "example.com" in result

    def test_strips_port(self):
        result = parse_targets(["example.com:8080"])
        assert "example.com" in result

    def test_ignores_empty_lines(self):
        result = parse_targets(["", "  ", "example.com"])
        assert result == ["example.com"]

    def test_rejects_broad_wildcard(self):
        assert parse_targets(["*.com"]) == []
        assert parse_targets(["*.io"]) == []

    def test_lowercases(self):
        result = parse_targets(["EXAMPLE.COM"])
        assert result == ["example.com"]


class TestGetQueryBases:
    def test_strips_wildcard(self):
        assert "example.com" in get_query_bases(["*.example.com"])

    def test_exact_pattern_gives_apex(self):
        result = get_query_bases(["api.example.com"])
        assert "example.com" in result

    def test_deduplicates(self):
        result = get_query_bases(["*.example.com", "api.example.com"])
        assert result.count("example.com") == 1

    def test_multiple_bases(self):
        result = get_query_bases(["*.foo.com", "*.bar.com"])
        assert "foo.com" in result
        assert "bar.com" in result
