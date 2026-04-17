import pytest
from src.models import Subdomain, DNSRecord
from src.analysis.takeover import check_takeover_candidates

SAMPLE_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname": ["github.io"],
        "fingerprint": ["There isn't a GitHub Pages site here."],
        "status": "Vulnerable",
        "notes": "Requires CNAME to unclaimed GitHub account",
    },
    {
        "service": "Heroku",
        "cname": ["herokuapp.com"],
        "fingerprint": ["No such app"],
        "status": "Vulnerable",
        "notes": "App does not exist",
    },
    {
        "service": "AWS S3",
        "cname": ["s3.amazonaws.com", "s3-website"],
        "fingerprint": ["NoSuchBucket"],
        "status": "Vulnerable",
        "notes": "S3 bucket does not exist",
    },
    {
        "service": "Not Vulnerable Service",
        "cname": ["safe-cdn.example.net"],
        "fingerprint": [],
        "status": "Not Vulnerable",
        "notes": "Actively maintained",
    },
]


class TestTakeover:
    def test_detects_github_pages(self):
        dns = DNSRecord(cname=["user.github.io"])
        sub = Subdomain(host="docs.example.com", dns=dns)
        candidate = check_takeover_candidates(sub, SAMPLE_FINGERPRINTS)
        assert candidate is not None
        assert candidate.service == "GitHub Pages"

    def test_detects_heroku(self):
        dns = DNSRecord(cname=["my-old-app.herokuapp.com"])
        sub = Subdomain(host="app.example.com", dns=dns)
        candidate = check_takeover_candidates(sub, SAMPLE_FINGERPRINTS)
        assert candidate is not None
        assert candidate.service == "Heroku"

    def test_no_cname_returns_none(self):
        dns = DNSRecord(a=["1.2.3.4"])
        sub = Subdomain(host="api.example.com", dns=dns)
        assert check_takeover_candidates(sub, SAMPLE_FINGERPRINTS) is None

    def test_safe_cname_returns_none(self):
        dns = DNSRecord(cname=["d123.cloudfront.net"])
        sub = Subdomain(host="cdn.example.com", dns=dns)
        assert check_takeover_candidates(sub, SAMPLE_FINGERPRINTS) is None

    def test_not_vulnerable_status_skipped(self):
        dns = DNSRecord(cname=["safe-cdn.example.net"])
        sub = Subdomain(host="cdn.example.com", dns=dns)
        assert check_takeover_candidates(sub, SAMPLE_FINGERPRINTS) is None

    def test_deep_cname_matches(self):
        dns = DNSRecord(cname=["org.github.io"])
        sub = Subdomain(host="pages.example.com", dns=dns)
        candidate = check_takeover_candidates(sub, SAMPLE_FINGERPRINTS)
        assert candidate is not None

    def test_empty_fingerprints(self):
        dns = DNSRecord(cname=["user.github.io"])
        sub = Subdomain(host="docs.example.com", dns=dns)
        assert check_takeover_candidates(sub, []) is None

    def test_candidate_has_correct_host(self):
        dns = DNSRecord(cname=["old-app.herokuapp.com"])
        sub = Subdomain(host="legacy.example.com", dns=dns)
        candidate = check_takeover_candidates(sub, SAMPLE_FINGERPRINTS)
        assert candidate is not None
        assert candidate.host == "legacy.example.com"
        assert candidate.cname_target == "old-app.herokuapp.com"
