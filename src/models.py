from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DNSRecord:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    resolved: bool = False


@dataclass
class TakeoverCandidate:
    host: str
    cname_target: str
    service: str
    notes: str


@dataclass
class Subdomain:
    host: str
    dns: DNSRecord = field(default_factory=DNSRecord)
    sources: list[str] = field(default_factory=list)
    takeover_candidate: Optional[TakeoverCandidate] = None


@dataclass
class InterestingURL:
    url: str
    host: str
    reason: str
    wayback_link: str
    category: str


@dataclass
class TechStack:
    tech: str
    evidence_urls: list[str] = field(default_factory=list)


@dataclass
class ParameterFindings:
    idor: list[str] = field(default_factory=list)
    redirect_ssrf: list[str] = field(default_factory=list)
    lfi: list[str] = field(default_factory=list)
    cmd_injection: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    xss: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)


@dataclass
class BaseResult:
    base: str
    subdomains: list[Subdomain] = field(default_factory=list)
    interesting_urls: list[InterestingURL] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    tech_stack: list[TechStack] = field(default_factory=list)
    parameters: Optional[ParameterFindings] = None
    raw_urls: list[str] = field(default_factory=list)


@dataclass
class ReconResult:
    version: str = "1.0"
    generated_at: str = ""
    scope: list[str] = field(default_factory=list)
    program_name: str = ""
    run_id: str = ""
    bases: list[BaseResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source_stats: dict[str, bool] = field(default_factory=dict)
