from urllib.parse import urlparse

from src.models import TechStack

_TECH_PATTERNS: list[tuple[str, list[str]]] = [
    ("WordPress", ["/wp-content/", "/wp-admin/", "/wp-json/", "/wp-includes/"]),
    ("Next.js", ["/_next/", "/__nextjs_"]),
    ("Spring Boot", ["/actuator/", "/spring-boot/"]),
    ("phpMyAdmin", ["/phpmyadmin/", "/pma/"]),
    ("GraphQL", ["/graphql", "/graphiql"]),
    ("OpenAPI/Swagger", ["/swagger", "/api-docs", "/openapi.json", "/openapi.yaml"]),
    ("Drupal", ["/drupal/", "/sites/default/", "/user/login?destination="]),
    ("SharePoint", ["/_layouts/", "/sites/"]),
    ("Django", ["/django-admin/", "/static/admin/"]),
    ("Jenkins", ["/jenkins/", "/job/"]),
    ("Exposed dev artifacts", ["/.git/", "/.env", "/.DS_Store", "/.idea/"]),
    ("Admin panel", ["/admin/", "/administrator/"]),
    ("Struts/Java", [".action", ".do", ".jsp"]),
]

_MAX_EVIDENCE = 3


def fingerprint_tech(urls: list[str]) -> list[TechStack]:
    tech_map: dict[str, TechStack] = {}

    for url in urls:
        try:
            path = urlparse(url).path.lower()
        except Exception:
            continue

        for tech_name, patterns in _TECH_PATTERNS:
            for pattern in patterns:
                if pattern.lower() in path:
                    if tech_name not in tech_map:
                        tech_map[tech_name] = TechStack(tech=tech_name)
                    ts = tech_map[tech_name]
                    if url not in ts.evidence_urls and len(ts.evidence_urls) < _MAX_EVIDENCE:
                        ts.evidence_urls.append(url)
                    break

    return list(tech_map.values())
