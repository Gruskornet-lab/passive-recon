# Passive Recon Tool — Specification

> Detta dokument är en fullständig specifikation för ett passivt
> recon-verktyg som ska användas inom bug bounty-program. Använd detta som
> kontext/prompt i Claude Code för att bygga vidare på ett befintligt
> grund-skelett eller implementera från scratch.

---

## 1. Översikt

**Vad är detta?**
Ett verktyg som tar emot en lista med in-scope web targets (inklusive
wildcards som `*.example.com`) från ett bug bounty-program och samlar
publik information från **gratis, passiva datakällor** — utan att skicka
ett enda request direkt till targeten. Output är en proffsig Markdown-
rapport som fungerar som underlag för vidare manuell analys och som
bilaga/referens när en faktisk bug bounty-rapport skickas in till programmet.

**Varför passiv?**
- Respektera programmets rules of engagement. Många program förbjuder
  eller rate-limitar aktiv scanning innan man har en konkret
  vulnerability.
- Bygga en bred, fullständig bild av angreppsytan innan aktiv probing.
- Lämnar ingen spårbar trafik på targetens egen infrastruktur (förutom
  normal DNS-trafik via publika resolvers, vilket är oskiljbart från
  vanlig användartrafik).

**Vem använder detta?**
En solo bug bounty-jägare som prioriterar nordiska program på Intigriti
(Visma, Stravito, Signicat m.fl.). Resultaten matas vidare manuellt
och/eller in i ett aktivt recon-verktyg i ett separat nästa steg.

---

## 2. Kritiska säkerhetskrav (MÅSTE UPPFYLLAS)

Dessa punkter är icke-förhandlingsbara. Ett misslyckande här kan leda till
out-of-scope-testing och avstängning från programmet.

### 2.1 Strikt scope-validering

Varje subdomän och varje URL som inkluderas i rapporten MÅSTE matcha
minst ett av de angivna in-scope patterns. Matchning sker enligt:

- `*.example.com` matchar:
  - `example.com` (apex-domänen själv, inkluderas för att de flesta
    program inkluderar apex i wildcarden)
  - `foo.example.com`
  - `a.b.c.example.com`
- `api.example.com` matchar **endast** exakt `api.example.com`. Inte
  `api.example.com.foo`, inte `foo.api.example.com`.

**Anti-bypass-tester som MÅSTE passera:**

| Input scope | Host | Förväntat |
|---|---|---|
| `*.example.com` | `example.com` | ✓ match (apex) |
| `*.example.com` | `api.example.com` | ✓ match |
| `*.example.com` | `deep.api.example.com` | ✓ match |
| `*.example.com` | `examplefake.com` | ✗ no match (prefix injection) |
| `*.example.com` | `example.com.evil.com` | ✗ no match (suffix injection) |
| `api.example.com` | `api.example.com` | ✓ match |
| `api.example.com` | `admin.example.com` | ✗ no match |
| `api.example.com` | `sub.api.example.com` | ✗ no match |

Implementera som:

```python
def matches_scope(host: str, scope_patterns: list[str]) -> bool:
    host = host.lower().strip().rstrip(".")
    for pattern in scope_patterns:
        pattern = pattern.lower().strip()
        if pattern.startswith("*."):
            base = pattern[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == pattern:
            return True
    return False
```

**Använd `host.endswith("." + base)`, inte `host.endswith(base)`.** Utan
punkten släpper man igenom `examplefake.com` mot scope `*.example.com`.

### 2.2 Inga direkta requests mot target

Följande är tillåtet:
- HTTP-requests till `crt.sh`, `web.archive.org`, och andra tredje-parts
  datakällor listade nedan.
- DNS-lookups via publika resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8,
  Quad9 9.9.9.9).

Följande är förbjudet (tillhör aktiv recon, inte detta verktyg):
- HTTP-requests till target-domäner.
- Port scanning, TCP connects.
- SSL/TLS-handshakes mot target.
- Directory brute forcing, fuzzing.
- Credential testing, login-försök.
- Screenshots som kräver browser-navigation till targeten.

### 2.3 Ingen out-of-scope-data i slutrapporten

Om scopet är `*.example.com` och vi via crt.sh hittar att samma
organisation äger `otherbrand.com`, får `otherbrand.com` INTE hamna i
huvudrapporten. Den kan loggas separat som "discovery notes" eller
skippas helt. Safe default: skippa.

### 2.4 Ingen lagring av känsliga fynd

Om Wayback returnerar en URL som innehåller en API-nyckel eller
credentials i query string, inkludera URL:en i rapporten men **skriv
inte ut secrets i plain text**. Markera med `[REDACTED]` istället och
referera till Wayback-snapshot-länken så användaren kan gå dit manuellt
vid behov.

---

## 3. Input

En textfil eller stdin med en domän/URL per rad:

```
# Kommentarer ignoreras
*.monzo.com
api.monzo.com
*.prod-ffs.io
https://banking.example.com  # URL strippas till hostname
```

Verktyget ska:
- Trimma whitespace
- Ignorera tomma rader och `#`-kommentarer
- Lower-case:a allt
- Strippa protokoll (`https://`), path, och port
- Dedupa
- Validera: måste innehålla minst en punkt, får inte innehålla space,
  får inte vara `*.com` eller andra farligt breda mönster

---

## 4. Datakällor

Följande källor är alla **gratis och kräver inga API-nycklar**.
Implementera minst stjärnmärkta (*) för MVP. Övriga är starkt
rekommenderade för en proffsig version.

### 4.1 Subdomain-källor

| Källa | URL | Anmärkning |
|---|---|---|
| *crt.sh | `https://crt.sh/?q=%25.{domain}&output=json` | CT-logs. Ger mest data men kan vara långsam/flaky. Retry med backoff. |
| Certspotter | `https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names` | CT-log aggregator, 100 req/h utan nyckel |
| AlienVault OTX | `https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns` | Passiv DNS |
| HackerTarget | `https://api.hackertarget.com/hostsearch/?q={domain}` | Plain text output, 100/dag gratis |
| RapidDNS | `https://rapiddns.io/subdomain/{domain}?full=1` | HTML-scraping, robust |
| Anubis-DB | `https://jldc.me/anubis/subdomains/{domain}` | JSON, snabbt |

**Strategi:** Fråga alla källor, unionen av resultaten, deduplicera,
filtrera strikt mot scope. En källa som är nere eller rate-limitad ska
inte stoppa hela körningen — samla felen och rapportera dem i slutet.

### 4.2 Historiska URL-källor

| Källa | URL | Anmärkning |
|---|---|---|
| *Wayback Machine CDX | `https://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain&output=json&collapse=urlkey&fl=original&limit={limit}` | Använd `matchType=domain` för att täcka alla subdomäner |
| CommonCrawl Index | `https://index.commoncrawl.org/CC-MAIN-{year}-{week}-index?url=*.{domain}&output=json` | Måste välja senaste index, sedan paginera |
| URLScan.io | `https://urlscan.io/api/v1/search/?q=domain:{domain}` | Publika scans, begränsat utan nyckel men fungerar |

### 4.3 DNS (via publika resolvers)

Fråga rekursivt mot `1.1.1.1`, `8.8.8.8`, `9.9.9.9`:

- **A** — IPv4-adresser
- **AAAA** — IPv6-adresser
- **CNAME** — kritiskt för takeover-detektion
- **MX** — mail-infrastruktur (ofta glömda assets)
- **TXT** — SPF, DKIM, verifierings-records (kan läcka tredje-parts-SaaS)
- **NS** — auktoritativa namnservrar (ägareffingerprint)

### 4.4 Tekniska fingerprints från URL-patterns

Inga externa requests — analysera Wayback-URL:erna för att gissa stack:

| Indikator | Trolig stack |
|---|---|
| `/wp-content/`, `/wp-admin/`, `/wp-json/` | WordPress |
| `/_next/`, `/__nextjs_original_stack` | Next.js |
| `/actuator/`, `/spring-boot/` | Spring Boot |
| `/phpmyadmin/`, `/pma/` | phpMyAdmin |
| `/graphql`, `/graphiql` | GraphQL |
| `/swagger`, `/api-docs`, `/openapi.json` | OpenAPI/Swagger |
| `/.git/`, `/.env`, `/.DS_Store` | Exponerade dev-artifakter |
| `/admin/`, `/administrator/` | Admin-paneler |
| `/drupal/`, `/sites/default/` | Drupal |
| `/_layouts/`, `/sites/` | SharePoint |
| `/user/login?destination=` | Drupal open redirect-kandidat |
| `.action`, `.do` | Struts/Java |

### 4.5 Subdomain takeover-kandidater

Matcha CNAMEs mot känt-sårbara tjänster och markera som kandidater för
manuell verifiering. **Detta är bara en heuristik — verktyget ska inte
försöka ta över något.**

Exempel på CNAME-mål som historiskt varit sårbara (listan är
ofullständig och ändras, slå upp aktuell lista från
[EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)):

- `*.github.io` (om sidan är 404)
- `*.herokuapp.com` (om appen inte existerar)
- `*.s3.amazonaws.com` (om bucket inte finns)
- `*.azurewebsites.net`
- `*.cloudapp.net`
- `*.fastly.net`
- `cname.vercel-dns.com`
- `*.netlify.app`
- `*.readthedocs.io`
- `*.ghost.io`
- `*.wpengine.com`

**Markera som "kandidat" — aldrig som "bekräftad takeover".**
Bekräftelse kräver aktiv test (registrering av den hängande resursen),
vilket är utanför detta verktygs scope.

---

## 5. Pipeline

```
INPUT targets.txt
    ↓
PARSE & NORMALIZE (parse_targets)
    ↓
DEDUP BASES (get_query_bases)
    ↓  för varje base-domän parallellt:
    ├── crt.sh         ─┐
    ├── Certspotter     │
    ├── AlienVault OTX  ├── union → subdomain set
    ├── HackerTarget    │
    ├── RapidDNS        │
    └── Anubis-DB      ─┘
    ↓
STRICT SCOPE FILTER (matches_scope)
    ↓
    ├── in-scope subs  ──┐
    └── out-of-scope    │ (separat lista i rapporten)
    ↓                    │
DNS RESOLVE (parallell, sem=20)
    ↓                    │
    ├── A, AAAA, CNAME, MX, TXT, NS
    ↓                    │
WAYBACK CDX QUERY (per base)
    ↓                    │
SCOPE FILTER URLs        │
    ↓                    │
INTERESTING URL FILTER   │
    ↓                    │
TECH FINGERPRINTING      │
    ↓                    │
TAKEOVER CANDIDATE SCAN ─┘
    ↓
RENDER MARKDOWN REPORT + JSON dump
    ↓
WRITE reports/{date}-{program-slug}.md
WRITE reports/{date}-{program-slug}.json
```

---

## 6. Rapport-format

Filnamn: `reports/YYYY-MM-DD-{program-slug}.md`

### 6.1 Struktur

```markdown
# Passive Recon-rapport — {program-namn}

**Datum:** YYYY-MM-DD HH:MM UTC
**Genererad av:** passive-recon v{version}
**Körning:** {kort unik id, t.ex. första 8 tecken av en UUID}

## Scope

Följande in-scope patterns användes:
- `*.example.com`
- `api.example.com`

## Exekutiv sammanfattning

| Metrik | Värde |
|---|---|
| Base-domäner undersökta | N |
| Subdomäner upptäckta (totalt) | N |
| Subdomäner in-scope | N |
| Subdomäner DNS-verifierade | N |
| Historiska URLs (totalt) | N |
| Intressanta endpoints | N |
| Potentiella takeover-kandidater | N |
| Datakällor som svarade | X/Y |

### Prioriterade quick wins (top 10)

Mest högintresse-fynd att titta på först. Rangordna efter:
1. Takeover-kandidater (högst)
2. Exponerade `.git`, `.env`, `.sql`, backup-filer
3. Admin-paneler på auth-subdomäner
4. API-endpoints med känsliga parametrar

## Per base-domän

### `example.com`

#### Bekräftade subdomäner

Tabell med kolumner: Subdomän, A, AAAA, CNAME, DNS-status, Källor

(Sortera alfabetiskt. Markera DNS-verifierade med ✓.)

#### Takeover-kandidater

Om CNAMEs pekar mot kända sårbara tjänster, lista dem här med:
- Subdomän
- CNAME-mål
- Sårbar tjänst (t.ex. "GitHub Pages")
- Nivå av manuell verifiering som krävs

#### DNS-insikter

- MX-records → vilka mail-tjänster används
- TXT-records → SaaS-integrationer (Google Workspace, Office 365,
  SendGrid, HubSpot, osv.)
- NS-records → auktoritativa namnservrar

#### Intressanta historiska endpoints

Grupperat per host. Collapsible `<details>`. Varje URL som hittas:
- Länk till Wayback-snapshot (`https://web.archive.org/web/*/URL`)
- Markera vad som gjorde den intressant (filändelse, path-segment,
  parameter)

Format:

```
**`api.example.com`** (N URLs)

- `https://api.example.com/v1/users?id=123` — IDOR-kandidat (param: id)
- `https://api.example.com/.env` — exponerad secrets-fil
- `https://api.example.com/backup.sql` — databas-dump
```

#### Teknisk stack (från URL-patterns)

Lista detekterade teknologier med exempel-URL:er.

#### Mining av parametrar

Alla unika query-parameternamn som någonsin observerats, grupperade:
- Högintresse (IDOR, SSRF, open redirect, LFI)
- Auth-relaterade (token, session, auth)
- Övriga

#### Filtrerade bort (utanför scope)

Collapsible. Lista allt som avvisades av scope-filtret för
transparens. Hjälper användaren upptäcka om scopet behöver utökas
(t.ex. om en tidigare okänd domän dyker upp i CT-logs).

## Metodik (för bilaga till bug bounty-rapporter)

Automatiskt genererat avsnitt som beskriver exakt vilka datakällor
som användes, vid vilken tidpunkt, och vilka fel som uppstod. Copy-
paste-vänligt för att bifoga i bug bounty-rapporter så triage-teamet
kan reproducera dina fynd.

## Fel och varningar

Datakällor som inte svarade, rate-limits som nåddes, timeouts.
Transparens om vad som inte täcktes.

---
_Rapport genererad {timestamp}. Alla datakällor är publika.
Inga requests skickades direkt till targeten._
```

### 6.2 JSON-dump

Samma data som markdown men maskinläsbart, för att mata in i nästa
verktyg (aktiv recon):

```json
{
  "version": "1.0",
  "generated_at": "2026-04-17T12:34:56Z",
  "scope": ["*.example.com", "api.example.com"],
  "bases": [
    {
      "base": "example.com",
      "subdomains": [
        {
          "host": "api.example.com",
          "dns": {"a": ["1.2.3.4"], "cname": [], "mx": [], "txt": []},
          "sources": ["crt.sh", "wayback", "hackertarget"],
          "takeover_candidate": null
        }
      ],
      "interesting_urls": [...],
      "out_of_scope": [...]
    }
  ],
  "stats": {...},
  "errors": [...]
}
```

---

## 7. Teknisk stack

- **Python 3.12+**
- `httpx` med `AsyncClient` för alla HTTP-anrop (concurrency)
- `dnspython` för DNS-lookups
- `asyncio.Semaphore` för rate-limiting
- Ingen databas — filsystemet räcker
- **Ingen extern ML/AI** — allt är regelbaserat och deterministiskt
- GitHub Actions för scheduling/körning

**Tillåtna extra beroenden om användbart:**
- `rich` för fina terminal-progress-bars
- `tenacity` för retry-logik (alternativt egen enkel implementation)

**Undvik:**
- Tunga recon-frameworks (Amass, Subfinder, ReconFTW) — målet är att
  behålla fullt kontroll över scope-filtret och ha ett lightweight,
  läsbart verktyg. De stora verktygen är proffsiga men de är svarta
  lådor för inlärningssyfte.

---

## 8. Kod-kvalitet

### 8.1 Struktur

Dela upp i moduler för läsbarhet och testbarhet:

```
passive-recon/
├── passive_recon.py          # CLI entrypoint
├── src/
│   ├── __init__.py
│   ├── scope.py              # parse_targets, matches_scope, get_query_bases
│   ├── sources/
│   │   ├── __init__.py
│   │   ├── crtsh.py
│   │   ├── certspotter.py
│   │   ├── alienvault.py
│   │   ├── hackertarget.py
│   │   ├── rapiddns.py
│   │   ├── anubis.py
│   │   └── wayback.py
│   ├── dns_resolver.py
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── interesting_urls.py
│   │   ├── tech_fingerprint.py
│   │   ├── takeover.py
│   │   └── parameter_mining.py
│   ├── report/
│   │   ├── __init__.py
│   │   ├── markdown.py
│   │   └── json_output.py
│   └── models.py             # dataclasses: ReconResult, Subdomain, ...
├── tests/
│   ├── test_scope.py
│   ├── test_interesting_urls.py
│   ├── test_takeover.py
│   └── fixtures/
├── requirements.txt
├── .github/
│   └── workflows/
│       └── passive-recon.yml
├── .gitignore
├── README.md
└── targets.example.txt
```

### 8.2 Testning (MÅSTE finnas)

`tests/test_scope.py` är det viktigaste. Skriv minst följande:

```python
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
        # Klassisk bypass: fake-example.com med scope *.example.com
        assert not matches_scope("examplefake.com", ["*.example.com"])

    def test_suffix_injection_rejected(self):
        # Klassisk bypass: example.com.evil.com
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
        # "localhost" etc
        assert parse_targets(["example"]) == []
```

Kör med `pytest tests/` — ska krävas grönt i CI innan rapport genereras.

### 8.3 Loggning

- Allt progress/debug till **stderr**
- Stdout reserverat för maskinläsbar output (JSON) om användaren vill
  pipe:a
- Feltolerans: en källa som failar loggas men stoppar inte körningen

### 8.4 Retry-logik

crt.sh är känd för att vara flaky. Implementera exponential backoff:

```python
async def query_crtsh_with_retry(client, base, max_attempts=3):
    for attempt in range(max_attempts):
        try:
            return await query_crtsh(client, base)
        except (httpx.TimeoutException, httpx.HTTPError) as e:
            if attempt == max_attempts - 1:
                raise
            wait = 2 ** attempt
            print(f"[!] crt.sh retry {attempt + 1}/{max_attempts} in {wait}s: {e}",
                  file=sys.stderr)
            await asyncio.sleep(wait)
```

### 8.5 Rate limiting

- HackerTarget: 100 requests/dag utan nyckel. Om vi hittar ett
  429-svar, bubbla upp ett tydligt felmeddelande och fortsätt med
  övriga källor.
- crt.sh: ingen officiell gräns men var snäll. Max 1 request/sekund
  om verktyget någonsin itererar över många baser.

### 8.6 Cache (optional, men trevligt)

En enkel filsystem-cache i `.cache/{source}/{domain}.json` med TTL på
24h kan:
- Spara bandbredd under utveckling
- Göra rekörning snabb om man itererar på rapport-formatet
- Flagga `--no-cache` för tvingad färsk data

---

## 9. GitHub Actions workflow

Trigga manuellt via `workflow_dispatch`:

```yaml
name: Passive Recon

on:
  workflow_dispatch:
    inputs:
      targets:
        description: 'In-scope targets, en per rad (wildcards OK)'
        required: true
        type: string
      program_name:
        description: 'Programnamn (används i filnamn)'
        required: false
        type: string
      wayback_limit:
        description: 'Max Wayback-URLs per base-domän'
        required: false
        type: string
        default: '50000'

permissions:
  contents: write

concurrency:
  group: passive-recon
  cancel-in-progress: false

jobs:
  recon:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v
      - env:
          TARGETS: ${{ inputs.targets }}
        run: printf '%s\n' "$TARGETS" > targets.txt
      - env:
          PROGRAM_NAME: ${{ inputs.program_name }}
          WAYBACK_LIMIT: ${{ inputs.wayback_limit }}
        run: |
          args=(--file targets.txt --output reports/ --wayback-limit "$WAYBACK_LIMIT")
          [ -n "$PROGRAM_NAME" ] && args+=(--name "$PROGRAM_NAME")
          python passive_recon.py "${args[@]}"
      - uses: actions/upload-artifact@v4
        with:
          name: passive-recon-report
          path: reports/
          retention-days: 90
      - run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add reports/
          git diff --cached --quiet || {
            git commit -m "recon: $(date -u +%Y-%m-%d) ${{ inputs.program_name }}"
            git push
          }
```

**Säkerhetsnot:** `targets.txt` ska stå med i `.gitignore` så den aldrig
committas — den innehåller det aktiva scopet du tittar på, vilket kan
vara känsligt för privata VDP-program. Rapport-filen i `reports/` får
däremot committas.

---

## 10. Bug bounty-rapporteringstips (hur du använder outputen)

När du hittar en vulnerability i output och skriver rapport till programmet:

### 10.1 Bygg rapport-template kring dina fynd

```markdown
# [Severity] [Type] in {subdomain}

## Summary
En mening som beskriver vulnen.

## Reproduction
1. Steg 1
2. Steg 2
3. Observera {behavior}

## Proof of Concept
(Screenshot / request / response. Markera känslig data.)

## Impact
Konkret vad en angripare kan göra.

## Methodology
Subdomänen `{subdomain}` upptäcktes via passiv recon mot publika
datakällor (Certificate Transparency logs via crt.sh, historisk crawl
via Wayback Machine). Inga aktiva requests skickades till targeten
under discovery-fasen.

## References
- OWASP: {relevant OWASP-ref}
- CWE-{nummer}
```

### 10.2 Vad du INTE ska lägga i rapporten

- Inte hela passive-recon-outputen som bilaga. Det är distraction.
  Referera bara till *den specifika subdomän/URL* som är sårbar.
- Inte råa wayback-dumps med hundratals URLs.
- Inte spekulation om andra sårbarheter du gissar finns.

### 10.3 Vad du SKA referera till

- Vilken publik källa som ledde dig till targeten (CT-logs är legitimt)
- Datum/tidpunkt för din passive recon
- Det exakta in-scope pattern som täcker subdomänen

### 10.4 Validera scope innan submit

- Dubbelkolla programmets current scope-sida. Scope kan ändras.
- Om subdomänen är på gränsen (t.ex. wildcard som kanske exkluderar
  vissa subdomäner), fråga programmet innan du skriver rapport.
- Många program exkluderar specifika subdomäner även inom ett wildcard.
  Läs "Out of scope"-sektionen noga.

### 10.5 Triage-vänlig rapportstil

Programmets triage-team ska kunna reproducera inom 5 min. Det betyder:
- Exakt URL
- Exakt curl/HTTP-request som triggar
- Screenshot som visar impact
- Ingen onödig text innan proof-of-concept

---

## 11. Icke-mål

- **Inte en framework.** En läsbar, hackbar ensamfil-stil är OK i början.
- **Inte realtid.** En körning per program per vecka räcker. Använd
  cache.
- **Inte aktiv exploitation.** Det här är första steget i en pipeline —
  nästa steg (aktiv recon med httpx/nuclei/etc.) är separata verktyg.
- **Inte ett ersättning för manuell analys.** Output är en karta, inte
  en diagnos. Du måste fortfarande läsa, tänka, och testa manuellt.

---

## 12. Framtida iterationer (bygg inte just nu)

- **Diff mot föregående körning:** jämför dagens subdomän-set mot
  förra veckans och flagga nytillkomna. Mycket värdefullt för att fånga
  nyligen deployade assets innan konkurrenterna.
- **Notifiering via ntfy** när intressanta nya endpoints dyker upp
  (likt ditt Electricity Price Notifier-mönster).
- **Integration med ditt Intigriti Hunter-verktyg:** Hunter hittar
  program, recon kör automatiskt på nya in-scope targets.
- **Mini-frontend** (HTML/React) för att browse rapporter lokalt.
- **Encrypted secrets-handling** om du någonsin lägger till API-nyckel-
  källor (Shodan, SecurityTrails, VirusTotal).

---

## 13. Acceptanskriterier

Detta verktyg är klart för produktionsanvändning när:

1. ✅ Alla tester i `tests/test_scope.py` passerar
2. ✅ Verktyget kan köra hela pipelinen för `*.example.com` utan att
   krascha ens om 2 av 6 källor är nere
3. ✅ Ingen enda out-of-scope-host syns i huvud-rapporten för ett
   känt test-case
4. ✅ Rapporten är läsbar på mobil utan horisontell scroll
5. ✅ JSON-outputen är valid JSON och innehåller all information från
   markdown-versionen
6. ✅ GitHub Actions-körning går igenom på en Ubuntu-runner med
   Python 3.12 och returnerar exit code 0
7. ✅ Hela body-körningen för en medelstor target (20k subdomäner,
   50k wayback-URLs) slutar på under 15 minuter
8. ✅ `.gitignore` stänger ute `targets.txt`, `.cache/`, och `__pycache__`

---

## 14. Bilaga A — Intressanta parametrar (utökad lista)

Använd som whitelist när parameter-mining körs mot Wayback-URLs:

**IDOR-kandidater:** `id`, `user`, `user_id`, `userid`, `uid`, `account`,
`account_id`, `order`, `order_id`, `invoice`, `invoice_id`, `ticket`,
`doc`, `doc_id`, `document`, `document_id`, `record`, `record_id`,
`profile`, `profile_id`, `customer`, `customer_id`, `org`, `org_id`,
`team_id`, `project_id`, `file_id`

**Open redirect / SSRF:** `redirect`, `redirect_uri`, `redirect_url`,
`redir`, `return`, `returnurl`, `return_url`, `returnto`, `next`,
`continue`, `dest`, `destination`, `url`, `u`, `callback`, `jsonp`, `go`,
`to`, `link`, `site`, `target`, `image_url`, `image`, `imgurl`

**LFI / Path traversal:** `file`, `path`, `filename`, `filepath`,
`download`, `load`, `include`, `template`, `module`, `folder`, `dir`

**Cmd injection:** `cmd`, `exec`, `command`, `payload`, `action`, `do`,
`run`

**Secrets (flagga som dataläckor, inte testa):** `token`, `auth`,
`authorization`, `api_key`, `apikey`, `key`, `secret`, `session`,
`sessionid`, `jwt`, `access_token`, `refresh_token`, `csrf`, `csrfmiddlewaretoken`

**XSS-kontextparametrar:** `q`, `query`, `search`, `s`, `keyword`,
`term`, `filter`, `sort`, `order_by`, `msg`, `message`, `name`, `title`

---

## 15. Bilaga B — Takeover-kandidatlista

Referens: https://github.com/EdOverflow/can-i-take-over-xyz

Slå upp aktuell lista och cacha den lokalt som `takeover_fingerprints.json`.
Format:

```json
[
  {
    "service": "GitHub Pages",
    "cname": ["github.io"],
    "fingerprint": ["There isn't a GitHub Pages site here."],
    "status": "Vulnerable",
    "notes": "Kräver att CNAME pekar på ett icke-registrerat GitHub-konto."
  }
]
```

Verktyget ska i sin passiva fas bara matcha CNAME-mål mot listan. Den
aktiva verifieringsfasen (HTTP-fingerprint-matchning mot targeten) är
utanför detta verktygs scope — den tillhör aktiv recon.

---

## 16. Bilaga C — Etik och scope-diskussion

- **Oklara scope?** Om programmets wildcard är `*.example.com` men det
  finns subdomäner som `corp.example.com` som uppenbart är interna
  corporate-system, skicka ett meddelande till programmet via Intigriti-
  plattformen och fråga. Dokumentera svaret.
- **Acquired companies:** Om example.com har köpt upp foo.com men foo.com
  inte står i scope, är det inte i scope. Inget undantag för "det är ju
  samma företag".
- **Historiska URLs som inte längre fungerar:** Helt ok att analysera —
  snapshot:en är publik data på archive.org. Men rapportera inte
  vulnerabilities mot en URL som inte längre svarar, för det är en
  död end för triage.
- **Staging/dev-subdomäner:** Ofta i scope men kolla alltid. Många
  program har policy om att `dev-*` och `*-staging` är out of scope.

---

_Detta dokument är specifikationen. Bygg enligt det, inte runt det. Om något
krav är oklart, lägg till ett FAQ-avsnitt här hellre än att gissa._
