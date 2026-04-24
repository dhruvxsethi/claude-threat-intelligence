# Claude Threat Intelligence

AI-powered threat intelligence platform. Claude reads 32 global security feeds, extracts structured intelligence, and serves it on a live portal that updates automatically every 3 hours.

**Claude IS the engine** — no AlienVault, no OTX. Every article is analyzed by Claude Sonnet to extract CVEs, IOCs, TTPs, threat actors, and sector impact scores.

---

## Quick Start

```bash
git clone https://github.com/dhruvxsethi/claude-threat-intelligence
cd claude-threat-intelligence
npm install
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
node portal/server.mjs         # portal at http://localhost:3000
node scripts/run-pipeline.mjs  # run first sync (separate terminal)
```

---

## Why do I need an Anthropic API key?

The platform uses Claude (claude-sonnet-4-6) as its intelligence engine. Every article is sent to Claude, which reads the full text and extracts:
- CVEs with CVSS scores
- IOCs (IPs, domains, hashes, URLs, registry keys…)
- MITRE ATT&CK TTPs
- Threat actor names, origins, and motivations
- Affected products and sector impact scores

Without the API key, feeds are fetched but nothing is analyzed — the threat database stays empty. **The key is only used on your machine and never shared.**

Get your key at: https://console.anthropic.com → API Keys

---

## Portal Pages

| Page | URL | What you see |
|---|---|---|
| Dashboard | `localhost:3000` | Live metrics strip, latest threats, charts, CVEs, actors |
| Threat Feed | `localhost:3000/threats.html` | Full paginated threat list with filters |
| Sectors | `localhost:3000/sectors.html` | Banking / Government / Healthcare breakdowns |
| IOC Explorer | `localhost:3000/iocs.html` | All extracted indicators, filterable + CSV export |
| Feed Health | `localhost:3000/feeds.html` | Per-feed status, run history |
| Threat Detail | `localhost:3000/threat-detail.html?id=…` | Full CVEs, IOCs, TTPs, actors, related threats |

---

## What's Automated

| What | How | When |
|---|---|---|
| Full pipeline — all feeds + vulnerability APIs | Built-in cron in `portal/server.mjs` | Every 3 hours |
| Portal live refresh | Server-Sent Events (SSE) | Real-time on pipeline completion |
| Cross-threat correlation | Built into pipeline | Every run |
| Credibility scoring | Built into pipeline | Every article |

**You only need to keep `node portal/server.mjs` running.** The pipeline executes automatically every 3 hours. The portal updates itself via SSE — no page reload needed.

The **↻ Sync Now** button in the sidebar manually triggers an immediate pipeline run.

---

## Manual Commands

```bash
node scripts/run-pipeline.mjs   # full sync — all feeds + vulnerability APIs
node scripts/doctor.mjs         # health check
```

---

## Skill Modes (in Claude)

Use these slash commands inside Claude to interact with the platform:

| Command | What it does |
|---|---|
| `/ingest` | Run the pipeline now from within Claude |
| `/analyze <url>` | Deep-analyze a single URL with full IOC/TTP extraction |
| `/brief banking` | Generate a sector threat brief (banking, government, or healthcare) |
| `/hunt APT28` | Search all threats by actor name, CVE ID, or IOC value |
| `/ioc export` | Export the current IOC list as CSV |
| `/stats` | Show pipeline statistics and feed health summary |
| `/feeds discover` | Ask Claude to suggest new feed sources to add |

---

## What Claude Extracts Per Article

| Category | Details |
|---|---|
| **CVEs** | ID, CVSS score, CVSS vector, severity, affected products, patch status |
| **IOCs** | IP, IPv6, domain, subdomain, URL, email, MD5, SHA1, SHA256, SHA512, file path, registry key, mutex, user-agent, ASN, Bitcoin address, YARA rule |
| **MITRE ATT&CK** | Tactic, technique ID, sub-technique, procedure description |
| **Threat Actors** | Name, aliases, origin country, motivation, sophistication level |
| **Context** | Malware families, affected products, geography, kill chain stage, sector impact |
| **Credibility** | 0–100 score based on source tier + technical richness + corroboration |

---

## Sectors Covered

- 🏦 **Banking** — financial institutions, crypto, payments, insurance
- 🏛️ **Government** — agencies, defense, critical infrastructure
- 🏥 **Healthcare** — hospitals, pharma, medical devices, health data

---

## Feed Sources (32 total)

| Tier | Sources |
|---|---|
| 1 — Official | CISA KEV (JSON API), NIST NVD (JSON API), GitHub Security Advisories, UK NCSC |
| 2 — Major vendors | CrowdStrike, Mandiant, Cisco Talos, Palo Alto Unit 42, Microsoft Security, Google TAG, Kaspersky, Check Point, Proofpoint, SentinelOne, Recorded Future |
| 3 — Security news | Krebs on Security, The Hacker News, Bleeping Computer, SecurityWeek, Dark Reading, CyberScoop, SANS ISC, Schneier on Security, Infosecurity Magazine, Sophos Naked Security |
| 4 — Sector-specific | BankInfoSecurity, GovInfoSecurity, Healthcare IT News, HIPAA Journal, Finextra |
| 5 — Supplementary | Graham Cluley, Threatpost |

---

## Architecture

```
32 feeds (CISA KEV, NVD, GitHub, CrowdStrike, Mandiant, Talos…)
  → ingestion/feed-fetcher.mjs    poll RSS + APIs (all feeds, every run)
  → ingestion/article-scraper.mjs fetch full article content
  → ingestion/dedup.mjs           skip already-seen articles
  → intelligence/analyzer.mjs     Claude extraction (CVEs, IOCs, TTPs, actors)
  → intelligence/normalizer.mjs   schema enforcement
  → intelligence/credibility.mjs  0–100 credibility score
  → intelligence/correlator.mjs   link related threats
  → data/threats.db               SQLite (WAL mode)
  → portal/server.mjs             Express + SSE
  → localhost:3000                live portal
```

---

## API Keys Required

| Key | Where to get it | Required? |
|---|---|---|
| `ANTHROPIC_API_KEY` | https://console.anthropic.com → API Keys | **Yes** — Claude is the intelligence engine |
| `PORT` | Set in `.env` (default: 3000) | No |

No other API keys are needed. NVD, CISA, GitHub Advisories, and all RSS feeds are free and unauthenticated.

---

## Config Files

| File | Purpose |
|---|---|
| `config/feeds.yml` | 32 feed sources — add new ones here |
| `config/sectors.yml` | Sector keywords and regulatory frameworks |
| `config/settings.yml` | Model, max articles per run, credibility weights |
| `.env` | `ANTHROPIC_API_KEY` and optional `PORT` |

---

## Frequently Asked Questions

**Does the website update automatically when the pipeline runs?**
Yes. The portal uses Server-Sent Events (SSE). When the pipeline finishes analyzing a batch of threats, the browser receives a push notification and refreshes the data — no page reload needed.

**How much does it cost to run?**
Each article analysis costs roughly $0.001–$0.003 with Claude Sonnet (prompt caching reduces costs ~80%). A typical 3-hour run analyzing 50 articles costs under $0.10.

**Can I add more feeds?**
Yes — edit `config/feeds.yml` and add an entry following the existing format. The pipeline picks it up on the next run.

**What does "Sync Now" do?**
It immediately triggers the same pipeline that runs automatically every 3 hours — fetches all 32 feeds, scrapes articles, sends them to Claude for analysis, and streams results to the portal.

**Why is a feed showing as failed?**
Some feeds change URLs or go offline. Check `localhost:3000/feeds.html` for error details. You can disable a broken feed in `config/feeds.yml` by setting `enabled: false`.
