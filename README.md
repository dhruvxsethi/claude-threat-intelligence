# Claude Threat Intelligence Platform

AI-powered global threat intelligence. Claude reads 32 security feeds every 3 hours, extracts structured data from every article, and serves a live portal that updates automatically.

**Claude IS the engine.** No AlienVault. No OTX. Every article is sent to Claude Sonnet which extracts CVEs, IOCs, MITRE ATT&CK TTPs, threat actors, sector impact, and credibility scores.

---

## How to Run

```bash
# 1. Install dependencies (once)
npm install

# 2. Add your Anthropic API key
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# 3. Start the portal (keep this running)
node portal/server.mjs

# 4. First sync (run in a separate terminal)
node scripts/run-pipeline.mjs
```

The portal runs at **http://localhost:3000**. Keep `server.mjs` running — it serves the portal and automatically triggers the pipeline every 3 hours.

---

## Why Do I Need an Anthropic API Key?

Claude is the intelligence engine. It reads the raw article text and extracts all the structured threat data. Without the key, feeds are fetched but nothing is analyzed — the threat database stays empty.

**Get your key:** https://console.anthropic.com → API Keys → Create Key

Cost: ~$0.001–$0.003 per article with Claude Sonnet. A typical 3-hour run (50 articles) costs under $0.10. Prompt caching reduces token costs by ~80%.

No other API keys needed — NVD, CISA, GitHub, and all RSS feeds are free and unauthenticated.

---

## Portal Pages

| Page | URL | What you see |
|---|---|---|
| **Dashboard** | `localhost:3000` | Metrics strip (critical/high/medium/CVEs/IOCs), latest threats table, charts, top CVEs, threat actors |
| **Threat Feed** | `localhost:3000/threats.html` | Full paginated list with filters (severity, sector, type, date range) |
| **Sectors** | `localhost:3000/sectors.html` | Banking / Government / Healthcare breakdowns — top CVEs, actors, threat tables |
| **IOC Explorer** | `localhost:3000/iocs.html` | All extracted indicators (IPs, domains, hashes…), filterable, CSV export |
| **Feed Health** | `localhost:3000/feeds.html` | Per-feed status, last success, run history |
| **Threat Detail** | Click any threat title | Full CVEs, IOCs, TTPs, actors, sector impact scores, related threats |

---

## What's Automated

| What | How | When |
|---|---|---|
| Full pipeline — all 32 feeds + vulnerability APIs | Built-in cron in `portal/server.mjs` | Every 3 hours (0:00, 3:00, 6:00… UTC) |
| Portal data refresh | Server-Sent Events (SSE) | Real-time on pipeline completion — no page reload |
| Cross-threat correlation | Built into pipeline | Every run |
| Credibility scoring | Built into pipeline | Every article |
| Deduplication | URL + content hash | Every article (skips already-seen content) |

**You only need `node portal/server.mjs` running.** Everything else is automatic.

The **↻ Sync Now** button in the sidebar manually triggers an immediate pipeline run identical to the scheduled one.

---

## Skill Commands (in Claude)

Use these slash commands inside a Claude session to interact with the platform directly:

| Command | What it does |
|---|---|
| `/ingest` | Trigger a full pipeline run from within Claude |
| `/analyze <url>` | Deep-analyze a single URL — full IOC/TTP/actor extraction |
| `/brief banking` | Generate a sector threat brief (banking, government, or healthcare) |
| `/hunt APT28` | Search all threats by actor name, CVE ID, or IOC value |
| `/ioc export` | Export the current IOC list as a CSV |
| `/stats` | Pipeline statistics, feed health, coverage gaps |
| `/feeds discover` | Ask Claude to suggest new feed sources to add |

---

## What Claude Extracts Per Article

| Category | What's extracted |
|---|---|
| **CVEs** | ID, CVSS score + vector, severity, affected products, patch status, in CISA KEV |
| **IOCs** | IP, IPv6, domain, subdomain, URL, email, MD5, SHA1, SHA256, SHA512, file path, registry key, mutex, user-agent, ASN, Bitcoin address, YARA rule |
| **MITRE ATT&CK** | Tactic, technique ID (e.g. T1059), sub-technique, procedure description |
| **Threat Actors** | Name, aliases, origin country, motivation, sophistication level |
| **Context** | Malware families, affected products, targeted geography, kill chain stage |
| **Sector Impact** | Per-sector (banking/government/healthcare) risk score + reasoning |
| **Credibility** | 0–100 score: source tier (40pts) + technical richness (30pts) + corroboration (20pts) + specificity (10pts) |
| **Summary** | 3-sentence executive brief |

---

## Feed Sources (32 total)

| Tier | Sources |
|---|---|
| 1 — Official | CISA KEV (JSON API), NIST NVD (JSON API), GitHub Security Advisories, UK NCSC |
| 2 — Major vendors | CrowdStrike, Mandiant, Cisco Talos, Palo Alto Unit 42, Microsoft Security, Google TAG, Kaspersky, Check Point, Proofpoint, SentinelOne, Recorded Future |
| 3 — Security news | Krebs on Security, The Hacker News, Bleeping Computer, SecurityWeek, Dark Reading, CyberScoop, SANS ISC, Schneier on Security, Infosecurity Magazine, Sophos Naked Security |
| 4 — Sector-specific | BankInfoSecurity, GovInfoSecurity, Healthcare IT News, HIPAA Journal, Finextra |
| 5 — Supplementary | Graham Cluley, Threatpost |

**Note:** CISA advisory RSS (`/cybersecurity-advisories/feed`) is disabled — it returns 404. CISA KEV JSON API covers the same data.

---

## Architecture

```
32 feeds (CISA KEV JSON, NVD JSON, GitHub Advisories, 28 RSS feeds)
  │
  ├─ ingestion/feed-fetcher.mjs     poll all feeds in parallel (no slot rotation)
  ├─ ingestion/article-scraper.mjs  fetch full article content + extract IOC hints
  ├─ ingestion/dedup.mjs            skip seen URLs and duplicate content (SHA256 hash)
  │
  ├─ intelligence/analyzer.mjs      Claude Sonnet extraction (THE BRAIN)
  ├─ intelligence/normalizer.mjs    enforce schema, validate fields
  ├─ intelligence/credibility.mjs   0–100 credibility score
  ├─ intelligence/correlator.mjs    link threats sharing CVE/IOC/actor/malware
  │
  ├─ data/threats.db                SQLite (WAL mode) — 10 normalized tables
  │
  ├─ portal/server.mjs              Express API + SSE + built-in cron scheduler
  └─ portal/public/                 Dashboard UI
```

### Database Tables
`threats` · `threat_cves` · `threat_iocs` · `threat_ttps` · `threat_actors` · `feed_runs` · `articles` · `corroborations` · `feed_health` · `ioc_index`

---

## Configuration Files

| File | Purpose | Auto-overwritten? |
|---|---|---|
| `config/feeds.yml` | All 32 feed sources — add/disable feeds here | No |
| `config/sectors.yml` | Sector keywords and regulatory frameworks | No |
| `config/settings.yml` | Claude model, max articles per run, credibility weights | No |
| `.env` | `ANTHROPIC_API_KEY` and optional `PORT` | No |

---

## Sectors Covered

- 🏦 **Banking** — financial institutions, payment processors, crypto exchanges, fintech
- 🏛️ **Government** — federal agencies, defense contractors, critical infrastructure
- 🏥 **Healthcare** — hospitals, pharma, medical devices, health insurers, biotech

---

## Manual Commands

```bash
node portal/server.mjs           # start portal + scheduler (keep running)
node scripts/run-pipeline.mjs    # manual full sync — all feeds + APIs
node scripts/doctor.mjs          # health check — validates config, DB, API key
```

---

## Known Issues / Status

| Item | Status |
|---|---|
| CISA advisory RSS | Disabled — URL returns 404, covered by KEV JSON |
| Slot A/B rotation | Removed — single unified run fetches everything |
| Portal auto-update | Working via SSE |
| GitHub Advisories API rate limiting | No auth token — rate limited to 60 req/hr (fine for current usage) |

---

## FAQ

**Does the website update automatically when the pipeline runs?**
Yes. SSE pushes a notification to all open browser tabs the moment the pipeline finishes. The dashboard refreshes its data immediately — no page reload.

**What's the "↻ Sync Now" button?**
It triggers the exact same pipeline that runs on the 3-hour schedule. Use it when you want fresh data immediately.

**Can I add more feeds?**
Edit `config/feeds.yml` and follow the existing format. Set `enabled: true`. The next pipeline run (or Sync Now) picks it up automatically.

**What if a feed is failing?**
Check `localhost:3000/feeds.html` for the error message. If the URL changed, update it in `config/feeds.yml`. If it's consistently broken, set `enabled: false`.

**How much does it cost?**
Claude Sonnet with prompt caching is ~$0.001–$0.003 per article. 50 articles = under $0.10 per run. 8 runs/day = under $0.80/day.
