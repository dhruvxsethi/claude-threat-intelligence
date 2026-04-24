# Claude Threat Intelligence

AI-powered threat intelligence platform. Claude reads global security feeds, extracts structured intelligence, and serves it on a live portal.

**Claude IS the engine** — no AlienVault, no OTX. Every article is analyzed by Claude Sonnet to extract CVEs, IOCs, TTPs, threat actors, and sector impact.

## Quick Start

```bash
git clone https://github.com/dhruvxsethi/claude-threat-intelligence
cd claude-threat-intelligence
npm install
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
node portal/server.mjs         # portal at http://localhost:3000
node scripts/run-pipeline.mjs  # run first ingest (separate terminal)
```

## Portal Pages

| Page | URL |
|---|---|
| Dashboard | `localhost:3000` |
| Threat Feed | `localhost:3000/threats.html` |
| Sectors | `localhost:3000/sectors.html` |
| IOC Explorer | `localhost:3000/iocs.html` |
| Feed Health | `localhost:3000/feeds.html` |

## What's Automated

| What | How | When |
|---|---|---|
| Pipeline — vulnerability APIs | Claude scheduled task `cti-pipeline-3hr` | 0, 6, 12, 18 UTC |
| Pipeline — news/blog feeds | Claude scheduled task `cti-pipeline-3hr` | 3, 9, 15, 21 UTC |
| Portal live refresh | Server-Sent Events (SSE) | Real-time on pipeline completion |
| Cross-threat correlation | Built into pipeline | Every run |
| Credibility scoring | Built into pipeline | Every article |

**You only need to keep `node portal/server.mjs` running.** The pipeline runs automatically via Claude's scheduler every 3 hours. The portal updates itself via SSE — no page reload needed.

## Manual Commands

```bash
node scripts/run-pipeline.mjs           # run both slots
node scripts/run-pipeline.mjs --slot-a  # vulnerability APIs only (NVD, CISA KEV, GitHub)
node scripts/run-pipeline.mjs --slot-b  # news/blog feeds only
node scripts/doctor.mjs                 # health check
```

## Skill Modes (in Claude)

```
/ingest          run pipeline now
/analyze <url>   deep analyze a URL
/brief banking   sector threat brief
/hunt APT28      search by actor/CVE/IOC
/ioc export      export IOC list
/stats           pipeline statistics
/feeds discover  find new feed sources
```

## Architecture

```
32 feeds (CISA, NVD, CrowdStrike, Mandiant, Talos, Krebs…)
  → ingestion/feed-fetcher.mjs   (poll RSS + APIs)
  → ingestion/article-scraper.mjs (fetch full content)
  → ingestion/dedup.mjs           (skip already-seen)
  → intelligence/analyzer.mjs     (Claude extraction)
  → intelligence/normalizer.mjs   (schema enforcement)
  → intelligence/credibility.mjs  (0-100 score)
  → intelligence/correlator.mjs   (link related threats)
  → data/threats.db               (SQLite)
  → portal/server.mjs             (Express + SSE)
  → localhost:3000                (dashboard)
```

## Sectors Covered

- 🏦 **Banking** — financial institutions, crypto, payments, insurance
- 🏛️ **Government** — agencies, defense, critical infrastructure
- 🏥 **Healthcare** — hospitals, pharma, medical devices, health data

## Extracted Per Article

CVEs · CVSS scores · IOCs (IP, domain, hash, URL, email, registry key, mutex, YARA…) · MITRE ATT&CK TTPs · Threat actors (name, origin, motivation, sophistication) · Malware families · Affected products · Geography · Kill chain stage · Sector impact scores · Credibility score

## Config

| File | Purpose |
|---|---|
| `config/feeds.yml` | 32 feed sources (add new ones here) |
| `config/sectors.yml` | Sector keywords and definitions |
| `config/settings.yml` | Model, intervals, thresholds |
| `.env` | `ANTHROPIC_API_KEY`, `PORT` |

## Deploy to Vercel

The portal is a standard Express app. For Vercel: add a `vercel.json` routing Express as a serverless function, or deploy as a standalone Node server on Vercel's infrastructure. Set `ANTHROPIC_API_KEY` in Vercel environment variables.
