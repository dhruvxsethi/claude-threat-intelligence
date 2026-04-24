# Claude Threat Intelligence Platform

AI-powered global threat intelligence platform. Claude IS the intelligence engine — no AlienVault, no OTX. Claude reads raw articles, extracts structured threat data, and normalizes it into a unified schema.

## Quick Start

```bash
npm install
cp .env.example .env          # add ANTHROPIC_API_KEY
node scripts/setup.mjs        # initialize database + validate config
node portal/server.mjs        # start portal at localhost:3000
node scripts/run-pipeline.mjs # manual ingestion run
```

## Architecture

```
Feed Sources (30+ RSS/APIs)
    ↓
ingestion/feed-fetcher.mjs    → polls feeds, deduplicates
ingestion/article-scraper.mjs → fetches full article content
    ↓
intelligence/analyzer.mjs     → Claude extracts all threat data (THE BRAIN)
intelligence/normalizer.mjs   → enforces schema
intelligence/credibility.mjs  → scores source credibility + corroboration
intelligence/correlator.mjs   → links related threats by actor/CVE/TTP
    ↓
SQLite (data/threats.db)
    ↓
portal/server.mjs             → Express API + SSE real-time updates
portal/public/                → Dashboard UI
```

## 3-Hour Rotation Slots

| Slot (UTC) | Focus |
|---|---|
| 0:00, 6:00, 12:00, 18:00 | Vulnerability APIs (NVD, CISA KEV, GitHub Advisories) + quick news scan |
| 3:00, 9:00, 15:00, 21:00 | Deep news/blog feeds + threat actor intelligence |

Claude only analyzes articles it hasn't seen before (URL + content hash deduplication). API calls are cheap and always run.

## Skill Modes

| Command | What it does |
|---|---|
| `/ingest` | Trigger full ingestion pipeline now |
| `/analyze` | Deep-analyze a specific URL |
| `/brief` | Generate sector briefing (banking/government/healthcare) |
| `/report` | Daily/weekly markdown intelligence report |
| `/hunt` | Search threats by actor, CVE, keyword |
| `/ioc` | Export IOCs from a time window |
| `/stats` | Pipeline health, feed coverage, gap analysis |
| `/feeds` | Update and validate feed sources |

## Normalized Threat Schema

Every article becomes this:
- `id`, `title`, `severity` (critical/high/medium/low), `threat_type`
- `sectors[]` — banking, government, healthcare
- `threat_actors[]` — name, aliases, origin_country, motivation, sophistication
- `cves[]` — cve_id, cvss_score, cvss_vector, affected_products, patch_available, in_kev
- `iocs[]` — type (ip/domain/hash_md5/hash_sha1/hash_sha256/url/email/file_path/registry_key/mutex), value, confidence
- `ttps[]` — mitre_id, tactic, technique, procedure
- `malware_families[]` — name, type, aliases
- `affected_products[]` — vendor, product, version_range
- `geography[]` — targeted countries/regions
- `kill_chain_stage` — reconnaissance/weaponization/delivery/exploitation/installation/c2/actions
- `credibility_score` (0-100) — weighted: source tier + technical richness + corroboration
- `summary` — 3-sentence Claude-generated executive brief
- `sector_impact` — per-sector risk assessment
- `related_threat_ids[]` — linked threats sharing actor/CVE/TTP

## Sectors

- **Banking** — financial institutions, payment processors, crypto exchanges, fintech
- **Government** — federal agencies, defense contractors, critical infrastructure, elections
- **Healthcare** — hospitals, pharma, medical devices, health insurers, biotech

## Config Files

- `config/feeds.yml` — all RSS/API sources with metadata (never auto-overwritten)
- `config/sectors.yml` — sector keywords and definitions (never auto-overwritten)
- `config/settings.yml` — global settings: model, intervals, thresholds

## Data Layer

- `data/threats.db` — SQLite: threats, iocs, cves, ttps, threat_actors, feed_runs tables
- `data/raw/` — cached raw article HTML (gitignored)
- `reports/` — generated sector briefs and digests (gitignored)

## Environment Variables

```
ANTHROPIC_API_KEY=sk-ant-...    # required
PORT=3000                        # portal port (default 3000)
NODE_ENV=development
```
