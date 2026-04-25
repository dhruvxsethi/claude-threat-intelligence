# Claude Threat Intelligence Platform

AI-powered global threat intelligence platform. The AI analyst backend reads raw articles, extracts structured threat data, and normalizes it into a unified schema. AlienVault/OTX/XSIAM are not intelligence sources for ingestion; they are comparison targets for gap tracking.

## Quick Start

```bash
npm install
cp .env.example .env          # add OLLAMA_MODEL or ANTHROPIC_API_KEY
npm run setup                 # initialize database + validate config
npm start                     # start portal at localhost:3000
npm run ingest                # manual ingestion run
```

## Architecture

```
Feed Sources (30+ RSS/APIs)
    ↓
ingestion/feed-fetcher.mjs    → polls feeds, deduplicates
ingestion/article-scraper.mjs → fetches full article content
    ↓
intelligence/analyzer.mjs     → Ollama or Claude extracts threat data
intelligence/normalizer.mjs   → enforces schema
intelligence/credibility.mjs  → scores source credibility + corroboration
intelligence/correlator.mjs   → links related threats by actor/CVE/TTP
    ↓
SQLite (data/threats.db)
    ↓
portal/server.mjs             → Express API + SSE real-time updates
portal/public/                → Dashboard UI
```

## Runtime Schedule

Configured in `config/settings.yml`.

| Schedule | Focus |
|---|---|
| Hourly (`0 * * * *`) | Vulnerability APIs (NVD, CISA KEV, GitHub Advisories) + RSS/blog feeds |
| Weekly (`0 2 * * 1`) | Source discovery suggestions |

The pipeline only analyzes articles it has not seen before using URL and content-hash deduplication. API sources are checked every run and are also deduplicated before storage.

## Operator Intents

These are intended agent/operator actions, not separate CLI binaries unless implemented in `package.json`.

| Intent | What it does |
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
- `summary` — 3-sentence Codex-generated executive brief
- `sector_impact` — per-sector risk assessment
- `related_threat_ids[]` — linked threats sharing actor/CVE/TTP
- `evidence[]` — source article, extraction time, and reason it matters
- `gap_status` — seen by us first / seen elsewhere / not seen elsewhere
- `external_sightings[]` — optional OTX/XSIAM/vendor comparison data

## Sectors

- **Banking** — financial institutions, payment processors, crypto exchanges, fintech
- **Government** — federal agencies, defense contractors, critical infrastructure, elections
- **Healthcare** — hospitals, pharma, medical devices, health insurers, biotech

## Config Files

- `config/feeds.yml` — all RSS/API sources with metadata (never auto-overwritten)
- `config/sectors.yml` — sector keywords and definitions (never auto-overwritten)
- `config/settings.yml` — global settings: model, intervals, thresholds

## Data Layer

- `data/threats.db` — SQLite: threats, iocs, cves, ttps, threat_actors, feed_runs, threat_evidence, external_sightings, discovered_sources tables
- `data/raw/` — cached raw article HTML (gitignored)
- `reports/` — generated sector briefs and digests (gitignored)

## Environment Variables

```
OLLAMA_MODEL=qwen2.5:7b          # optional local backend
OLLAMA_BASE_URL=http://localhost:11434
ANTHROPIC_API_KEY=sk-ant-...     # optional Claude backend
PORT=3000                        # portal port (default 3000)
NODE_ENV=development
```
