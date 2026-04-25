# Sentinel — Threat Intelligence Platform

AI-powered threat intelligence. Reads 32+ security feeds every hour, extracts CVEs / IOCs / TTPs / threat actors via Claude or Ollama, and serves a live portal at `localhost:3000`.

---

## Quick Start

```bash
npm install
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env   # get from console.anthropic.com
node portal/server.mjs                         # start portal (keep running)
node scripts/run-pipeline.mjs                  # first sync (separate terminal)
```

Portal: **http://localhost:3000**. After each sync, the UI refreshes automatically via SSE — no page reload needed.

---

## Using Ollama (free, local)

No Anthropic key needed if you have Ollama running locally.

```bash
ollama pull qwen2.5:7b    # ~4.7 GB — good balance on M4 MacBook
# or
ollama pull qwen2.5:14b   # ~9 GB — better extraction quality
```

Add to `.env`:
```
OLLAMA_MODEL=qwen2.5:7b
```

The pipeline switches automatically. No API costs.

---

## How It Works

```
32+ RSS feeds + NVD/CISA/GitHub APIs
         ↓
  portal/server.mjs       ← Express server + hourly cron
         ↓
  scripts/run-pipeline.mjs
    1. Fetch NVD CVEs + CISA KEV (vulnerability APIs)
    2. Poll RSS feeds (30+ sources)
    3. Scrape full article content
    4. Deduplicate by URL + content hash
    5. Send to Claude/Ollama → structured JSON (CVEs, IOCs, TTPs, actors)
    6. Normalize + save to SQLite
    7. Notify portal → SSE → UI auto-refreshes
         ↓
     SQLite (data/threats.db)
         ↓
     Portal UI (localhost:3000)
```

## Data Freshness Model

- The portal scheduler runs the full pipeline hourly by default (`config/settings.yml` → `pipeline.cron_schedule`).
- Vulnerability APIs run every pipeline cycle. NVD is queried with both `pubStartDate` and `pubEndDate`, paginated, and deduped before model analysis.
- GitHub Security Advisories are ingested as first-class advisory items and normalized through the same AI extraction path as articles.
- RSS items are deduped by normalized URL and content hash. New RSS items older than `claude.max_article_age_hours` are marked stale so old backlog does not consume the analysis budget.
- Fresh RSS items are analyzed newest-first, up to `claude.max_articles_per_run`.
- Pipeline runs are written to `feed_runs`, and source health is written to `feed_health`.

## Gap Tracking & Evidence

- Every newly saved threat gets an evidence trail: source article/advisory, extraction summary, extraction time, and initial gap status.
- Gap status starts as `not_seen_elsewhere`. Sync or import OTX/AlienVault sightings later to mark threats as `seen_elsewhere` or `seen_by_us_first`.
- OTX can be synced directly when `OTX_API_KEY` is present in `.env`. OTX is used as an external comparison source, not as the primary intelligence source.
- Import external sightings with:

```bash
npm run import:sightings -- sightings.json
```

Expected JSON fields include `provider`, `external_id`, `first_seen_at`, `url`, `cve_id`, `ioc_type`, and `ioc_value`. Matching is done by URL, CVE, or IOC.
- Sync OTX directly with:

```bash
npm run sync:otx
```

- Threat detail pages include an Evidence tab showing source material, extraction evidence, external sightings, and gap status.

## Source Discovery

Source discovery suggests candidate RSS/Atom feeds and stores them for review in the Feed Health page. It does not automatically edit `config/feeds.yml`.

```bash
npm run discover:sources
```

The portal also schedules discovery weekly by default (`feeds.discovery_cron_schedule`).

**"Sync Now" button** — triggers the pipeline immediately from the browser. The portal runs it as a child process and broadcasts a `pipeline_done` event when it's done, causing all connected browsers to reload their data without a page refresh.

**Hourly cron** — runs automatically inside `portal/server.mjs` every hour as long as the portal is running.

**Ollama** — the pipeline calls Ollama's local API (`http://localhost:11434`) instead of Anthropic's API when `OLLAMA_MODEL` is set. Ollama must be running separately (`ollama serve`).

---

## Sharing / Remote Access

Sentinel uses a local SQLite file and a persistent Node.js server, so it **cannot be deployed to Vercel** (Vercel is serverless + no persistent file system).

To let someone else see your data:

```bash
npx ngrok http 3000
# → gives you a public URL like https://abc123.ngrok.io
```

Anyone with that URL sees your live portal in real time.

---

## Portal Pages

| Page | URL |
|---|---|
| Dashboard | `localhost:3000` |
| Threat Feed | `localhost:3000/threats.html` |
| Sectors | `localhost:3000/sectors.html` |
| IOC Explorer | `localhost:3000/iocs.html` |
| Feed Health | `localhost:3000/feeds.html` |
| Threat Detail | click any threat title |

---

## Slash Commands (in Claude)

```
/ingest          — run full pipeline now
/analyze <url>   — deep-analyze a single URL
/brief banking   — sector threat brief
/hunt APT28      — search by actor, CVE, or IOC
/ioc export      — export IOC list as CSV
/stats           — feed health and pipeline stats
```

---

## Config

| File | Purpose |
|---|---|
| `config/feeds.yml` | All 32+ feed sources — add/disable here |
| `config/settings.yml` | Model, max articles per run, intervals |
| `.env` | `ANTHROPIC_API_KEY` or `OLLAMA_MODEL` + `PORT` |

---

## Feed Sources

- **APIs:** CISA KEV, NIST NVD, GitHub Advisories
- **Tier 1 (vendors):** CrowdStrike, Mandiant, Talos, Unit 42, Microsoft, Google TAG, Kaspersky, Check Point, Proofpoint, SentinelOne, Recorded Future, Rapid7
- **Tier 2 (news):** Krebs, The Hacker News, Bleeping Computer, SecurityWeek, Dark Reading, CyberScoop, SANS ISC, Schneier, Infosecurity Magazine, Sophos
- **Tier 3 (sector):** BankInfoSecurity, GovInfoSecurity, Healthcare IT News, HIPAA Journal

---

## Commands

```bash
node portal/server.mjs         # start portal + hourly scheduler
node scripts/run-pipeline.mjs  # manual full sync
node scripts/setup.mjs         # initialize database + validate config
```
