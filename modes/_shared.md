# Shared Context — Claude Threat Intelligence Platform

## What this platform is

An AI-powered threat intelligence engine where **Claude is the brain**. No AlienVault, no OTX. Claude reads raw security articles, extracts structured threat data, and normalizes it into a queryable schema covering 3 sectors: **Banking**, **Government**, and **Healthcare**.

## Data files you can read

- `config/feeds.yml` — all 32 RSS/API sources
- `config/sectors.yml` — sector keyword definitions
- `config/settings.yml` — global settings
- `data/threats.db` — SQLite database (use `node scripts/migrate.mjs` to verify schema)
- `reports/` — generated sector briefs

## Database schema (key tables)

- `threats` — core threat records (id, title, severity, threat_type, credibility_score, sectors, sector_impact, published_at, ingested_at)
- `threat_cves` — CVEs linked to threats (cve_id, cvss_score, in_kev, exploited_in_wild)
- `threat_iocs` — IOCs (ioc_type, ioc_value, confidence, malware_family)
- `threat_ttps` — MITRE ATT&CK mappings (mitre_id, tactic, technique, procedure)
- `threat_actors` — attributed actors (name, origin_country, motivation, sophistication)
- `feed_health` — per-feed health status
- `feed_runs` — pipeline run history
- `ioc_index` — global IOC deduplication table

## Sectors

- **banking** — financial institutions, payment, crypto, insurance
- **government** — agencies, defense, critical infrastructure
- **healthcare** — hospitals, pharma, medical devices, health data

## Pipeline rotation

- **Slot A** (0,6,12,18 UTC): Vulnerability APIs — NVD CVEs, CISA KEV, GitHub Advisories
- **Slot B** (3,9,15,21 UTC): News/blog RSS feeds — 28 sources across 5 tiers

## Severity scale

- **critical** — active exploitation, mass impact, life-safety risk
- **high** — high confidence threat, significant sector exposure
- **medium** — credible threat, moderate exposure
- **low** — early warning, limited confirmed impact

## Credibility score (0-100)

- Source tier (0-40) + Technical richness (0-30) + Corroboration (0-20) + Specificity (0-10)
- Corroboration: when multiple sources report the same event, scores rise automatically

## Common queries

```bash
# Run pipeline now
node scripts/run-pipeline.mjs

# Slot A only (vulnerability APIs)
node scripts/run-pipeline.mjs --slot-a

# Slot B only (news feeds)
node scripts/run-pipeline.mjs --slot-b

# Start portal
node portal/server.mjs

# Health check
node scripts/doctor.mjs
```
