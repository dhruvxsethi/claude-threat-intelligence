# /brief — Generate Sector Threat Intelligence Brief

Generates a professional threat intelligence brief for a specific sector, based on the last N hours/days of ingested data.

## Usage

```
/brief banking
/brief government
/brief healthcare
/brief all           # all 3 sectors
/brief banking --days 1   # last 24 hours
/brief banking --days 7   # last 7 days (default)
```

## What to do

1. Query `data/threats.db` for threats matching the sector in the specified time range
2. Pull: top threats by severity+credibility, active CVEs, IOCs, threat actors, TTPs
3. Call `generateSectorBrief()` from `intelligence/analyzer.mjs`
4. Output and save the brief to `reports/{YYYY-MM-DD}-{sector}-brief.md`

## Brief format

```markdown
# [SECTOR] Threat Intelligence Brief
**Period:** [date range]  **Generated:** [datetime]  **Threats Analyzed:** [N]

## Executive Summary
[2-3 sentence overview of current threat landscape for this sector]

## 🔴 Top Threats
1. **[Title]** (Critical) — [why it matters to this sector]
2. ...

## 👤 Active Threat Actors
[table: name, origin, motivation, sophistication, threats_this_period]

## 🔑 Critical CVEs to Patch
[table: CVE-ID, CVSS, product, in_kev, patch_available]

## 📊 IOC Summary
[counts by type, top high-confidence IOCs]

## 🎯 MITRE ATT&CK Coverage
[top tactics observed]

## ✅ Recommended Actions (Prioritized)
1. [Immediate — critical]
2. [This week — high]
3. [This month — medium]

## 📡 Threat Forecast
[what to watch for in next 24-48 hours based on current trends]
```

## Context

Read `_shared.md` for database schema. Read `config/sectors.yml` for sector definitions.
