# /feeds — Manage and Update Feed Sources

Manage the feed list, check health, discover new sources, and update `config/feeds.yml`.

## Usage

```
/feeds status         # show all feed health
/feeds discover       # Claude discovers new security feeds to add
/feeds add <url>      # add a new feed
/feeds disable <id>   # disable a failing feed
/feeds test <url>     # test if a URL is a valid feed
```

## What to do

### status
Show `feed_health` table in a readable format with health indicators.

### discover
Use WebSearch to find high-quality threat intelligence RSS feeds not already in `config/feeds.yml`. Focus on:
- Sector-specific sources (banking security, government CERT, healthcare IT security)
- Threat research blogs from major security vendors
- National CERT/CSIRT RSS feeds (EU, APAC, MENA regions)
- Dark web monitoring report feeds (public only)

For each discovered feed:
1. Verify it's a valid RSS/Atom feed
2. Check it's not already in `config/feeds.yml`
3. Assign a tier (1-5) and source_credibility score
4. Suggest it to user before adding

### add
1. Validate the URL is a working feed
2. Determine appropriate tier and sectors
3. Add to `config/feeds.yml` with proper metadata
4. Do NOT auto-overwrite user entries — append only

### test
Fetch the feed URL and report: valid RSS?, item count, most recent item date, avg content length.

## Context

Read `config/feeds.yml` for current feeds. Read `_shared.md` for tier definitions.
