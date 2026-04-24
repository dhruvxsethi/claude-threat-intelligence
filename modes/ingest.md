# /ingest — Trigger Ingestion Pipeline

Triggers the threat intelligence ingestion pipeline immediately, outside the 3-hour cron schedule.

## Usage

```
/ingest
/ingest --slot-a     # vulnerability APIs only (NVD, CISA KEV, GitHub)
/ingest --slot-b     # news/blog feeds only
/ingest --url <url>  # analyze a single specific URL
```

## What to do

1. If `--url` is specified: scrape the URL, analyze with Claude, store result, output the normalized threat record.

2. Otherwise, run the pipeline:
   - Read `config/settings.yml` for current slot logic
   - Run `node scripts/run-pipeline.mjs [--slot-a|--slot-b]`
   - Monitor output and summarize: articles fetched, analyzed, threats created, errors
   - If new threats were created with severity critical/high, highlight them

3. After completion, output a brief run summary:
   ```
   ✓ Pipeline complete
   Articles fetched: N
   Articles analyzed: N  
   Threats created: N (X critical, Y high)
   CVEs extracted: N
   IOCs extracted: N
   Duration: Xs
   ```

## Context

Read `_shared.md` for database schema and sector definitions.
