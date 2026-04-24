# /stats — Pipeline Statistics and Coverage Analysis

Shows pipeline health, feed coverage, threat statistics, and identifies gaps.

## Usage

```
/stats
/stats --days 30
/stats feeds     # focus on feed health
/stats coverage  # identify coverage gaps
```

## What to do

Query the database and output:

```
PIPELINE STATISTICS
════════════════════════════════════════

THREATS (last 7 days)
  Total: N  |  Critical: X  |  High: Y  |  Medium: Z  |  Low: W
  CVEs: N  |  In CISA KEV: N  |  IOCs: N  |  Actors: N

SECTORS
  Banking:    N threats  (X critical)
  Government: N threats  (X critical)
  Healthcare: N threats  (X critical)

TOP SOURCES (by threat count)
  1. CrowdStrike Blog — N threats
  2. NIST NVD — N threats
  ...

FEED HEALTH
  Healthy: X/32  |  Failed: Y  |  Degraded: Z
  Failed feeds: [list]

PIPELINE RUNS
  Today: N runs  |  This week: N runs
  Last run: [time]  |  Next scheduled: [time]
  Avg threats/run: N
  Avg articles analyzed/run: N

COVERAGE GAPS
  [Claude analysis: which threat types/sectors are underrepresented]
  [Suggested new feed sources to add]

CREDIBILITY DISTRIBUTION
  Very High (80-100): N%
  High (60-79): N%
  Moderate (40-59): N%
  Low (<40): N%
```

If coverage gaps detected, suggest specific feed URLs to add to `config/feeds.yml`.

## Context

Read `_shared.md`. Query all relevant tables from the database.
