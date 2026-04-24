# /analyze — Deep Analyze a Specific URL or Article

Performs a deep Claude-powered analysis of a specific security article or URL, outside the normal pipeline flow.

## Usage

```
/analyze <url>
/analyze <url> --save      # save result to database
/analyze <url> --sector banking  # focus analysis on a sector
```

## What to do

1. Fetch the full content of the URL using the WebFetch tool or `scrapeArticle()`
2. Send to `intelligence/analyzer.mjs` → `analyzeArticle()` with highest credibility setting
3. Display the full normalized threat record:

```
THREAT ANALYSIS REPORT
═══════════════════════
Title: [extracted title]
Severity: [critical/high/medium/low]
Threat Type: [type]
Credibility: [score]/100

SUMMARY
[3-sentence executive brief]

SECTORS AFFECTED
Banking: [score]/100 — [reason]
Government: [score]/100 — [reason]  
Healthcare: [score]/100 — [reason]

CVEs ([count])
[list each with CVSS score]

IOCs ([count])
[list each with type, value, confidence]

MITRE ATT&CK TTPs ([count])
[list each]

THREAT ACTORS
[list each]

REMEDIATION
[list steps]
```

4. If `--save` flag: store in database and output the threat ID for portal viewing.

## Context

Read `_shared.md` for schema and sector definitions.
