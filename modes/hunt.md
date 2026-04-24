# /hunt — Search Across All Threat Intelligence

Search across the full threat database by actor name, CVE ID, IOC value, malware family, keyword, or any combination.

## Usage

```
/hunt APT28
/hunt CVE-2024-1234
/hunt 192.168.1.1
/hunt LockBit --days 30
/hunt "supply chain" --sector banking
/hunt <hash_value>
```

## What to do

1. Parse the search query — detect if it's a CVE, IP, hash, actor name, or keyword
2. Query appropriate tables:
   - CVE: `threat_cves` WHERE cve_id LIKE '%query%'
   - IP/domain/hash: `threat_iocs` WHERE ioc_value = query
   - Actor: `threat_actors` WHERE name LIKE '%query%'
   - General: `threats` WHERE title/summary LIKE '%query%'
3. Cross-reference: for each hit, pull all linked threats, CVEs, IOCs, actors
4. Output structured results:

```
HUNT RESULTS: "[query]"
════════════════════════
Found in 7 threats across 14 days

THREATS
─────────────────────────────────────────
[severity] [title] — [date] — [source]
  CVEs: [list]  IOCs: [count]  Sectors: [list]

TIMELINE
─────────────────────────────────────────
[chronological view of all appearances]

LINKED IOCs (if hunting actor/malware)
─────────────────────────────────────────
[all IOCs associated with this entity]

MITRE ATT&CK PATTERNS
─────────────────────────────────────────
[TTPs seen across all related threats]

ASSESSMENT
─────────────────────────────────────────
[Claude's analysis of what these results mean]
```

## Context

Read `_shared.md` for database schema.
