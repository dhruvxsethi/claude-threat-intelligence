# /ioc — IOC Export and Lookup

Export IOCs from a time window, look up a specific IOC, or generate an IOC feed.

## Usage

```
/ioc export --days 7           # export all IOCs from last 7 days
/ioc export --type ip --days 1 # export only IPs from last 24h
/ioc lookup 1.2.3.4            # look up a specific IOC
/ioc lookup CVE-2024-1234      # look up by CVE
/ioc stats                     # IOC statistics summary
```

## What to do

### export
1. Query `threat_iocs` joined with `threats` for the time window
2. Filter by type if specified
3. Output in multiple formats:

```
IOC EXPORT — [date range]
══════════════════════════
Total: N IOCs  |  Types: ip(X) domain(Y) hash(Z) ...

IPs (N)
  1.2.3.4  [confidence: 90%]  [LockBit C2]  [linked: CVE-2024-XXXX]
  ...

Domains (N)
  evil.com  [confidence: 85%]  [Phishing kit]
  ...

Hashes (N) 
  [SHA256]  [confidence: 95%]  [Ransomware payload: LockBit 3.0]
  ...
```

4. Also output raw list for copy-paste into SIEM/firewall

### lookup
1. Search `ioc_index` for exact match
2. Pull all linked threats, malware families, context
3. Output full IOC profile with historical context

### stats
- Total IOCs by type
- Top malware families
- Highest confidence IOCs
- Newly seen vs recurring

## Context

Read `_shared.md` for database schema.
