import Anthropic from '@anthropic-ai/sdk';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const client = new Anthropic();

function loadSectors() {
  return yaml.load(readFileSync(join(ROOT, 'config/sectors.yml'), 'utf8'));
}

// System prompt is constant — eligible for prompt caching (saves ~80% tokens per run)
const SYSTEM_PROMPT = `You are an elite threat intelligence analyst with deep expertise in cybersecurity, nation-state APTs, ransomware operations, vulnerability research, and sector-specific threat landscapes. You analyze raw security articles and extract highly structured, normalized threat intelligence.

Your analysis must be exhaustive, precise, and actionable. Extract ONLY what is explicitly stated or strongly implied in the article — never hallucinate IOCs, CVEs, or threat actor names. When uncertain, use lower confidence scores.

You will return a single JSON object. Every field is required (use null or empty arrays if not found).

EXTRACTION RULES:
- CVE IDs: exact format CVE-YYYY-NNNNN. Extract ALL mentioned, even in passing.
- IOCs: Extract IPs, domains, URLs, file hashes (MD5/SHA1/SHA256/SHA512), email addresses, file paths, registry keys, mutex names, YARA rules, ASNs, Bitcoin addresses. Defang if needed (e.g., 1[.]2[.]3[.]4 → 1.2.3.4).
- MITRE ATT&CK: Use exact technique IDs (T1566.001, not just "phishing"). Include subtechniques.
- Threat actors: Use canonical names. Note all aliases mentioned.
- Severity: base on CVSS scores if present, or attacker capability + impact if not.
- Credibility: you will receive source_credibility (0-100) — factor it into ioc confidence scores.
- Geography: be specific — countries, not just regions.
- Kill chain: use Lockheed Martin Kill Chain stages.
- Sector relevance: score 0-100 for banking, government, healthcare based on article content.

Respond ONLY with valid JSON. No markdown, no explanation.`;

const EXTRACTION_SCHEMA = `{
  "title": "string — concise threat title (max 100 chars)",
  "summary": "string — 3-sentence executive brief: what happened, who's affected, what to do",
  "severity": "critical|high|medium|low|unknown",
  "threat_type": "ransomware|apt|phishing|vulnerability|data_breach|ddos|supply_chain|insider_threat|cryptojacking|malware|fraud|espionage|zero_day|other",
  "kill_chain_stage": "reconnaissance|weaponization|delivery|exploitation|installation|c2|actions_on_objectives|unknown",
  "sectors": ["banking","government","healthcare"],
  "sector_impact": {
    "banking": {"score": 0, "reason": "string"},
    "government": {"score": 0, "reason": "string"},
    "healthcare": {"score": 0, "reason": "string"}
  },
  "geography": ["country or region names"],
  "threat_actors": [
    {
      "name": "string",
      "aliases": ["string"],
      "origin_country": "string|null",
      "motivation": "financial|espionage|sabotage|hacktivism|cyberwarfare|unknown",
      "sophistication": "nation_state|advanced|intermediate|basic|script_kiddie|unknown",
      "active_since": "YYYY|null",
      "description": "string"
    }
  ],
  "cves": [
    {
      "cve_id": "CVE-YYYY-NNNNN",
      "cvss_score": null,
      "cvss_vector": null,
      "cvss_severity": "critical|high|medium|low|null",
      "description": "string",
      "affected_products": ["string"],
      "patch_available": true,
      "patch_url": "string|null",
      "exploited_in_wild": true,
      "in_kev": false
    }
  ],
  "iocs": [
    {
      "type": "ip|ipv6|domain|subdomain|url|email|hash_md5|hash_sha1|hash_sha256|hash_sha512|file_name|file_path|registry_key|mutex|user_agent|asn|bitcoin_address|yara_rule",
      "value": "string",
      "confidence": 85,
      "malware_family": "string|null",
      "context": "string — what this IOC does/represents"
    }
  ],
  "ttps": [
    {
      "mitre_id": "TXXXX.XXX",
      "tactic": "string",
      "technique": "string",
      "sub_technique": "string|null",
      "procedure": "string — specific observed behavior"
    }
  ],
  "malware_families": [
    {
      "name": "string",
      "type": "ransomware|trojan|backdoor|loader|stealer|wiper|rootkit|botnet|rat|other",
      "aliases": ["string"],
      "description": "string"
    }
  ],
  "affected_products": [
    {
      "vendor": "string",
      "product": "string",
      "version_range": "string|null",
      "component": "string|null"
    }
  ],
  "attack_timeline": {
    "first_seen": "ISO8601|null",
    "discovered": "ISO8601|null",
    "disclosed": "ISO8601|null",
    "duration": "string|null"
  },
  "data_types_compromised": ["PII","PHI","financial_data","credentials","source_code","classified","other"],
  "estimated_victims": "string|null",
  "financial_impact": "string|null",
  "remediation": ["string — specific actionable steps"],
  "confidence_notes": "string — explain any uncertainty in the extraction"
}`;

export async function analyzeArticle(article, sourceCredibility = 70) {
  const userPrompt = `Analyze this security article and extract threat intelligence. Return ONLY valid JSON matching the schema.

SOURCE: ${article.source_name || 'Unknown'}
SOURCE CREDIBILITY: ${sourceCredibility}/100
URL: ${article.url}
TITLE: ${article.title}
PUBLISHED: ${article.published_at || 'Unknown'}

ARTICLE CONTENT:
${article.content.slice(0, 12000)}

${article.cve_mentions?.length ? `CVE MENTIONS DETECTED IN TEXT: ${article.cve_mentions.join(', ')}` : ''}
${article.ip_mentions?.length ? `IP ADDRESSES DETECTED IN TEXT: ${article.ip_mentions.join(', ')}` : ''}
${article.hash_mentions?.length ? `HASHES DETECTED IN TEXT: ${article.hash_mentions.slice(0, 10).join(', ')}` : ''}

REQUIRED OUTPUT SCHEMA:
${EXTRACTION_SCHEMA}`;

  try {
    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 4096,
      system: [
        {
          type: 'text',
          text: SYSTEM_PROMPT,
          cache_control: { type: 'ephemeral' }, // cache the system prompt
        }
      ],
      messages: [{ role: 'user', content: userPrompt }],
    });

    const raw = response.content[0]?.text || '';
    const jsonStr = raw.match(/\{[\s\S]*\}/)?.[0];
    if (!jsonStr) throw new Error('No JSON in response');

    const parsed = JSON.parse(jsonStr);
    return { success: true, data: parsed, usage: response.usage };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export async function analyzeNvdCve(cve, cisaKevIds = new Set()) {
  const inKev = cisaKevIds.has(cve.cve_id);
  const severity = cve.cvss_severity?.toLowerCase() || 'unknown';

  const prompt = `Analyze this CVE and extract threat intelligence for a security portal. Return ONLY valid JSON.

CVE: ${cve.cve_id}
CVSS Score: ${cve.cvss_score || 'Not scored'}
CVSS Vector: ${cve.cvss_vector || 'N/A'}
Severity: ${severity}
In CISA KEV: ${inKev}
Description: ${cve.description}
Affected Products (CPE): ${(cve.affected_products || []).slice(0, 5).join('\n')}
References: ${(cve.references || []).join('\n')}

Provide:
1. A clear title (format: "CVE-XXXX-XXXXX: [product] [vulnerability type]")
2. 3-sentence executive summary (what it is, who's affected, urgency)
3. Which of our target sectors are affected: banking, government, healthcare
4. Affected vendors/products in plain language
5. Remediation steps
6. Likely threat types that would exploit this
7. MITRE ATT&CK technique if applicable

REQUIRED OUTPUT SCHEMA:
${EXTRACTION_SCHEMA}`;

  try {
    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 2048,
      system: [{ type: 'text', text: SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
      messages: [{ role: 'user', content: prompt }],
    });

    const raw = response.content[0]?.text || '';
    const jsonStr = raw.match(/\{[\s\S]*\}/)?.[0];
    if (!jsonStr) throw new Error('No JSON in response');

    const parsed = JSON.parse(jsonStr);

    // Ensure the CVE is in the output
    if (!parsed.cves || parsed.cves.length === 0) {
      parsed.cves = [{
        cve_id: cve.cve_id,
        cvss_score: cve.cvss_score,
        cvss_vector: cve.cvss_vector,
        cvss_severity: severity,
        description: cve.description,
        affected_products: [],
        patch_available: true,
        exploited_in_wild: inKev,
        in_kev: inKev,
      }];
    }

    return { success: true, data: parsed, source_url: cve.source_url };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export async function analyzeCisaKevEntry(vuln) {
  const prompt = `Analyze this CISA Known Exploited Vulnerability and extract threat intelligence. This CVE is confirmed exploited in the wild. Return ONLY valid JSON.

CVE: ${vuln.cveID}
Vendor: ${vuln.vendorProject}
Product: ${vuln.product}
Vulnerability Name: ${vuln.vulnerabilityName}
Date Added to KEV: ${vuln.dateAdded}
Short Description: ${vuln.shortDescription}
Required Action: ${vuln.requiredAction}
Due Date (Federal): ${vuln.dueDate}
Notes: ${vuln.notes || 'None'}

REQUIRED OUTPUT SCHEMA:
${EXTRACTION_SCHEMA}`;

  try {
    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 2048,
      system: [{ type: 'text', text: SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
      messages: [{ role: 'user', content: prompt }],
    });

    const raw = response.content[0]?.text || '';
    const jsonStr = raw.match(/\{[\s\S]*\}/)?.[0];
    if (!jsonStr) throw new Error('No JSON');
    const parsed = JSON.parse(jsonStr);
    return { success: true, data: parsed, source_url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export async function generateSectorBrief(sector, threats, dateRange = '24 hours') {
  const threatSummaries = threats.slice(0, 20).map((t, i) =>
    `${i + 1}. [${t.severity?.toUpperCase()}] ${t.title} — ${t.summary?.slice(0, 150)}`
  ).join('\n');

  const prompt = `Generate an executive threat intelligence brief for the ${sector.toUpperCase()} sector covering the last ${dateRange}.

THREATS DETECTED (${threats.length} total):
${threatSummaries}

Write a professional threat intelligence brief with:
1. EXECUTIVE SUMMARY (2-3 sentences on overall threat landscape)
2. TOP THREATS (top 5, each with: title, severity, why it matters to ${sector})
3. ACTIVE THREAT ACTORS targeting this sector
4. KEY VULNERABILITIES to patch immediately
5. RECOMMENDED ACTIONS (prioritized, specific)
6. THREAT FORECAST (what to watch for in the next 24-48 hours)

Format as structured markdown. Be direct, specific, and actionable. No fluff.`;

  const response = await client.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 2000,
    system: [{ type: 'text', text: SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
    messages: [{ role: 'user', content: prompt }],
  });

  return response.content[0]?.text || '';
}
