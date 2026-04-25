import Anthropic from '@anthropic-ai/sdk';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

// ── LLM backend — checked at call time so .env loads before first use ─────────
// Set OLLAMA_MODEL in .env to use local Ollama (free).
// e.g. OLLAMA_MODEL=qwen2.5:7b

function isOllama()   { return !!process.env.OLLAMA_MODEL; }
function ollamaUrl()  { return (process.env.OLLAMA_BASE_URL || 'http://localhost:11434').replace(/\/$/, ''); }
function ollamaModel(){ return process.env.OLLAMA_MODEL || ''; }

let _anthropic;
function anthropic() {
  if (!_anthropic) _anthropic = new Anthropic();
  return _anthropic;
}

// ── JSON repair — Ollama sometimes outputs slightly malformed JSON ─────────────
function extractJson(raw) {
  // 1. Try direct parse
  try { return JSON.parse(raw); } catch {}

  // 2. Find the first {...} block and try parsing it
  const m = raw.match(/\{[\s\S]*\}/);
  if (m) {
    try { return JSON.parse(m[0]); } catch {}

    // 3. Remove trailing commas (common Ollama mistake)
    const repaired = m[0]
      .replace(/,\s*([}\]])/g, '$1')        // trailing commas
      .replace(/([{,]\s*)(\w+)\s*:/g, (_, pre, key) => `${pre}"${key}":`) // unquoted keys
      .replace(/:\s*'([^']*)'/g, ': "$1"'); // single-quoted strings
    try { return JSON.parse(repaired); } catch {}
  }

  return null;
}

// ── Core LLM call ─────────────────────────────────────────────────────────────
async function callLLM(systemPrompt, userPrompt, maxTokens = 2048) {
  if (isOllama()) {
    const res = await fetch(`${ollamaUrl()}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: ollamaModel(),
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user',   content: userPrompt   },
        ],
        stream:  false,
        format:  'json',
        options: { temperature: 0, num_predict: maxTokens },
      }),
    });
    if (!res.ok) throw new Error(`Ollama HTTP ${res.status}: ${await res.text()}`);
    const data = await res.json();
    return data.message?.content || '';
  } else {
    const response = await anthropic().messages.create({
      model:      'claude-sonnet-4-6',
      max_tokens: maxTokens,
      system: [{ type: 'text', text: systemPrompt, cache_control: { type: 'ephemeral' } }],
      messages: [{ role: 'user', content: userPrompt }],
    });
    return response.content[0]?.text || '';
  }
}

function loadSectors() {
  return yaml.load(readFileSync(join(ROOT, 'config/sectors.yml'), 'utf8'));
}

// ── Prompts ────────────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are an elite threat intelligence analyst. Analyze security articles and extract structured threat intelligence.

RULES:
- Extract ONLY what is explicitly stated — never hallucinate IOCs, CVEs, or threat actor names
- CVE IDs must be exact format: CVE-YYYY-NNNNN
- IOCs: IPs, domains, URLs, hashes (MD5/SHA1/SHA256), emails, file paths, registry keys, mutexes
- MITRE ATT&CK: exact technique IDs (T1566.001, not just "phishing")
- Severity: base on CVSS if present, otherwise attacker capability + impact
- Sectors: banking, government, healthcare only
- Respond ONLY with valid JSON. No markdown, no explanation.`;

const EXTRACTION_SCHEMA = `{
  "title": "concise threat title (max 100 chars)",
  "summary": "3-sentence executive brief: what happened, who's affected, what to do",
  "severity": "critical|high|medium|low|unknown",
  "threat_type": "ransomware|apt|phishing|vulnerability|data_breach|ddos|supply_chain|insider_threat|cryptojacking|malware|fraud|espionage|zero_day|other",
  "kill_chain_stage": "reconnaissance|weaponization|delivery|exploitation|installation|c2|actions_on_objectives|unknown",
  "sectors": ["banking","government","healthcare"],
  "sector_impact": {
    "banking":    {"score": 0, "reason": ""},
    "government": {"score": 0, "reason": ""},
    "healthcare": {"score": 0, "reason": ""}
  },
  "geography": ["country names"],
  "threat_actors": [{
    "name": "", "aliases": [], "origin_country": null,
    "motivation": "financial|espionage|sabotage|hacktivism|cyberwarfare|unknown",
    "sophistication": "nation_state|advanced|intermediate|basic|unknown",
    "active_since": null, "description": ""
  }],
  "cves": [{
    "cve_id": "CVE-YYYY-NNNNN", "cvss_score": null, "cvss_vector": null,
    "cvss_severity": null, "description": "", "affected_products": [],
    "patch_available": false, "patch_url": null, "exploited_in_wild": false, "in_kev": false
  }],
  "iocs": [{
    "type": "ip|domain|url|email|hash_md5|hash_sha1|hash_sha256|file_path|registry_key|mutex",
    "value": "", "confidence": 80, "malware_family": null, "context": ""
  }],
  "ttps": [{
    "mitre_id": "TXXXX", "tactic": "", "technique": "",
    "sub_technique": null, "procedure": ""
  }],
  "malware_families": [{"name": "", "type": "ransomware|trojan|backdoor|loader|stealer|other", "aliases": []}],
  "affected_products": [{"vendor": "", "product": "", "version_range": null}],
  "remediation": ["actionable step"],
  "confidence_notes": "any extraction uncertainty"
}`;

// ── Exported analyzers ─────────────────────────────────────────────────────────

export async function analyzeArticle(article, sourceCredibility = 70) {
  const userPrompt = `Analyze this security article. Return ONLY valid JSON matching the schema exactly.

SOURCE: ${article.source_name || 'Unknown'} (credibility: ${sourceCredibility}/100)
URL: ${article.url}
TITLE: ${article.title}
PUBLISHED: ${article.published_at || 'Unknown'}

CONTENT:
${article.content.slice(0, 10000)}

${article.cve_mentions?.length ? `CVEs IN TEXT: ${article.cve_mentions.join(', ')}` : ''}
${article.ip_mentions?.length   ? `IPs IN TEXT: ${article.ip_mentions.join(', ')}`   : ''}

SCHEMA:
${EXTRACTION_SCHEMA}`;

  try {
    const raw    = await callLLM(SYSTEM_PROMPT, userPrompt, 2048);
    const parsed = extractJson(raw);
    if (!parsed) throw new Error(`Could not parse JSON from response (length: ${raw.length})`);
    return { success: true, data: parsed };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export async function analyzeNvdCve(cve, cisaKevIds = new Set()) {
  const inKev    = cisaKevIds.has(cve.cve_id);
  const severity = cve.cvss_severity?.toLowerCase() || 'unknown';

  const prompt = `Analyze this CVE for a security portal. Return ONLY valid JSON matching the schema.

CVE: ${cve.cve_id}
CVSS Score: ${cve.cvss_score || 'Not scored'}
Severity: ${severity.toUpperCase()}
In CISA KEV: ${inKev}
Description: ${cve.description}
Affected Products: ${(cve.affected_products || []).slice(0, 5).join(', ')}

Write a clear title like: "${cve.cve_id}: [Product] [Vulnerability Type]"
Explain who is affected and urgency in the summary.

SCHEMA:
${EXTRACTION_SCHEMA}`;

  try {
    const raw    = await callLLM(SYSTEM_PROMPT, prompt, 1500);
    const parsed = extractJson(raw);
    if (!parsed) throw new Error(`Could not parse JSON (length: ${raw.length})`);

    if (!parsed.cves || parsed.cves.length === 0) {
      parsed.cves = [{
        cve_id:            cve.cve_id,
        cvss_score:        cve.cvss_score,
        cvss_vector:       cve.cvss_vector,
        cvss_severity:     severity,
        description:       cve.description,
        affected_products: [],
        patch_available:   true,
        exploited_in_wild: inKev,
        in_kev:            inKev,
      }];
    }

    return { success: true, data: parsed, source_url: cve.source_url };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export async function analyzeCisaKevEntry(vuln) {
  const prompt = `Analyze this CISA Known Exploited Vulnerability. Confirmed exploited in the wild. Return ONLY valid JSON.

CVE: ${vuln.cveID}
Vendor/Product: ${vuln.vendorProject} — ${vuln.product}
Vulnerability: ${vuln.vulnerabilityName}
Date Added to KEV: ${vuln.dateAdded}
Description: ${vuln.shortDescription}
Required Action: ${vuln.requiredAction}
Due Date: ${vuln.dueDate}

SCHEMA:
${EXTRACTION_SCHEMA}`;

  try {
    const raw    = await callLLM(SYSTEM_PROMPT, prompt, 1500);
    const parsed = extractJson(raw);
    if (!parsed) throw new Error(`Could not parse JSON (length: ${raw.length})`);
    return { success: true, data: parsed, source_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export async function generateSectorBrief(sector, threats, dateRange = '24 hours') {
  const threatSummaries = threats.slice(0, 20).map((t, i) =>
    `${i + 1}. [${t.severity?.toUpperCase()}] ${t.title} — ${t.summary?.slice(0, 120)}`
  ).join('\n');

  const prompt = `Write a professional threat intelligence brief for the ${sector.toUpperCase()} sector, last ${dateRange}.

THREATS (${threats.length} total):
${threatSummaries}

Include: Executive Summary, Top 5 Threats, Active Actors, Key CVEs, Recommended Actions, Threat Forecast.
Format as structured markdown. Direct and actionable.`;

  return await callLLM(SYSTEM_PROMPT, prompt, 2000);
}
