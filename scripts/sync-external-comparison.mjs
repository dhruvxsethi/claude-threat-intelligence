#!/usr/bin/env node
/**
 * Sync public external comparison sources against locally collected threats.
 *
 * Primary intelligence still comes from article/API ingestion. This job answers:
 * "Did common public platforms already know this CVE/IOC, or is Radar holding
 * something useful from article/vendor feeds before those sources show it?"
 */

import { existsSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb, migrate } from './migrate.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const DB_PATH = join(ROOT, 'data/threats.db');

function loadEnv() {
  const envPath = join(ROOT, '.env');
  if (!existsSync(envPath)) return;
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx < 0) continue;
    const k = trimmed.slice(0, idx).trim();
    const v = trimmed.slice(idx + 1).trim();
    if (k && !process.env[k]) process.env[k] = v;
  }
}

function argValue(name, fallback) {
  const prefix = `--${name}=`;
  const arg = process.argv.find(a => a.startsWith(prefix));
  return arg ? arg.slice(prefix.length) : fallback;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isoNow() {
  return new Date().toISOString();
}

function normalizeIocValue(type, value = '') {
  const raw = String(value).trim();
  if (['domain', 'email'].includes(type)) return raw.toLowerCase();
  if (type?.startsWith('hash_')) return raw.toLowerCase();
  return raw;
}

function isPublicIp(ip = '') {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  const parts = ip.split('.').map(Number);
  if (parts.some(n => n < 0 || n > 255)) return false;
  if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return false;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
  if (parts[0] === 192 && parts[1] === 168) return false;
  if (parts[0] === 169 && parts[1] === 254) return false;
  return true;
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'RadarThreatIntelligence/1.0 external-comparison',
      ...(options.headers || {}),
    },
    signal: AbortSignal.timeout(options.timeoutMs || 20000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

async function postForm(url, body, options = {}) {
  const res = await fetch(url, {
    method: 'POST',
    body: new URLSearchParams(body),
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'RadarThreatIntelligence/1.0 external-comparison',
      ...(options.headers || {}),
    },
    signal: AbortSignal.timeout(options.timeoutMs || 20000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

async function queryNvd(cve) {
  const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
  url.searchParams.set('cveId', cve);
  const data = await fetchJson(url);
  const item = data.vulnerabilities?.[0]?.cve;
  if (!item) return null;
  return {
    provider: 'nvd',
    external_id: `nvd:${cve}`,
    first_seen_at: item.published || isoNow(),
    last_seen_at: item.lastModified || item.published || isoNow(),
    url: `https://nvd.nist.gov/vuln/detail/${cve}`,
    title: cve,
    metadata: {
      sourceIdentifier: item.sourceIdentifier,
      vulnStatus: item.vulnStatus,
      published: item.published,
      lastModified: item.lastModified,
    },
  };
}

async function loadCisaKevSet() {
  const data = await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  const out = new Map();
  for (const item of data.vulnerabilities || []) {
    if (!item.cveID) continue;
    out.set(item.cveID.toUpperCase(), {
      provider: 'cisa_kev',
      external_id: `cisa-kev:${item.cveID}`,
      first_seen_at: item.dateAdded || isoNow(),
      last_seen_at: item.dateAdded || isoNow(),
      url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      title: `${item.cveID} in CISA KEV`,
      metadata: item,
    });
  }
  return out;
}

async function queryGithubAdvisory(cve) {
  const url = new URL('https://api.github.com/advisories');
  url.searchParams.set('cve_id', cve);
  url.searchParams.set('per_page', '10');
  const data = await fetchJson(url, {
    headers: process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {},
  });
  const item = Array.isArray(data) ? data[0] : null;
  if (!item) return null;
  return {
    provider: 'github_advisory',
    external_id: `github:${item.ghsa_id || cve}`,
    first_seen_at: item.published_at || item.updated_at || isoNow(),
    last_seen_at: item.updated_at || item.published_at || isoNow(),
    url: item.html_url || `https://github.com/advisories?query=${encodeURIComponent(cve)}`,
    title: item.summary || cve,
    metadata: {
      ghsa_id: item.ghsa_id,
      cve_id: item.cve_id,
      severity: item.severity,
      ecosystem: item.vulnerabilities?.[0]?.package?.ecosystem,
      package: item.vulnerabilities?.[0]?.package?.name,
    },
  };
}

async function queryMalwareBazaar(ioc) {
  if (!ioc.ioc_type?.startsWith('hash_')) return null;
  const headers = process.env.MALWAREBAZAAR_AUTH_KEY ? { 'Auth-Key': process.env.MALWAREBAZAAR_AUTH_KEY } : {};
  const data = await postForm('https://mb-api.abuse.ch/api/v1/', {
    query: 'get_info',
    hash: ioc.ioc_value,
  }, { headers });
  if (data.query_status !== 'ok' || !data.data?.length) return null;
  const item = data.data[0];
  return {
    provider: 'malwarebazaar',
    external_id: `malwarebazaar:${ioc.ioc_value}`,
    first_seen_at: item.first_seen || isoNow(),
    last_seen_at: item.last_seen || item.first_seen || isoNow(),
    url: `https://bazaar.abuse.ch/sample/${ioc.ioc_value}/`,
    title: item.file_name || ioc.ioc_value,
    metadata: {
      signature: item.signature,
      file_type: item.file_type,
      reporter: item.reporter,
      tags: item.tags || [],
    },
  };
}

async function queryUrlHaus(ioc) {
  if (!process.env.URLHAUS_AUTH_KEY) return null;
  const headers = { 'Auth-Key': process.env.URLHAUS_AUTH_KEY };
  if (ioc.ioc_type === 'url') {
    const data = await postForm('https://urlhaus-api.abuse.ch/v1/url/', { url: ioc.ioc_value }, { headers });
    if (data.query_status !== 'ok') return null;
    return {
      provider: 'urlhaus',
      external_id: `urlhaus:url:${data.id || ioc.ioc_value}`,
      first_seen_at: data.date_added || isoNow(),
      last_seen_at: data.date_added || isoNow(),
      url: data.urlhaus_reference || ioc.ioc_value,
      title: data.url || ioc.ioc_value,
      metadata: data,
    };
  }

  if (ioc.ioc_type === 'domain' || ioc.ioc_type === 'ip') {
    const data = await postForm('https://urlhaus-api.abuse.ch/v1/host/', { host: ioc.ioc_value }, { headers });
    if (data.query_status !== 'ok' || Number(data.url_count || 0) === 0) return null;
    return {
      provider: 'urlhaus',
      external_id: `urlhaus:host:${ioc.ioc_value}`,
      first_seen_at: data.firstseen || data.urls?.[0]?.date_added || isoNow(),
      last_seen_at: data.lastseen || data.urls?.[0]?.date_added || isoNow(),
      url: `https://urlhaus.abuse.ch/host/${ioc.ioc_value}/`,
      title: `${ioc.ioc_value} in URLHaus`,
      metadata: {
        url_count: data.url_count,
        blacklists: data.blacklists,
        sample_urls: (data.urls || []).slice(0, 5),
      },
    };
  }

  return null;
}

async function queryShodan(ioc) {
  if (!process.env.SHODAN_API_KEY || ioc.ioc_type !== 'ip' || !isPublicIp(ioc.ioc_value)) return null;
  const url = new URL(`https://api.shodan.io/shodan/host/${ioc.ioc_value}`);
  url.searchParams.set('key', process.env.SHODAN_API_KEY);
  url.searchParams.set('minify', 'true');
  const data = await fetchJson(url);
  if (!data.ip_str) return null;
  return {
    provider: 'shodan',
    external_id: `shodan:${ioc.ioc_value}`,
    first_seen_at: data.last_update || isoNow(),
    last_seen_at: data.last_update || isoNow(),
    url: `https://www.shodan.io/host/${ioc.ioc_value}`,
    title: `${ioc.ioc_value} in Shodan`,
    metadata: {
      org: data.org,
      isp: data.isp,
      ports: data.ports || [],
      vulns: data.vulns || [],
      country_name: data.country_name,
    },
  };
}

async function queryCensys(ioc) {
  if (!process.env.CENSYS_API_ID || !process.env.CENSYS_API_SECRET || ioc.ioc_type !== 'ip' || !isPublicIp(ioc.ioc_value)) return null;
  const token = Buffer.from(`${process.env.CENSYS_API_ID}:${process.env.CENSYS_API_SECRET}`).toString('base64');
  const data = await fetchJson(`https://search.censys.io/api/v2/hosts/${ioc.ioc_value}`, {
    headers: { Authorization: `Basic ${token}` },
  });
  if (data.status !== 'OK' && !data.result) return null;
  const result = data.result || {};
  return {
    provider: 'censys',
    external_id: `censys:${ioc.ioc_value}`,
    first_seen_at: result.last_updated_at || isoNow(),
    last_seen_at: result.last_updated_at || isoNow(),
    url: `https://search.censys.io/hosts/${ioc.ioc_value}`,
    title: `${ioc.ioc_value} in Censys`,
    metadata: {
      location: result.location,
      autonomous_system: result.autonomous_system,
      services: (result.services || []).slice(0, 20).map(s => ({
        port: s.port,
        service_name: s.service_name,
        transport_protocol: s.transport_protocol,
      })),
    },
  };
}

function insertExternalSighting(db, row, match) {
  const insert = db.prepare(`
    INSERT OR IGNORE INTO external_sightings (
      threat_id, provider, external_id, match_type, match_value,
      first_seen_at, last_seen_at, metadata
    ) VALUES (
      @threat_id, @provider, @external_id, @match_type, @match_value,
      @first_seen_at, @last_seen_at, @metadata
    )
  `);
  const evidence = db.prepare(`
    INSERT INTO threat_evidence (
      threat_id, evidence_type, title, body, url, observed_at, metadata
    ) VALUES (?, 'external_sighting', ?, ?, ?, ?, ?)
  `);
  const update = db.prepare(`
    UPDATE threats SET
      external_seen_at = CASE
        WHEN external_seen_at IS NULL THEN ?
        WHEN ? IS NOT NULL AND datetime(?) < datetime(external_seen_at) THEN ?
        ELSE external_seen_at
      END,
      gap_checked_at = datetime('now'),
      gap_status = CASE
        WHEN first_seen_by_us_at IS NOT NULL
         AND ? IS NOT NULL
         AND datetime(first_seen_by_us_at) < datetime(?)
        THEN 'seen_by_us_first'
        ELSE 'seen_elsewhere'
      END
    WHERE id = ?
  `);

  const firstSeen = row.first_seen_at || row.last_seen_at || isoNow();
  const metadata = JSON.stringify(row.metadata || row);
  const result = insert.run({
    threat_id: match.threat_id,
    provider: row.provider,
    external_id: row.external_id,
    match_type: match.match_type,
    match_value: match.match_value,
    first_seen_at: firstSeen,
    last_seen_at: row.last_seen_at || firstSeen,
    metadata,
  });
  update.run(firstSeen, firstSeen, firstSeen, firstSeen, firstSeen, firstSeen, match.threat_id);

  if (result.changes > 0) {
    evidence.run(
      match.threat_id,
      `${row.provider} sighting: ${row.title || match.match_value}`,
      `Matched ${row.provider} by ${match.match_type}: ${match.match_value}`,
      row.url || null,
      firstSeen,
      metadata
    );
    return true;
  }
  return false;
}

function insertCheckEvidence(db, threatId, provider, matchType, matchValue, status, detail = {}) {
  db.prepare(`
    INSERT INTO threat_evidence (
      threat_id, evidence_type, title, body, url, observed_at, metadata
    ) VALUES (?, 'gap_tracking', ?, ?, ?, datetime('now'), ?)
  `).run(
    threatId,
    `${provider} check: ${status}`,
    status === 'not_found'
      ? `${provider} was checked for ${matchType}: ${matchValue}; no matching record was found.`
      : `${provider} was checked for ${matchType}: ${matchValue}.`,
    detail.url || null,
    JSON.stringify({
      provider,
      match_type: matchType,
      match_value: matchValue,
      status,
      checked_at: isoNow(),
      ...detail,
    })
  );
}

function markChecked(db, threatIds, provider, matchType, matchValue, found, detail = {}) {
  const update = db.prepare(`
    UPDATE threats
    SET gap_checked_at = datetime('now'),
        gap_status = CASE
          WHEN ? = 1 THEN gap_status
          WHEN gap_status IS NULL OR gap_status = 'not_checked' THEN 'not_seen_elsewhere'
          ELSE gap_status
        END
    WHERE id = ?
  `);
  for (const threatId of threatIds) {
    update.run(found ? 1 : 0, threatId);
    insertCheckEvidence(db, threatId, provider, matchType, matchValue, found ? 'found' : 'not_found', detail);
  }
}

loadEnv();

const days = parseInt(argValue('days', '14'), 10);
const limitCves = parseInt(argValue('cves', '80'), 10);
const limitIocs = parseInt(argValue('iocs', '120'), 10);
const delayMs = parseInt(argValue('delay-ms', '650'), 10);
const cutoff = new Date(Date.now() - days * 86400000).toISOString();

const db = getDb(DB_PATH);
migrate(db);

const cves = db.prepare(`
  SELECT DISTINCT upper(c.cve_id) AS cve_id
  FROM threat_cves c JOIN threats t ON c.threat_id = t.id
  WHERE t.ingested_at >= ?
  ORDER BY c.id DESC
  LIMIT ?
`).all(cutoff, limitCves).map(r => r.cve_id);

const iocs = db.prepare(`
  SELECT ti.threat_id, ti.ioc_type, lower(ti.ioc_value) AS ioc_value
  FROM threat_iocs ti JOIN threats t ON ti.threat_id = t.id
  WHERE t.ingested_at >= ?
    AND ti.ioc_type IN ('ip','domain','url','hash_md5','hash_sha1','hash_sha256','hash_sha512')
  GROUP BY ti.ioc_type, lower(ti.ioc_value)
  ORDER BY MAX(t.ingested_at) DESC
  LIMIT ?
`).all(cutoff, limitIocs).map(i => ({ ...i, ioc_value: normalizeIocValue(i.ioc_type, i.ioc_value) }));

const cveThreats = db.prepare(`
  SELECT threat_id FROM threat_cves WHERE upper(cve_id) = upper(?)
`);
const iocThreats = db.prepare(`
  SELECT threat_id FROM threat_iocs
  WHERE ioc_type = ? AND lower(ioc_value) = lower(?)
`);

let checked = 0;
let matched = 0;
let imported = 0;
const byProvider = {};

function record(provider, didImport, didMatch = true) {
  byProvider[provider] = byProvider[provider] || { matched: 0, imported: 0 };
  if (didMatch) byProvider[provider].matched += 1;
  if (didImport) byProvider[provider].imported += 1;
}

const cisaKev = await loadCisaKevSet().catch(e => {
  console.warn(`CISA KEV sync skipped: ${e.message}`);
  return new Map();
});

for (const cve of cves) {
  const providers = [
    ['cisa_kev', async () => cisaKev.get(cve) || null],
    ['nvd', async () => queryNvd(cve)],
    ['github_advisory', async () => queryGithubAdvisory(cve)],
  ];

  for (const [provider, fn] of providers) {
    checked++;
    try {
      const row = await fn();
      const threats = cveThreats.all(cve);
      markChecked(db, threats.map(t => t.threat_id), provider, 'cve', cve, !!row, row ? { url: row.url } : {});
      if (!row) continue;
      for (const t of threats) {
        matched++;
        const didImport = insertExternalSighting(db, row, { threat_id: t.threat_id, match_type: 'cve', match_value: cve });
        imported += didImport ? 1 : 0;
        record(provider, didImport);
      }
    } catch (e) {
      console.warn(`${provider} ${cve} skipped: ${e.message.slice(0, 160)}`);
    }
    await sleep(delayMs);
  }
}

for (const ioc of iocs) {
  const providers = [
    ['malwarebazaar', async () => queryMalwareBazaar(ioc)],
    ['urlhaus', async () => queryUrlHaus(ioc)],
    ['shodan', async () => queryShodan(ioc)],
    ['censys', async () => queryCensys(ioc)],
  ];

  for (const [provider, fn] of providers) {
    checked++;
    try {
      const row = await fn();
      const threats = iocThreats.all(ioc.ioc_type, ioc.ioc_value);
      markChecked(db, threats.map(t => t.threat_id), provider, 'ioc', `${ioc.ioc_type}:${ioc.ioc_value}`, !!row, row ? { url: row.url } : {});
      if (!row) continue;
      for (const t of threats) {
        matched++;
        const didImport = insertExternalSighting(db, row, {
          threat_id: t.threat_id,
          match_type: 'ioc',
          match_value: `${ioc.ioc_type}:${ioc.ioc_value}`,
        });
        imported += didImport ? 1 : 0;
        record(provider, didImport);
      }
    } catch (e) {
      console.warn(`${provider} ${ioc.ioc_type}:${ioc.ioc_value} skipped: ${e.message.slice(0, 160)}`);
    }
    await sleep(delayMs);
  }
}

db.close();

console.log(`External comparison sync complete: ${checked} checks, ${matched} matches, ${imported} new sightings.`);
console.log(JSON.stringify(byProvider, null, 2));
