#!/usr/bin/env node
/**
 * Sync AlienVault OTX as an external comparison source.
 *
 * OTX is not used as a primary intelligence feed here. It is used to answer:
 * "Did OTX already know about something we collected ourselves?"
 */

import { existsSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb, migrate } from './migrate.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const OTX_BASE = 'https://otx.alienvault.com/api/v1';

function loadEnv() {
  const envPath = join(ROOT, '.env');
  if (!existsSync(envPath)) return;
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) continue;
    const k = trimmed.slice(0, eqIdx).trim();
    const v = trimmed.slice(eqIdx + 1).trim();
    if (k && !process.env[k]) process.env[k] = v;
  }
}

function argValue(name, fallback) {
  const prefix = `--${name}=`;
  const arg = process.argv.find(a => a.startsWith(prefix));
  return arg ? arg.slice(prefix.length) : fallback;
}

function isoDaysAgo(days) {
  return new Date(Date.now() - days * 86400000).toISOString();
}

function normalizeIocType(type = '') {
  const t = String(type).toLowerCase();
  if (['ipv4', 'ipv6'].includes(t)) return 'ip';
  if (['domain', 'hostname'].includes(t)) return 'domain';
  if (t === 'url' || t === 'uri') return 'url';
  if (t === 'email' || t === 'emailaddress') return 'email';
  if (t.includes('md5')) return 'hash_md5';
  if (t.includes('sha1')) return 'hash_sha1';
  if (t.includes('sha256')) return 'hash_sha256';
  if (t.includes('sha512')) return 'hash_sha512';
  return null;
}

function normalizeIocValue(type, value = '') {
  const raw = String(value).trim();
  if (!raw) return '';
  if (['domain', 'email'].includes(type)) return raw.toLowerCase();
  if (type?.startsWith('hash_')) return raw.toLowerCase();
  return raw;
}

function extractCves(text = '') {
  return [...new Set(String(text).match(/\bCVE-\d{4}-\d{4,}\b/gi) || [])]
    .map(cve => cve.toUpperCase());
}

async function fetchOtxPage(apiKey, page, limit, modifiedSince, useModifiedSince = true) {
  const url = new URL(`${OTX_BASE}/pulses/subscribed`);
  url.searchParams.set('page', String(page));
  url.searchParams.set('limit', String(limit));
  if (useModifiedSince && modifiedSince) url.searchParams.set('modified_since', modifiedSince);

  const res = await fetch(url, {
    headers: {
      'X-OTX-API-KEY': apiKey,
      'Accept': 'application/json',
      'User-Agent': 'ClaudeThreatIntelligence/1.0 OTX gap sync',
    },
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`OTX HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

async function fetchOtxPulses(apiKey, { days, maxPages, limit }) {
  const modifiedSince = isoDaysAgo(days);
  const pulses = [];
  let useModifiedSince = true;

  for (let page = 1; page <= maxPages; page++) {
    let data;
    try {
      data = await fetchOtxPage(apiKey, page, limit, modifiedSince, useModifiedSince);
    } catch (e) {
      if (page === 1 && useModifiedSince && /400|modified_since/i.test(e.message)) {
        useModifiedSince = false;
        data = await fetchOtxPage(apiKey, page, limit, modifiedSince, false);
      } else {
        throw e;
      }
    }

    const results = Array.isArray(data) ? data : (data.results || []);
    pulses.push(...results);
    if (!data.next || results.length === 0) break;
  }

  const cutoff = Date.parse(modifiedSince);
  return pulses.filter(p => {
    const ts = Date.parse(p.modified || p.created || p.created_at || '');
    return !Number.isFinite(ts) || ts >= cutoff;
  });
}

function rowsFromPulse(pulse) {
  const rows = [];
  const pulseId = pulse.id || pulse.pulse_id || pulse.name;
  const pulseUrl = pulseId ? `https://otx.alienvault.com/pulse/${pulseId}` : null;
  const firstSeen = pulse.created || pulse.created_at || pulse.modified || pulse.modified_at || new Date().toISOString();
  const lastSeen = pulse.modified || pulse.modified_at || firstSeen;
  const baseText = [
    pulse.name,
    pulse.description,
    pulse.adversary,
    ...(pulse.tags || []),
    ...(pulse.references || []),
  ].filter(Boolean).join('\n');

  const metadata = {
    pulse_id: pulseId,
    pulse_name: pulse.name || null,
    pulse_url: pulseUrl,
    author_name: pulse.author_name || pulse.author?.username || null,
    adversary: pulse.adversary || null,
    tlp: pulse.tlp || null,
    tags: pulse.tags || [],
  };

  for (const cve of extractCves(baseText)) {
    rows.push({
      provider: 'otx',
      external_id: `otx:pulse:${pulseId}:cve:${cve}`,
      first_seen_at: firstSeen,
      last_seen_at: lastSeen,
      url: pulseUrl,
      cve_id: cve,
      title: pulse.name || cve,
      metadata,
    });
  }

  for (const ind of pulse.indicators || []) {
    const indicator = String(ind.indicator || '').trim();
    if (!indicator) continue;

    const cves = ind.type === 'CVE' ? [indicator.toUpperCase()] : extractCves(indicator);
    for (const cve of cves) {
      rows.push({
        provider: 'otx',
        external_id: `otx:pulse:${pulseId}:indicator:${ind.id || cve}`,
        first_seen_at: ind.created || firstSeen,
        last_seen_at: lastSeen,
        url: pulseUrl,
        cve_id: cve,
        title: pulse.name || cve,
        metadata: { ...metadata, indicator: ind },
      });
    }

    const iocType = normalizeIocType(ind.type);
    if (!iocType) continue;
    const iocValue = normalizeIocValue(iocType, indicator);
    if (!iocValue) continue;
    rows.push({
      provider: 'otx',
      external_id: `otx:pulse:${pulseId}:indicator:${ind.id || `${iocType}:${iocValue}`}`,
      first_seen_at: ind.created || firstSeen,
      last_seen_at: lastSeen,
      url: pulseUrl,
      ioc_type: iocType,
      ioc_value: iocValue,
      title: pulse.name || iocValue,
      metadata: { ...metadata, indicator: ind },
    });
  }

  return rows;
}

function findThreat(db, row) {
  if (row.url) {
    const byUrl = db.prepare('SELECT id FROM threats WHERE source_url = ?').get(row.url);
    if (byUrl) return { threat_id: byUrl.id, match_type: 'url', match_value: row.url };
  }

  if (row.cve_id) {
    const byCve = db.prepare(`
      SELECT threat_id FROM threat_cves
      WHERE upper(cve_id) = upper(?)
      ORDER BY id DESC LIMIT 1
    `).get(row.cve_id);
    if (byCve) return { threat_id: byCve.threat_id, match_type: 'cve', match_value: row.cve_id };
  }

  if (row.ioc_type && row.ioc_value) {
    const byIoc = db.prepare(`
      SELECT threat_id FROM threat_iocs
      WHERE ioc_type = ? AND lower(ioc_value) = lower(?)
      ORDER BY confidence DESC LIMIT 1
    `).get(row.ioc_type, row.ioc_value);
    if (byIoc) return { threat_id: byIoc.threat_id, match_type: 'ioc', match_value: `${row.ioc_type}:${row.ioc_value}` };
  }

  return null;
}

loadEnv();

const apiKey = process.env.OTX_API_KEY;
if (!apiKey) {
  console.error('OTX_API_KEY is not set in .env');
  process.exit(1);
}

const days = parseInt(argValue('days', process.env.OTX_LOOKBACK_DAYS || '14'), 10);
const maxPages = parseInt(argValue('pages', process.env.OTX_MAX_PAGES || '5'), 10);
const limit = parseInt(argValue('limit', process.env.OTX_PAGE_LIMIT || '50'), 10);

const db = getDb(join(ROOT, 'data/threats.db'));
migrate(db);

const insert = db.prepare(`
  INSERT OR IGNORE INTO external_sightings (
    threat_id, provider, external_id, match_type, match_value,
    first_seen_at, last_seen_at, metadata
  ) VALUES (
    @threat_id, @provider, @external_id, @match_type, @match_value,
    @first_seen_at, @last_seen_at, @metadata
  )
`);

const insertEvidence = db.prepare(`
  INSERT INTO threat_evidence (
    threat_id, evidence_type, title, body, url, observed_at, metadata
  ) VALUES (?, 'external_sighting', ?, ?, ?, ?, ?)
`);

const updateThreat = db.prepare(`
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

const markUnchecked = db.prepare(`
  UPDATE threats
  SET gap_checked_at = datetime('now'),
      gap_status = CASE
        WHEN gap_status IS NULL OR gap_status = 'not_checked' THEN 'not_seen_elsewhere'
        ELSE gap_status
      END
  WHERE ingested_at >= ?
    AND id NOT IN (SELECT DISTINCT threat_id FROM external_sightings WHERE provider = 'otx')
`);

let pulses = [];
try {
  pulses = await fetchOtxPulses(apiKey, { days, maxPages, limit });
} catch (e) {
  db.close();
  console.error(`OTX sync failed: ${e.message}`);
  process.exit(1);
}

const rows = pulses.flatMap(rowsFromPulse);
const seenExternalIds = new Set();
let imported = 0;
let matched = 0;
let unmatched = 0;

const run = db.transaction(() => {
  for (const row of rows) {
    if (seenExternalIds.has(row.external_id)) continue;
    seenExternalIds.add(row.external_id);

    const match = findThreat(db, row);
    if (!match) {
      unmatched++;
      continue;
    }

    const firstSeen = row.first_seen_at || row.last_seen_at || new Date().toISOString();
    const externalId = row.external_id || `otx:${match.match_type}:${match.match_value}`;
    const metadata = JSON.stringify(row.metadata || row);
    const result = insert.run({
      threat_id: match.threat_id,
      provider: 'otx',
      external_id: externalId,
      match_type: match.match_type,
      match_value: match.match_value,
      first_seen_at: firstSeen,
      last_seen_at: row.last_seen_at || firstSeen,
      metadata,
    });

    matched++;
    updateThreat.run(firstSeen, firstSeen, firstSeen, firstSeen, firstSeen, firstSeen, match.threat_id);

    if (result.changes > 0) {
      insertEvidence.run(
        match.threat_id,
        `OTX sighting: ${row.title || match.match_value}`,
        `Matched OTX pulse by ${match.match_type}: ${match.match_value}`,
        row.url || null,
        firstSeen,
        metadata
      );
      imported++;
    }
  }

  markUnchecked.run(isoDaysAgo(days));
});

run();
db.close();

console.log(`OTX sync complete: ${pulses.length} pulses, ${rows.length} sightings, ${matched} matched, ${imported} imported, ${unmatched} unmatched.`);
