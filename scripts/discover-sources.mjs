#!/usr/bin/env node
/**
 * Discover candidate RSS/Atom feeds from configured source homepages.
 * It records suggestions in discovered_sources; it does not edit feeds.yml.
 */

import Parser from 'rss-parser';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb, migrate } from './migrate.mjs';
import { loadFeedsConfig, loadSettings } from '../ingestion/feed-fetcher.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const parser = new Parser({ timeout: 10000 });

const settings = loadSettings();
const AUTO_ADD_THRESHOLD = parseInt(
  process.env.SOURCE_AUTO_ADD_THRESHOLD || settings.feeds?.auto_promote_threshold || '72',
  10
);
const AUTO_REJECT_THRESHOLD = parseInt(process.env.SOURCE_AUTO_REJECT_THRESHOLD || '40', 10);
const FRESH_DAYS = parseInt(process.env.SOURCE_DISCOVERY_FRESH_DAYS || '30', 10);
const MAX_CANDIDATES = parseInt(process.env.SOURCE_DISCOVERY_MAX_CANDIDATES || '90', 10);

const DISCOVERY_SEED_HOMES = [
  'https://www.rapid7.com/',
  'https://www.fortinet.com/',
  'https://blog.sekoia.io/',
  'https://www.welivesecurity.com/',
  'https://www.trendmicro.com/',
  'https://www.zscaler.com/',
  'https://www.splunk.com/',
  'https://www.reversinglabs.com/',
  'https://www.akamai.com/',
  'https://www.netcraft.com/',
];

const DIRECT_FEED_CANDIDATES = [
  { url: 'https://www.rapid7.com/rss.xml', title: 'Rapid7 Cybersecurity Blog' },
  { url: 'https://www.fortinet.com/blog/threat-research/rss.xml', title: 'Fortinet Threat Research' },
  { url: 'https://blog.sekoia.io/feed/', title: 'SEKOIA.IO Threat Intelligence' },
  { url: 'https://www.welivesecurity.com/en/rss/feed/', title: 'ESET WeLiveSecurity' },
  { url: 'https://www.trendmicro.com/en_us/research/rss.xml', title: 'Trend Micro Research' },
  { url: 'https://www.reversinglabs.com/blog/rss.xml', title: 'ReversingLabs Blog' },
  { url: 'https://www.netcraft.com/blog/feed/', title: 'Netcraft Blog' },
];

const BAD_FEED_PATTERNS = [
  /comments?\//i,
  /\/tag\//i,
  /\/category\//i,
  /podcast/i,
  /press-release/i,
  /careers/i,
  /events/i,
];

const THREAT_TERMS = [
  'apt', 'ransomware', 'malware', 'phishing', 'cve', 'zero-day', 'zeroday',
  'vulnerability', 'exploit', 'ioc', 'threat', 'campaign', 'intrusion',
  'backdoor', 'trojan', 'loader', 'botnet', 'credential', 'espionage',
  'initial access', 'lateral movement', 'mitre', 'attack',
];

const SECTOR_TERMS = {
  banking: ['bank', 'financial', 'fintech', 'payment', 'swift', 'crypto', 'insurance'],
  government: ['government', 'ministry', 'agency', 'public sector', 'defense', 'election', 'critical infrastructure'],
  healthcare: ['healthcare', 'hospital', 'medical', 'pharma', 'patient', 'clinic', 'biotech'],
};

function sourceHome(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.hostname}/`;
  } catch {
    return null;
  }
}

function resolveUrl(href, base) {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

async function discoverFeedsFromHome(home) {
  const res = await fetch(home, {
    headers: {
      'User-Agent': 'ClaudeThreatIntelligence/1.0 source discovery',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
    signal: AbortSignal.timeout(12000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const html = await res.text();
  const matches = [];
  const linkRe = /<link\b[^>]*>/gi;
  for (const m of html.matchAll(linkRe)) {
    const tag = m[0];
    if (!/rss|atom|application\/xml|application\/rss\+xml|application\/atom\+xml/i.test(tag)) continue;
    const href = tag.match(/\bhref=["']([^"']+)["']/i)?.[1];
    if (!href) continue;
    const title = tag.match(/\btitle=["']([^"']+)["']/i)?.[1] || 'Discovered feed';
    const url = resolveUrl(href, home);
    if (url) matches.push({ url, title });
  }

  const common = ['feed/', 'rss/', 'atom.xml', 'feed.xml', 'rss.xml'];
  for (const suffix of common) {
    const url = resolveUrl(suffix, home);
    if (url && !matches.some(m => m.url === url)) matches.push({ url, title: `Candidate ${suffix}` });
  }
  return matches;
}

async function validateFeed(url) {
  try {
    const feed = await parser.parseURL(url);
    const count = feed.items?.length || 0;
    const latest = feed.items?.[0]?.isoDate || feed.items?.[0]?.pubDate || null;
    const sampleText = [
      feed.title,
      feed.description,
      ...(feed.items || []).slice(0, 12).flatMap(item => [
        item.title,
        item.contentSnippet,
        item.content,
        item.description,
        ...(Array.isArray(item.categories) ? item.categories : []),
      ]),
    ].filter(Boolean).join('\n').toLowerCase();
    return {
      ok: count > 0,
      title: feed.title || null,
      count,
      latest,
      sampleText,
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function daysSince(value) {
  const ts = Date.parse(value || '');
  if (!Number.isFinite(ts)) return Infinity;
  return Math.max(0, (Date.now() - ts) / 86400000);
}

function inferSectors(text) {
  const sectors = [];
  for (const [sector, terms] of Object.entries(SECTOR_TERMS)) {
    if (terms.some(term => text.includes(term))) sectors.push(sector);
  }
  return sectors.length ? sectors : ['banking', 'government', 'healthcare'];
}

function scoreCandidate(item, validation, discoveredFrom, configuredHomes) {
  const url = String(item.url || '');
  const title = String(validation.title || item.title || '');
  const text = `${title}\n${validation.sampleText || ''}`.toLowerCase();
  const staleDays = daysSince(validation.latest);
  const threatTermHits = THREAT_TERMS.filter(term => text.includes(term)).length;
  const sectors = inferSectors(text);

  let score = 20;
  const reasons = [];

  if (validation.count >= 20) { score += 15; reasons.push(`${validation.count} items`); }
  else if (validation.count >= 8) { score += 10; reasons.push(`${validation.count} items`); }
  else if (validation.count >= 3) { score += 4; reasons.push(`${validation.count} items`); }

  if (staleDays <= 2) { score += 25; reasons.push('fresh within 48h'); }
  else if (staleDays <= 7) { score += 20; reasons.push('fresh within 7d'); }
  else if (staleDays <= FRESH_DAYS) { score += 10; reasons.push(`fresh within ${FRESH_DAYS}d`); }
  else { score -= 35; reasons.push(`stale latest item (${Math.round(staleDays)}d old)`); }

  if (threatTermHits >= 8) { score += 25; reasons.push('high threat-intel relevance'); }
  else if (threatTermHits >= 4) { score += 18; reasons.push('medium threat-intel relevance'); }
  else if (threatTermHits >= 2) { score += 8; reasons.push('some threat-intel relevance'); }
  else { score -= 20; reasons.push('low threat-intel relevance'); }

  if (sectors.length > 0) score += Math.min(10, sectors.length * 3);
  if (BAD_FEED_PATTERNS.some(re => re.test(url) || re.test(title))) {
    score -= 45;
    reasons.push('looks like comments/category/non-intel feed');
  }
  if (configuredHomes.has(sourceHome(url)) && discoveredFrom !== 'curated_seed') {
    score -= 35;
    reasons.push('same source domain already configured');
  }

  const status = score >= AUTO_ADD_THRESHOLD
    ? 'added'
    : score < AUTO_REJECT_THRESHOLD
      ? 'rejected'
      : 'reviewed';

  return {
    confidence: Math.max(0, Math.min(100, score)),
    status,
    sectors,
    reasons,
    source_tier: score >= 85 ? 2 : score >= 70 ? 3 : 4,
  };
}

const db = getDb(join(ROOT, 'data/threats.db'));
migrate(db);

const feedsConfig = loadFeedsConfig();
const configuredUrls = new Set((feedsConfig.feeds || []).map(f => f.url));
const configuredHomes = new Set((feedsConfig.feeds || []).map(f => sourceHome(f.url)).filter(Boolean));
const homes = [...new Set([
  ...(feedsConfig.feeds || []).map(f => sourceHome(f.url)).filter(Boolean),
  ...DISCOVERY_SEED_HOMES,
])];

const upsert = db.prepare(`
  INSERT INTO discovered_sources (
    url, title, source_type, discovered_from, confidence, status, reason, last_checked, metadata
  ) VALUES (?, ?, 'rss', ?, ?, ?, ?, datetime('now'), ?)
  ON CONFLICT(url) DO UPDATE SET
    title = excluded.title,
    confidence = excluded.confidence,
    status = CASE
      WHEN discovered_sources.status = 'added' THEN 'added'
      ELSE excluded.status
    END,
    reason = excluded.reason,
    last_checked = datetime('now'),
    metadata = excluded.metadata
`);

function demoteDuplicatePromotions() {
  const rows = db.prepare(`
    SELECT id, url, confidence, reason
    FROM discovered_sources
    WHERE status = 'added'
    ORDER BY confidence DESC, discovered_at DESC
  `).all();
  const seenHomes = new Set();
  const demote = db.prepare(`
    UPDATE discovered_sources
    SET status = 'reviewed',
        reason = ?
    WHERE id = ?
  `);
  let demoted = 0;
  for (const row of rows) {
    const home = sourceHome(row.url);
    if (!home) continue;
    if (!seenHomes.has(home)) {
      seenHomes.add(home);
      continue;
    }
    demote.run(`${row.reason || ''}; duplicate auto-promoted feed for same source domain`.replace(/^; /, ''), row.id);
    demoted++;
  }
  return demoted;
}

let candidates = 0;
let saved = 0;
let promoted = 0;
let rejected = 0;
const seenCandidateUrls = new Set();

async function considerCandidate(item, discoveredFrom) {
  if (candidates >= MAX_CANDIDATES) return;
  const normalizedUrl = String(item.url || '').trim();
  if (!normalizedUrl || seenCandidateUrls.has(normalizedUrl)) return;
  seenCandidateUrls.add(normalizedUrl);
  if (configuredUrls.has(item.url)) return;
  candidates++;
  const validation = await validateFeed(item.url);
  if (!validation.ok) return;
  const scored = scoreCandidate(item, validation, discoveredFrom, configuredHomes);
  const reason = [
    `${validation.count} items available`,
    validation.latest ? `latest ${validation.latest}` : null,
    ...scored.reasons,
  ].filter(Boolean).join('; ');
  upsert.run(
    item.url,
    validation.title || item.title,
    discoveredFrom,
    scored.confidence,
    scored.status,
    reason,
    JSON.stringify({
      ...validation,
      sampleText: undefined,
      auto_scored_at: new Date().toISOString(),
      source_tier: scored.source_tier,
      sectors: scored.sectors,
      status_reason: scored.reasons,
    })
  );
  saved++;
  if (scored.status === 'added') promoted++;
  if (scored.status === 'rejected') rejected++;
}

for (const item of DIRECT_FEED_CANDIDATES) {
  try {
    await considerCandidate(item, 'curated_seed');
  } catch (e) {
    console.warn(`Discovery failed for ${item.url}: ${e.message}`);
  }
}

for (const home of homes) {
  try {
    const discovered = await discoverFeedsFromHome(home);
    for (const item of discovered) {
      await considerCandidate(item, home);
    }
  } catch (e) {
    console.warn(`Discovery failed for ${home}: ${e.message}`);
  }
}

const demotedDuplicates = demoteDuplicatePromotions();
db.close();
console.log(`Discovered ${saved} candidate feeds from ${candidates} candidates (${promoted} auto-added, ${rejected} auto-rejected, ${demotedDuplicates} duplicate promotions demoted).`);
process.exit(0);
