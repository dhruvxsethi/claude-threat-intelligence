import Parser from 'rss-parser';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import { createHash } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const parser = new Parser({
  timeout: 10000,
  headers: {
    'User-Agent': 'ClaudeThreatIntelligence/1.0 (security research feed aggregator)',
    'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
  },
  customFields: {
    item: ['description', 'content:encoded', 'dc:creator', 'category', 'author'],
  },
});

export function loadFeedsConfig() {
  const raw = readFileSync(join(ROOT, 'config/feeds.yml'), 'utf8');
  return yaml.load(raw);
}

export function loadSettings() {
  const raw = readFileSync(join(ROOT, 'config/settings.yml'), 'utf8');
  return yaml.load(raw);
}

export function getCurrentSlot(settings) {
  const hour = new Date().getUTCHours();
  const slotA = settings.pipeline.slot_a_hours;
  const slotB = settings.pipeline.slot_b_hours;
  if (slotA.includes(hour)) return 'A';
  if (slotB.includes(hour)) return 'B';
  // Not an exact slot hour — run the nearest slot
  return hour % 6 < 3 ? 'A' : 'B';
}

export function getFeedsForSlot(feedsConfig, slot) {
  return feedsConfig.feeds.filter(f =>
    f.enabled &&
    f.type === 'rss' &&
    (f.rotation_slot === slot || f.rotation_slot === 'BOTH')
  );
}

export function getNvdFeed(settings) {
  const since = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString().replace('.000Z', '.000');
  return {
    id: 'nvd_cve_api',
    url: `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&pubStartDate=${since}`,
    name: 'NIST NVD CVE Database',
    tier: 1,
    source_credibility: 100,
  };
}

export function getCisaKevFeed() {
  return {
    id: 'cisa_kev_api',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    name: 'CISA Known Exploited Vulnerabilities',
    tier: 1,
    source_credibility: 100,
  };
}

export async function fetchRssFeed(feed) {
  try {
    const result = await parser.parseURL(feed.url);
    const items = (result.items || []).slice(0, 30).map(item => ({
      url: item.link || item.guid,
      title: item.title || '',
      description: item.description || item.contentSnippet || '',
      published_at: item.pubDate || item.isoDate || new Date().toISOString(),
      feed_id: feed.id,
      feed_name: feed.name,
      source_tier: feed.tier,
      source_credibility: feed.source_credibility,
      content_hash: createHash('sha256').update(item.link || item.title || '').digest('hex'),
    }));
    return { success: true, items, feed_title: result.title };
  } catch (err) {
    return { success: false, items: [], error: err.message };
  }
}

export async function fetchNvdCves() {
  try {
    const since = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString().split('.')[0] + '.000';
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&pubStartDate=${since}`;
    const res = await fetch(url, {
      headers: { 'User-Agent': 'ClaudeThreatIntelligence/1.0' },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return { success: false, cves: [], error: `HTTP ${res.status}` };
    const data = await res.json();
    const cves = (data.vulnerabilities || []).map(v => {
      const cve = v.cve;
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
      const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
      return {
        cve_id: cve.id,
        cvss_score: metrics?.cvssData?.baseScore || null,
        cvss_vector: metrics?.cvssData?.vectorString || null,
        cvss_severity: metrics?.cvssData?.baseSeverity || null,
        description: desc,
        published_date: cve.published,
        affected_products: (cve.configurations || []).flatMap(c =>
          c.nodes?.flatMap(n => n.cpeMatch?.map(m => m.criteria) || []) || []
        ).slice(0, 10),
        references: (cve.references || []).map(r => r.url).slice(0, 5),
        source_url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      };
    });
    return { success: true, cves };
  } catch (err) {
    return { success: false, cves: [], error: err.message };
  }
}

export async function fetchCisaKev() {
  try {
    const res = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: AbortSignal.timeout(15000) }
    );
    if (!res.ok) return { success: false, vulnerabilities: [], error: `HTTP ${res.status}` };
    const data = await res.json();
    // Return only entries added in the last 7 days
    const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recent = (data.vulnerabilities || []).filter(v =>
      v.dateAdded && new Date(v.dateAdded) > cutoff
    );
    return { success: true, vulnerabilities: recent, total: data.vulnerabilities?.length };
  } catch (err) {
    return { success: false, vulnerabilities: [], error: err.message };
  }
}

export async function fetchGithubAdvisories() {
  try {
    const res = await fetch(
      'https://api.github.com/advisories?per_page=30&type=reviewed',
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'ClaudeThreatIntelligence/1.0',
        },
        signal: AbortSignal.timeout(15000),
      }
    );
    if (!res.ok) return { success: false, advisories: [], error: `HTTP ${res.status}` };
    const advisories = await res.json();
    return {
      success: true,
      advisories: advisories.map(a => ({
        id: a.ghsa_id,
        cve_id: a.cve_id,
        summary: a.summary,
        description: a.description,
        severity: a.severity,
        cvss_score: a.cvss?.score,
        cvss_vector: a.cvss?.vector_string,
        published_at: a.published_at,
        url: a.html_url,
        affected: (a.vulnerabilities || []).map(v => ({
          package: v.package?.name,
          ecosystem: v.package?.ecosystem,
          vulnerable_version_range: v.vulnerable_version_range,
          patched_versions: v.patched_versions,
        })),
      })),
    };
  } catch (err) {
    return { success: false, advisories: [], error: err.message };
  }
}

export async function runAllFeeds(slot, db, log = console.log) {
  const feedsConfig = loadFeedsConfig();
  const rssFeeds = getFeedsForSlot(feedsConfig, slot);

  log(`\nFetching ${rssFeeds.length} RSS feeds for slot ${slot}...`);
  const results = [];

  // RSS feeds with concurrency control
  const concurrency = 5;
  for (let i = 0; i < rssFeeds.length; i += concurrency) {
    const batch = rssFeeds.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(f => fetchRssFeed(f)));
    results.push(...batchResults.map((r, j) => ({ feed: batch[j], ...r })));
    await new Promise(r => setTimeout(r, 500));
  }

  // API sources (always run on slot A)
  const apiResults = { nvd: null, kev: null, github: null };
  if (slot === 'A') {
    log('Fetching vulnerability APIs...');
    [apiResults.nvd, apiResults.kev, apiResults.github] = await Promise.all([
      fetchNvdCves(),
      fetchCisaKev(),
      fetchGithubAdvisories(),
    ]);
  }

  // Update feed health in DB
  const updateHealth = db.prepare(`
    INSERT INTO feed_health (feed_id, feed_name, last_checked, last_success, consecutive_failures, is_healthy)
    VALUES (?, ?, datetime('now'), ?, ?, ?)
    ON CONFLICT(feed_id) DO UPDATE SET
      last_checked = datetime('now'),
      last_success = CASE WHEN excluded.is_healthy = 1 THEN datetime('now') ELSE last_success END,
      consecutive_failures = CASE WHEN excluded.is_healthy = 1 THEN 0 ELSE consecutive_failures + 1 END,
      is_healthy = excluded.is_healthy,
      error_message = excluded.error_message
  `);

  for (const r of results) {
    updateHealth.run(
      r.feed.id, r.feed.name,
      r.success ? new Date().toISOString() : null,
      r.success ? 0 : 1,
      r.success ? 1 : 0
    );
  }

  return { rssResults: results, apiResults };
}
