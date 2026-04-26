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

function stableFeedId(prefix, value) {
  return `${prefix}_${createHash('sha1').update(String(value || '')).digest('hex').slice(0, 12)}`;
}

function loadPromotedFeeds(db, settings = {}) {
  if (!db || settings.feeds?.auto_promote_discovered === false) return [];
  try {
    return db.prepare(`
      SELECT url, title, confidence, metadata
      FROM discovered_sources
      WHERE status = 'added'
        AND source_type = 'rss'
      ORDER BY confidence DESC, discovered_at DESC
      LIMIT ?
    `).all(settings.feeds?.max_auto_promoted_feeds || 25).map(row => {
      let metadata = {};
      try { metadata = JSON.parse(row.metadata || '{}'); } catch {}
      const sourceTier = metadata.source_tier || (row.confidence >= 85 ? 2 : row.confidence >= 70 ? 3 : 4);
      return {
        id: stableFeedId('auto', row.url),
        name: row.title || metadata.title || new URL(row.url).hostname,
        url: row.url,
        type: 'rss',
        tier: sourceTier,
        rotation_slot: 'B',
        sectors: metadata.sectors || ['banking', 'government', 'healthcare'],
        enabled: true,
        source_credibility: Math.max(60, Math.min(90, row.confidence || 70)),
        auto_discovered: true,
      };
    });
  } catch {
    return [];
  }
}

function isoDateForApi(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

function getJsonHeaders() {
  const headers = { 'User-Agent': 'ClaudeThreatIntelligence/1.0' };
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  return headers;
}

function normalizeNvdCve(v) {
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
}

export async function fetchRssFeed(feed, { maxItems = 30 } = {}) {
  try {
    const result = await parser.parseURL(feed.url);
    const items = (result.items || []).slice(0, maxItems).map(item => ({
      url: item.link || item.guid,
      title: item.title || '',
      description: item['content:encoded'] || item.content || item.description || item.contentSnippet || '',
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

export async function fetchNvdCves({ hoursBack = 48, resultsPerPage = 2000, maxPages = 5 } = {}) {
  try {
    const since = new Date(Date.now() - hoursBack * 60 * 60 * 1000);
    const until = new Date();
    const cves = [];
    let startIndex = 0;
    let totalResults = Infinity;
    let pages = 0;

    while (startIndex < totalResults && pages < maxPages) {
      const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
      url.searchParams.set('resultsPerPage', String(resultsPerPage));
      url.searchParams.set('startIndex', String(startIndex));
      url.searchParams.set('pubStartDate', isoDateForApi(since));
      url.searchParams.set('pubEndDate', isoDateForApi(until));
      url.searchParams.set('noRejected', '');

      const res = await fetch(url, {
        headers: getJsonHeaders(),
        signal: AbortSignal.timeout(20000),
      });
      if (!res.ok) return { success: false, cves: [], error: `HTTP ${res.status}: ${await res.text()}` };

      const data = await res.json();
      const vulnerabilities = data.vulnerabilities || [];
      cves.push(...vulnerabilities.map(normalizeNvdCve));

      totalResults = data.totalResults || vulnerabilities.length;
      startIndex += data.resultsPerPage || vulnerabilities.length || resultsPerPage;
      pages++;
    }

    cves.sort((a, b) => new Date(b.published_date || 0) - new Date(a.published_date || 0));
    return { success: true, cves, total: totalResults };
  } catch (err) {
    return { success: false, cves: [], error: err.message };
  }
}

export async function fetchCisaKev({ daysBack = 7 } = {}) {
  try {
    const res = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: AbortSignal.timeout(15000) }
    );
    if (!res.ok) return { success: false, vulnerabilities: [], error: `HTTP ${res.status}` };
    const data = await res.json();
    const cutoff = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000);
    const recent = (data.vulnerabilities || []).filter(v =>
      v.dateAdded && new Date(v.dateAdded) > cutoff
    );
    return { success: true, vulnerabilities: recent, total: data.vulnerabilities?.length };
  } catch (err) {
    return { success: false, vulnerabilities: [], error: err.message };
  }
}

export async function fetchGithubAdvisories({ hoursBack = 48, perPage = 100 } = {}) {
  try {
    const since = new Date(Date.now() - hoursBack * 60 * 60 * 1000).toISOString().slice(0, 10);
    const url = new URL('https://api.github.com/advisories');
    url.searchParams.set('per_page', String(perPage));
    url.searchParams.set('type', 'reviewed');
    url.searchParams.set('sort', 'published');
    url.searchParams.set('direction', 'desc');
    url.searchParams.set('modified', `>=${since}`);

    const res = await fetch(url, {
      headers: {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'ClaudeThreatIntelligence/1.0',
      },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return { success: false, advisories: [], error: `HTTP ${res.status}: ${await res.text()}` };
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
        updated_at: a.updated_at,
        url: a.html_url,
        references: a.references || [],
        affected: (a.vulnerabilities || []).map(v => ({
          package: v.package?.name,
          ecosystem: v.package?.ecosystem,
          vulnerable_version_range: v.vulnerable_version_range,
          patched_versions: v.first_patched_version?.identifier || null,
        })),
      })),
    };
  } catch (err) {
    return { success: false, advisories: [], error: err.message };
  }
}

function hoursSince(value) {
  const ts = Date.parse(value || '');
  if (!Number.isFinite(ts)) return Infinity;
  return Math.max(0, (Date.now() - ts) / 3600000);
}

export async function runAllFeeds(db, log = console.log, settings = {}) {
  const feedsConfig = loadFeedsConfig();
  // Fetch ALL enabled RSS feeds — no slot rotation
  const configuredRssFeeds = feedsConfig.feeds.filter(f => f.enabled && f.type === 'rss');
  const promotedFeeds = loadPromotedFeeds(db, settings);
  const seenUrls = new Set();
  const rssFeeds = [...configuredRssFeeds, ...promotedFeeds].filter(feed => {
    const key = String(feed.url || '').trim().toLowerCase();
    if (!key || seenUrls.has(key)) return false;
    seenUrls.add(key);
    return true;
  });
  const baseMaxItems = settings.feeds?.max_items_per_feed || 30;
  const catchupMaxItems = settings.feeds?.catchup_max_items_per_feed || 100;
  const catchupAfterHours = settings.pipeline?.startup_catchup_after_hours || 3;
  const healthRows = Object.fromEntries(db.prepare('SELECT feed_id, last_success FROM feed_health').all().map(r => [r.feed_id, r]));

  log(`\nFetching ${rssFeeds.length} RSS feeds in parallel (${configuredRssFeeds.length} configured, ${promotedFeeds.length} auto-promoted)...`);
  const results = [];

  // Concurrency-controlled parallel fetch
  const concurrency = 8;
  for (let i = 0; i < rssFeeds.length; i += concurrency) {
    const batch = rssFeeds.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(f => {
      const downtimeHours = hoursSince(healthRows[f.id]?.last_success);
      const maxItems = downtimeHours >= catchupAfterHours ? catchupMaxItems : baseMaxItems;
      return fetchRssFeed(f, { maxItems });
    }));
    results.push(...batchResults.map((r, j) => ({ feed: batch[j], ...r })));
  }

  // Update feed health in DB
  const updateHealth = db.prepare(`
    INSERT INTO feed_health (
      feed_id, feed_name, last_checked, last_success,
      consecutive_failures, is_healthy, error_message
    )
    VALUES (?, ?, datetime('now'), ?, ?, ?, ?)
    ON CONFLICT(feed_id) DO UPDATE SET
      feed_name = excluded.feed_name,
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
      r.success ? 1 : 0,
      r.success ? null : r.error
    );
  }

  return { rssResults: results };
}
