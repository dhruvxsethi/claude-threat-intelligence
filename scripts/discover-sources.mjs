#!/usr/bin/env node
/**
 * Discover candidate RSS/Atom feeds from configured source homepages.
 * It records suggestions in discovered_sources; it does not edit feeds.yml.
 */

import Parser from 'rss-parser';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb, migrate } from './migrate.mjs';
import { loadFeedsConfig } from '../ingestion/feed-fetcher.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const parser = new Parser({ timeout: 10000 });

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
    return {
      ok: count > 0,
      title: feed.title || null,
      count,
      latest: feed.items?.[0]?.isoDate || feed.items?.[0]?.pubDate || null,
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

const db = getDb(join(ROOT, 'data/threats.db'));
migrate(db);

const feedsConfig = loadFeedsConfig();
const configuredUrls = new Set((feedsConfig.feeds || []).map(f => f.url));
const homes = [...new Set((feedsConfig.feeds || []).map(f => sourceHome(f.url)).filter(Boolean))];

const upsert = db.prepare(`
  INSERT INTO discovered_sources (
    url, title, source_type, discovered_from, confidence, reason, last_checked, metadata
  ) VALUES (?, ?, 'rss', ?, ?, ?, datetime('now'), ?)
  ON CONFLICT(url) DO UPDATE SET
    title = excluded.title,
    confidence = excluded.confidence,
    reason = excluded.reason,
    last_checked = datetime('now'),
    metadata = excluded.metadata
`);

let candidates = 0;
let saved = 0;

for (const home of homes) {
  try {
    const discovered = await discoverFeedsFromHome(home);
    for (const item of discovered) {
      if (configuredUrls.has(item.url)) continue;
      candidates++;
      const validation = await validateFeed(item.url);
      if (!validation.ok) continue;
      const confidence = validation.count >= 10 ? 80 : 60;
      upsert.run(
        item.url,
        validation.title || item.title,
        home,
        confidence,
        `${validation.count} items available${validation.latest ? `; latest ${validation.latest}` : ''}`,
        JSON.stringify(validation)
      );
      saved++;
    }
  } catch (e) {
    console.warn(`Discovery failed for ${home}: ${e.message}`);
  }
}

db.close();
console.log(`Discovered ${saved} candidate feeds from ${candidates} candidates.`);
