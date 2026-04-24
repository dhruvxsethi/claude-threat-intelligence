import * as cheerio from 'cheerio';
import { createHash } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const RAW_DIR = join(ROOT, 'data/raw');

// Selectors to try for main article content (ordered by preference)
const CONTENT_SELECTORS = [
  'article', '[role="main"]', 'main',
  '.article-body', '.post-content', '.entry-content', '.content-body',
  '.article-content', '.post-body', '.blog-post', '.story-body',
  '#article-body', '#content', '.threat-report', '.research-content',
];

// Elements to remove (noise)
const NOISE_SELECTORS = [
  'script', 'style', 'nav', 'header', 'footer', 'aside',
  '.sidebar', '.advertisement', '.ads', '.social-share',
  '.related-posts', '.newsletter', '.comments', '#comments',
  '.cookie-banner', '.popup', 'iframe', 'form',
];

export async function fetchArticle(url, timeoutMs = 15000) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; ClaudeThreatIntelligence/1.0; +https://github.com/dhruvxsethi/claude-threat-intelligence)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
      },
    });

    clearTimeout(timer);

    if (!res.ok) return { success: false, error: `HTTP ${res.status}` };

    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('html') && !contentType.includes('xml')) {
      return { success: false, error: 'Not HTML content' };
    }

    const html = await res.text();
    return { success: true, html, finalUrl: res.url };
  } catch (err) {
    if (err.name === 'AbortError') return { success: false, error: 'Timeout' };
    return { success: false, error: err.message };
  }
}

export function extractContent(html, url) {
  const $ = cheerio.load(html);

  // Remove noise elements
  NOISE_SELECTORS.forEach(sel => $(sel).remove());

  // Try to find main content
  let contentEl = null;
  for (const sel of CONTENT_SELECTORS) {
    const el = $(sel).first();
    if (el.length && el.text().trim().length > 200) {
      contentEl = el;
      break;
    }
  }

  // Fallback to body
  if (!contentEl) contentEl = $('body');

  const rawText = contentEl.text()
    .replace(/\s+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  // Extract metadata
  const title = $('meta[property="og:title"]').attr('content') ||
    $('title').text() || '';

  const description = $('meta[property="og:description"]').attr('content') ||
    $('meta[name="description"]').attr('content') || '';

  const publishedAt = $('meta[property="article:published_time"]').attr('content') ||
    $('time[datetime]').first().attr('datetime') ||
    $('meta[name="pubdate"]').attr('content') || null;

  const author = $('meta[name="author"]').attr('content') ||
    $('[rel="author"]').first().text() ||
    $('.author').first().text() || null;

  // Extract all links (useful for finding IOC references, CVE links, etc.)
  const links = [];
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (href && (href.startsWith('http') || href.startsWith('/'))) {
      links.push({ text: $(el).text().trim(), href });
    }
  });

  // Look for CVE mentions in text
  const cvePattern = /CVE-\d{4}-\d{4,7}/gi;
  const cveMatches = [...new Set(rawText.match(cvePattern) || [])];

  // Look for IOC patterns directly in text
  const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const hashPattern = /\b[0-9a-fA-F]{32,64}\b/g;

  const ipMatches = [...new Set(rawText.match(ipPattern) || [])].filter(ip =>
    !ip.startsWith('127.') && !ip.startsWith('192.168.') &&
    !ip.startsWith('10.') && !ip.startsWith('0.')
  );

  const hashMatches = [...new Set(rawText.match(hashPattern) || [])];

  return {
    title: title.trim(),
    description: description.trim(),
    content: rawText,
    published_at: publishedAt,
    author: author?.trim(),
    links: links.slice(0, 50),
    cve_mentions: cveMatches,
    ip_mentions: ipMatches.slice(0, 20),
    hash_mentions: hashMatches.slice(0, 20),
    content_length: rawText.length,
    content_hash: createHash('sha256').update(rawText).digest('hex'),
  };
}

export async function scrapeArticle(url, cacheEnabled = true) {
  if (!existsSync(RAW_DIR)) mkdirSync(RAW_DIR, { recursive: true });

  const cacheKey = createHash('md5').update(url).digest('hex');
  const cachePath = join(RAW_DIR, `${cacheKey}.json`);

  // Check cache (valid for 24 hours)
  if (cacheEnabled && existsSync(cachePath)) {
    const cached = JSON.parse(readFileSync(cachePath, 'utf8'));
    const age = Date.now() - new Date(cached.cached_at).getTime();
    if (age < 24 * 60 * 60 * 1000) {
      return { ...cached.data, fromCache: true };
    }
  }

  const { success, html, error, finalUrl } = await fetchArticle(url);
  if (!success) return { success: false, error };

  const extracted = extractContent(html, finalUrl || url);

  if (extracted.content_length < 200) {
    return { success: false, error: 'Content too short (paywall or bot block)' };
  }

  const result = { success: true, url: finalUrl || url, ...extracted };

  if (cacheEnabled) {
    writeFileSync(cachePath, JSON.stringify({ cached_at: new Date().toISOString(), data: result }));
  }

  return result;
}
