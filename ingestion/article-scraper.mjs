import * as cheerio from 'cheerio';
import { createHash } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execFile } from 'child_process';
import { promisify } from 'util';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const RAW_DIR = join(ROOT, 'data/raw');
const execFileAsync = promisify(execFile);

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
  '[aria-label="breadcrumb"]', '.breadcrumb', '.breadcrumbs',
];

function cleanText(text) {
  return (text || '')
    .replace(/\s+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function extractJsonLdArticle($) {
  const candidates = [];
  $('script[type="application/ld+json"]').each((_, el) => {
    const raw = $(el).contents().text();
    if (!raw) return;
    try {
      const parsed = JSON.parse(raw);
      const nodes = Array.isArray(parsed) ? parsed : [parsed, ...(parsed['@graph'] || [])];
      for (const node of nodes.flat()) {
        const type = node?.['@type'];
        const types = Array.isArray(type) ? type : [type];
        if (types.some(t => ['Article', 'NewsArticle', 'BlogPosting', 'Report'].includes(t))) {
          candidates.push({
            headline: node.headline,
            description: node.description,
            articleBody: node.articleBody,
            datePublished: node.datePublished,
            author: Array.isArray(node.author) ? node.author.map(a => a.name).filter(Boolean).join(', ') : node.author?.name,
          });
        }
      }
    } catch {}
  });
  return candidates.find(c => c.articleBody || c.description || c.headline) || null;
}

function bestParagraphText($) {
  const paragraphs = [];
  $('p, li').each((_, el) => {
    const text = cleanText($(el).text());
    if (text.length >= 60) paragraphs.push(text);
  });
  return paragraphs.join('\n\n');
}

function detectAccessLimit($, rawText) {
  const text = rawText.toLowerCase();
  const patterns = [
    'enable javascript',
    'subscribe to continue',
    'sign in to continue',
    'already a subscriber',
    'paywall',
    'access denied',
    'verify you are human',
  ];
  return patterns.find(p => text.includes(p)) || null;
}

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

function chromeCandidates() {
  return [
    process.env.CHROME_PATH,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
}

function findChrome() {
  return chromeCandidates().find(p => p.includes('/') ? existsSync(p) : p);
}

export async function fetchArticleWithPlaywright(url, timeoutMs = 30000) {
  let chromium;
  try {
    ({ chromium } = await import('playwright-core'));
  } catch {
    return { success: false, error: 'playwright-core not installed' };
  }
  const executablePath = findChrome();
  if (!executablePath) return { success: false, error: 'No local Chrome/Chromium executable found for Playwright' };

  let browser;
  try {
    browser = await chromium.launch({ headless: true, executablePath });
    const page = await browser.newPage({
      userAgent: 'Mozilla/5.0 (compatible; RadarThreatIntelligence/1.0; security research)',
    });
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    try {
      await page.waitForLoadState('networkidle', { timeout: Math.min(8000, timeoutMs) });
    } catch {}
    const html = await page.content();
    const finalUrl = page.url();
    await browser.close();
    return { success: true, html, finalUrl, rendered: true, renderer: 'playwright' };
  } catch (err) {
    try { await browser?.close(); } catch {}
    return { success: false, error: `Playwright render failed: ${err.message}` };
  }
}

export async function fetchArticleWithBrowser(url, timeoutMs = 30000) {
  const playwrightResult = await fetchArticleWithPlaywright(url, timeoutMs);
  if (playwrightResult.success) return playwrightResult;

  const chrome = findChrome();
  if (!chrome) return { success: false, error: `${playwrightResult.error}; no Chrome/Chromium executable found` };

  try {
    const { stdout } = await execFileAsync(chrome, [
      '--headless=new',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-background-networking',
      '--disable-extensions',
      '--disable-sync',
      '--no-first-run',
      '--no-default-browser-check',
      '--virtual-time-budget=8000',
      '--dump-dom',
      url,
    ], {
      timeout: timeoutMs,
      maxBuffer: 20 * 1024 * 1024,
      env: { ...process.env },
    });

    if (!stdout || stdout.length < 200) return { success: false, error: 'Rendered DOM too short' };
    return { success: true, html: stdout, finalUrl: url, rendered: true, renderer: 'chrome_dump_dom' };
  } catch (err) {
    return { success: false, error: `Browser render failed: ${err.message}` };
  }
}

export function extractContent(html, url) {
  const $ = cheerio.load(html);
  const jsonLd = extractJsonLdArticle($);

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

  let rawText = cleanText(contentEl.text());
  const paragraphText = bestParagraphText($);
  if (paragraphText.length > rawText.length * 1.2) rawText = paragraphText;
  if (jsonLd?.articleBody && jsonLd.articleBody.length > rawText.length) rawText = cleanText(jsonLd.articleBody);

  // Extract metadata
  const title = jsonLd?.headline ||
    $('meta[property="og:title"]').attr('content') ||
    $('title').text() || '';

  const description = jsonLd?.description ||
    $('meta[property="og:description"]').attr('content') ||
    $('meta[name="description"]').attr('content') || '';

  const publishedAt = jsonLd?.datePublished ||
    $('meta[property="article:published_time"]').attr('content') ||
    $('time[datetime]').first().attr('datetime') ||
    $('meta[name="date"]').attr('content') ||
    $('meta[name="publish-date"]').attr('content') ||
    $('meta[name="pubdate"]').attr('content') || null;

  const author = jsonLd?.author ||
    $('meta[name="author"]').attr('content') ||
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
    access_limit: detectAccessLimit($, rawText),
    extraction_method: jsonLd?.articleBody ? 'jsonld_article_body' : (paragraphText.length > 0 ? 'html_paragraphs' : 'html_main_selector'),
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

  let { success, html, error, finalUrl, rendered, renderer } = await fetchArticle(url);
  if (!success && process.env.BROWSER_RENDERED_SCRAPE !== 'false') {
    const browserResult = await fetchArticleWithBrowser(url);
    if (browserResult.success) {
      ({ success, html, error, finalUrl, rendered, renderer } = browserResult);
    }
  }
  if (!success) return { success: false, error };

  const extracted = extractContent(html, finalUrl || url);

  if (extracted.content_length < 200) {
    if (!rendered && process.env.BROWSER_RENDERED_SCRAPE !== 'false') {
      const browserResult = await fetchArticleWithBrowser(url);
      if (browserResult.success) {
        const browserExtracted = extractContent(browserResult.html, browserResult.finalUrl || url);
        if (browserExtracted.content_length >= 200) {
          const result = {
            success: true,
            url: browserResult.finalUrl || url,
            ...browserExtracted,
            extraction_method: `${browserResult.renderer || 'browser_rendered'}:${browserExtracted.extraction_method}`,
          };
          if (cacheEnabled) {
            writeFileSync(cachePath, JSON.stringify({ cached_at: new Date().toISOString(), data: result }));
          }
          return result;
        }
      }
    }
    return {
      success: false,
      error: extracted.access_limit ? `Access limited: ${extracted.access_limit}` : 'Content too short (paywall or bot block)',
      ...extracted,
    };
  }

  const result = {
    success: true,
    url: finalUrl || url,
    ...extracted,
    extraction_method: rendered ? `${renderer || 'browser_rendered'}:${extracted.extraction_method}` : extracted.extraction_method,
  };

  if (cacheEnabled) {
    writeFileSync(cachePath, JSON.stringify({ cached_at: new Date().toISOString(), data: result }));
  }

  return result;
}
