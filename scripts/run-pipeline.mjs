#!/usr/bin/env node
/**
 * Sentinel Threat Intelligence — ingestion pipeline
 * Fetches all feeds + vulnerability APIs, analyzes via Ollama or Anthropic, saves to SQLite.
 */

import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, readFileSync } from 'fs';

// ── Load .env FIRST before any other imports use process.env ─────────────────
const __envDir = dirname(fileURLToPath(import.meta.url));
const envPath = join(__envDir, '..', '.env');
if (existsSync(envPath)) {
  readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) return;
    const k = trimmed.slice(0, eqIdx).trim();
    const v = trimmed.slice(eqIdx + 1).trim();
    if (k && !process.env[k]) process.env[k] = v;
  });
}

import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import chalk from 'chalk';
import { getDb, migrate } from './migrate.mjs';
import { runAllFeeds, fetchNvdCves, fetchCisaKev, fetchGithubAdvisories, loadSettings } from '../ingestion/feed-fetcher.mjs';
import { scrapeArticle } from '../ingestion/article-scraper.mjs';
import { Deduplicator } from '../ingestion/dedup.mjs';
import { analyzeArticle, analyzeNvdCve, analyzeCisaKevEntry } from '../intelligence/analyzer.mjs';
import { normalizeArticleThreat, normalizeCveThreat } from '../intelligence/normalizer.mjs';
import { Correlator } from '../intelligence/correlator.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const log  = (msg, color = 'white') => console.log(chalk[color](msg));
const ok   = msg => log(`  ✓ ${msg}`, 'green');
const warn = msg => log(`  ⚠ ${msg}`, 'yellow');
const err  = msg => log(`  ✗ ${msg}`, 'red');
const info = msg => log(`  → ${msg}`, 'cyan');

// Notify portal that the pipeline is done (triggers browser SSE refresh)
async function notifyPortalDone(threats, errors) {
  const port = process.env.PORT || 3000;
  try {
    await fetch(`http://localhost:${port}/api/pipeline/done`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threats_created: threats, errors }),
      signal: AbortSignal.timeout(3000),
    });
  } catch {
    // Portal not running (e.g. CLI-only run) — that's fine, skip notification
  }
}

async function saveThreat(db, threat) {
  const insert = db.prepare(`
    INSERT OR IGNORE INTO threats (
      id, title, summary, severity, threat_type, kill_chain_stage,
      credibility_score, source_url, source_name, source_tier,
      published_at, ingested_at, analyzed_at, sector_impact,
      sectors, geography, malware_families, affected_products,
      raw_content_hash, content_length, is_corroborated,
      corroboration_count, related_threat_ids, slot
    ) VALUES (
      @id, @title, @summary, @severity, @threat_type, @kill_chain_stage,
      @credibility_score, @source_url, @source_name, @source_tier,
      @published_at, @ingested_at, @analyzed_at, @sector_impact,
      @sectors, @geography, @malware_families, @affected_products,
      @raw_content_hash, @content_length, @is_corroborated,
      @corroboration_count, @related_threat_ids, @slot
    )
  `);

  const insertCve = db.prepare(`
    INSERT OR IGNORE INTO threat_cves (
      threat_id, cve_id, cvss_score, cvss_vector, cvss_severity,
      description, affected_products, patch_available, patch_url,
      in_kev, exploited_in_wild, published_date
    ) VALUES (
      @threat_id, @cve_id, @cvss_score, @cvss_vector, @cvss_severity,
      @description, @affected_products, @patch_available, @patch_url,
      @in_kev, @exploited_in_wild, @published_date
    )
  `);

  const insertIoc = db.prepare(`
    INSERT OR IGNORE INTO threat_iocs (
      threat_id, ioc_type, ioc_value, confidence, malware_family, context
    ) VALUES (@threat_id, @ioc_type, @ioc_value, @confidence, @malware_family, @context)
  `);

  const insertTtp = db.prepare(`
    INSERT OR IGNORE INTO threat_ttps (
      threat_id, mitre_id, tactic, technique, sub_technique, procedure
    ) VALUES (@threat_id, @mitre_id, @tactic, @technique, @sub_technique, @procedure)
  `);

  const insertActor = db.prepare(`
    INSERT INTO threat_actors (
      threat_id, name, aliases, origin_country, motivation, sophistication, active_since, description
    ) VALUES (@threat_id, @name, @aliases, @origin_country, @motivation, @sophistication, @active_since, @description)
  `);

  const saveAll = db.transaction(() => {
    const { _cves, _iocs, _ttps, _actors, ...threatRecord } = threat;
    let result;
    try {
      result = insert.run(threatRecord);
    } catch (e) {
      warn(`saveThreat constraint error: ${e.message} — ${threatRecord.source_url?.slice(0, 60)}`);
      return false;
    }
    if (result.changes === 0) {
      warn(`saveThreat skipped (duplicate): ${threatRecord.source_url?.slice(0, 60)}`);
      return false;
    }
    (_cves   || []).forEach(c => { try { insertCve.run(c);   } catch {} });
    (_iocs   || []).forEach(i => { try { insertIoc.run(i);   } catch {} });
    (_ttps   || []).forEach(t => { try { insertTtp.run(t);   } catch {} });
    (_actors || []).forEach(a => { try { insertActor.run(a); } catch {} });
    return true;
  });

  return saveAll();
}

async function processArticles(db, items, dedup, correlator, settings) {
  const maxAnalyze = settings.claude.max_articles_per_run;
  const newItems = dedup.filterNewItems(items);
  let analyzed = 0, threats = 0, errors = 0;

  info(`${newItems.length} new articles of ${items.length} total to process`);

  for (const item of newItems) {
    if (analyzed >= maxAnalyze) {
      warn(`Reached analysis limit (${maxAnalyze}). Rest queued for next run.`);
      break;
    }

    try {
      const scraped = await scrapeArticle(item.url);

      let content, contentLength, contentHash, cve_mentions, ip_mentions, hash_mentions;

      if (scraped.success && (scraped.content_length || 0) >= 300) {
        content       = scraped.content;
        contentLength = scraped.content_length;
        contentHash   = scraped.content_hash;
        cve_mentions  = scraped.cve_mentions;
        ip_mentions   = scraped.ip_mentions;
        hash_mentions = scraped.hash_mentions;
      } else {
        // Fall back to RSS title + description when scraping fails
        const fallback = [item.title, item.description].filter(s => s && s.trim()).join('\n\n');
        if (fallback.length < 80) {
          dedup.registerArticle(item.url, item.feed_id, item.title, item.published_at, null);
          dedup.markSkipped(item.url, scraped.success ? 'content_too_short' : (scraped.error || 'scrape_failed'));
          continue;
        }
        content       = fallback;
        contentLength = fallback.length;
        contentHash   = createHash('sha256').update(fallback).digest('hex');
        cve_mentions  = [];
        ip_mentions   = [];
        hash_mentions = [];
        info(`RSS fallback (${contentLength}ch): ${item.url.slice(0, 60)}`);
      }

      // ── CRITICAL: check for duplicate content BEFORE registering ─────────
      // If we register first, isNewContent will always find it and skip everything.
      const isNewContent = dedup.isNewContent(contentHash);
      dedup.registerArticle(item.url, item.feed_id, item.title, item.published_at, contentHash);

      if (!isNewContent) {
        dedup.markSkipped(item.url, 'duplicate_content');
        continue;
      }

      const articleForAnalysis = {
        url:            item.url,
        title:          item.title || scraped?.title || '',
        content,
        published_at:   item.published_at || scraped?.published_at,
        content_hash:   contentHash,
        content_length: contentLength,
        source_name:    item.feed_name,
        cve_mentions,
        ip_mentions,
        hash_mentions,
      };

      const analysis = await analyzeArticle(articleForAnalysis, item.source_credibility || 70);
      analyzed++;

      if (!analysis.success) {
        err(`Analysis failed: ${analysis.error} — ${item.url.slice(0, 60)}`);
        errors++;
        continue;
      }

      const threat = normalizeArticleThreat(analysis.data, articleForAnalysis, {
        name:              item.feed_name,
        source_tier:       item.source_tier,
        source_credibility:item.source_credibility,
        rotation_slot:     'BOTH',
      });

      const saved = await saveThreat(db, threat);
      if (saved) {
        dedup.markAnalyzed(item.url, threat.id);
        correlator.correlate(threat.id);
        correlator.updateIocIndex(threat._iocs || [], threat.id);
        threats++;
        ok(`[${(threat.severity || 'unknown').toUpperCase()}] ${threat.title.slice(0, 80)}`);
      }

      // Brief pause between analysis calls
      await new Promise(r => setTimeout(r, 200));

    } catch (e) {
      err(`Error processing ${item.url}: ${e.message}`);
      errors++;
    }
  }

  return { analyzed, threats, errors };
}

async function processVulnerabilityApis(db, correlator) {
  log('\n→ Fetching vulnerability APIs (NVD, CISA KEV, GitHub)...', 'blue');

  const [nvdResult, kevResult] = await Promise.all([
    fetchNvdCves(),
    fetchCisaKev(),
  ]);

  let threatsCreated = 0;
  const kevIds = new Set((kevResult.vulnerabilities || []).map(v => v.cveID));

  // NVD CVEs
  if (nvdResult.success && nvdResult.cves.length > 0) {
    info(`NVD: ${nvdResult.cves.length} recent CVEs`);
    for (const cve of nvdResult.cves) {
      cve.in_kev = kevIds.has(cve.cve_id);
      const analysis = await analyzeNvdCve(cve, kevIds);
      if (!analysis.success) { err(`NVD analysis failed (${cve.cve_id}): ${analysis.error}`); continue; }
      const threat = normalizeCveThreat(analysis.data, cve, analysis.source_url);
      const saved = await saveThreat(db, threat);
      if (saved) {
        correlator.correlate(threat.id);
        threatsCreated++;
        ok(`NVD: ${cve.cve_id} (CVSS ${cve.cvss_score || 'N/A'})`);
      }
      await new Promise(r => setTimeout(r, 200));
    }
  } else if (nvdResult.success) {
    info('NVD: 0 new CVEs in the last hour');
  } else {
    warn(`NVD fetch failed: ${nvdResult.error}`);
  }

  // CISA KEV
  if (kevResult.success && kevResult.vulnerabilities.length > 0) {
    info(`CISA KEV: ${kevResult.vulnerabilities.length} entries added in last 7 days`);
    for (const vuln of kevResult.vulnerabilities) {
      const existing = db.prepare('SELECT id FROM threat_cves WHERE cve_id = ?').get(vuln.cveID);
      if (existing) {
        db.prepare('UPDATE threat_cves SET in_kev = 1, exploited_in_wild = 1 WHERE cve_id = ?').run(vuln.cveID);
        continue;
      }
      const analysis = await analyzeCisaKevEntry(vuln);
      if (!analysis.success) { err(`KEV analysis failed (${vuln.cveID}): ${analysis.error}`); continue; }
      const cve = {
        cve_id:           vuln.cveID,
        cvss_score:       null,
        cvss_vector:      null,
        cvss_severity:    null,
        description:      vuln.shortDescription,
        published_date:   vuln.dateAdded,
        in_kev:           true,
        exploited_in_wild:true,
      };
      // Use CVE-specific URL so each KEV entry has a unique source_url
      const kevSourceUrl = `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`;
      const threat = normalizeCveThreat(analysis.data, cve, kevSourceUrl);
      threat.credibility_score = 95;
      const saved = await saveThreat(db, threat);
      if (saved) {
        correlator.correlate(threat.id);
        threatsCreated++;
        ok(`KEV: ${vuln.cveID} — ${vuln.vulnerabilityName}`);
      }
      await new Promise(r => setTimeout(r, 200));
    }
  } else if (kevResult.success) {
    info('CISA KEV: no new entries this week');
  }

  return threatsCreated;
}

async function run() {
  const runId = uuidv4().slice(0, 8);
  const db = getDb(join(ROOT, 'data/threats.db'));
  migrate(db);

  const settings = loadSettings();

  const backend = process.env.OLLAMA_MODEL
    ? `Ollama (${process.env.OLLAMA_MODEL})`
    : process.env.ANTHROPIC_API_KEY
      ? 'Anthropic Claude'
      : null;

  log(`\n${'═'.repeat(60)}`, 'blue');
  log(`  SENTINEL — RUN ${runId}`, 'bold');
  log(`  ${new Date().toUTCString()}`, 'cyan');
  log(`  Backend: ${backend || 'NOT CONFIGURED'}`, backend ? 'cyan' : 'red');
  log(`${'═'.repeat(60)}\n`, 'blue');

  if (!backend) {
    err('No AI backend configured. Add to .env:');
    err('  OLLAMA_MODEL=qwen2.5:7b   (free, local — recommended)');
    err('  ANTHROPIC_API_KEY=sk-ant-... (Anthropic API)');
    db.close();
    return;
  }

  const dedup = new Deduplicator(db);
  const correlator = new Correlator(db);

  let totalArticles = 0, totalThreats = 0, totalErrors = 0;

  try {
    // 1. Vulnerability APIs (NVD + CISA KEV)
    const vulnThreats = await processVulnerabilityApis(db, correlator);
    totalThreats += vulnThreats;

    // 2. RSS feeds
    const { rssResults } = await runAllFeeds(db, info);
    const allItems = rssResults.flatMap(r =>
      (r.items || []).map(item => ({
        ...item,
        source_tier:        r.feed?.tier,
        source_credibility: r.feed?.source_credibility,
      }))
    );
    totalArticles = allItems.length;

    const { analyzed, threats, errors } = await processArticles(db, allItems, dedup, correlator, settings);
    totalThreats += threats;
    totalErrors  += errors;

    log(`\n${'─'.repeat(60)}`, 'blue');
    log(`  Run ${runId} complete`, 'green');
    log(`  RSS articles fetched:  ${totalArticles}`, 'white');
    log(`  Articles analyzed:     ${analyzed}`, analyzed > 0 ? 'green' : 'white');
    log(`  Threats saved:         ${totalThreats}`, totalThreats > 0 ? 'green' : 'white');
    if (totalErrors > 0) log(`  Errors:                ${totalErrors}`, 'yellow');
    log(`${'─'.repeat(60)}\n`, 'blue');

    // Notify portal so browsers auto-refresh
    await notifyPortalDone(totalThreats, totalErrors);

  } catch (e) {
    err(`Fatal pipeline error: ${e.message}`);
    console.error(e);
  } finally {
    db.close();
  }
}

run();
