#!/usr/bin/env node
/**
 * Main ingestion pipeline runner.
 * Fetches ALL feeds and vulnerability APIs every run — no slot rotation.
 * Streams results to the portal via SSE as each threat is analyzed.
 */

import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, readFileSync } from 'fs';

// Load .env manually
const __envDir = dirname(fileURLToPath(import.meta.url));
const envPath = join(__envDir, '..', '.env');
if (existsSync(envPath)) {
  readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const [k, ...v] = line.split('=');
    if (k?.trim() && !process.env[k.trim()]) process.env[k.trim()] = v.join('=').trim();
  });
}

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
    insert.run(threatRecord);
    (_cves   || []).forEach(c => { try { insertCve.run(c);   } catch {} });
    (_iocs   || []).forEach(i => { try { insertIoc.run(i);   } catch {} });
    (_ttps   || []).forEach(t => { try { insertTtp.run(t);   } catch {} });
    (_actors || []).forEach(a => { try { insertActor.run(a); } catch {} });
  });

  saveAll();
}

async function processArticles(db, items, dedup, correlator, settings) {
  const maxAnalyze = settings.claude.max_articles_per_run;
  const newItems = dedup.filterNewItems(items);
  let analyzed = 0, threats = 0, errors = 0;

  info(`${newItems.length} new articles of ${items.length} total`);

  for (const item of newItems) {
    if (analyzed >= maxAnalyze) {
      warn(`Reached max analysis limit (${maxAnalyze}). Remaining queued for next run.`);
      break;
    }

    try {
      const scraped = await scrapeArticle(item.url);
      if (!scraped.success) { dedup.markSkipped(item.url, scraped.error); continue; }
      if (scraped.content_length < 500) { dedup.markSkipped(item.url, 'content_too_short'); continue; }

      dedup.registerArticle(item.url, item.feed_id, item.title, item.published_at, scraped.content_hash);

      if (!dedup.isNewContent(scraped.content_hash)) {
        dedup.markSkipped(item.url, 'duplicate_content');
        continue;
      }

      const articleForAnalysis = {
        url: item.url,
        title: item.title || scraped.title,
        content: scraped.content,
        published_at: item.published_at || scraped.published_at,
        content_hash: scraped.content_hash,
        content_length: scraped.content_length,
        source_name: item.feed_name,
        cve_mentions: scraped.cve_mentions,
        ip_mentions: scraped.ip_mentions,
        hash_mentions: scraped.hash_mentions,
      };

      const analysis = await analyzeArticle(articleForAnalysis, item.source_credibility || 70);
      analyzed++;

      if (!analysis.success) {
        err(`Analysis failed for ${item.url}: ${analysis.error}`);
        errors++;
        continue;
      }

      const threat = normalizeArticleThreat(analysis.data, articleForAnalysis, {
        name: item.feed_name,
        source_tier: item.source_tier,
        source_credibility: item.source_credibility,
        rotation_slot: 'ALL',
      });

      await saveThreat(db, threat);
      dedup.markAnalyzed(item.url, threat.id);
      correlator.correlate(threat.id);
      correlator.updateIocIndex(threat._iocs || [], threat.id);

      threats++;
      ok(`[${threat.severity?.toUpperCase()}] ${threat.title.slice(0, 80)}`);

      await new Promise(r => setTimeout(r, 500));

    } catch (e) {
      err(`Error processing ${item.url}: ${e.message}`);
      errors++;
    }
  }

  return { analyzed, threats, errors };
}

async function processVulnerabilityApis(db, correlator) {
  log('\n→ Fetching vulnerability APIs (NVD, CISA KEV, GitHub)...', 'blue');

  const [nvdResult, kevResult, ghResult] = await Promise.all([
    fetchNvdCves(),
    fetchCisaKev(),
    fetchGithubAdvisories(),
  ]);

  let threatsCreated = 0;
  const kevIds = new Set((kevResult.vulnerabilities || []).map(v => v.cveID));

  if (nvdResult.success) {
    info(`NVD: ${nvdResult.cves.length} new CVEs`);
    for (const cve of nvdResult.cves) {
      cve.in_kev = kevIds.has(cve.cve_id);
      const analysis = await analyzeNvdCve(cve, kevIds);
      if (!analysis.success) { err(`NVD analysis failed (${cve.cve_id}): ${analysis.error}`); continue; }
      const threat = normalizeCveThreat(analysis.data, cve, analysis.source_url);
      await saveThreat(db, threat);
      correlator.correlate(threat.id);
      threatsCreated++;
      ok(`NVD: ${cve.cve_id} (CVSS ${cve.cvss_score || 'N/A'})`);
      await new Promise(r => setTimeout(r, 300));
    }
  }

  if (kevResult.success && kevResult.vulnerabilities.length > 0) {
    info(`CISA KEV: ${kevResult.vulnerabilities.length} new entries`);
    for (const vuln of kevResult.vulnerabilities) {
      const existing = db.prepare('SELECT id FROM threat_cves WHERE cve_id = ?').get(vuln.cveID);
      if (existing) {
        db.prepare('UPDATE threat_cves SET in_kev = 1, exploited_in_wild = 1 WHERE cve_id = ?').run(vuln.cveID);
        continue;
      }
      const analysis = await analyzeCisaKevEntry(vuln);
      if (!analysis.success) { err(`KEV analysis failed (${vuln.cveID}): ${analysis.error}`); continue; }
      const cve = {
        cve_id: vuln.cveID, cvss_score: null, cvss_vector: null,
        cvss_severity: null, description: vuln.shortDescription,
        published_date: vuln.dateAdded, in_kev: true, exploited_in_wild: true,
      };
      const threat = normalizeCveThreat(analysis.data, cve, analysis.source_url);
      threat.credibility_score = 95;
      await saveThreat(db, threat);
      correlator.correlate(threat.id);
      threatsCreated++;
      ok(`KEV: ${vuln.cveID} — ${vuln.vulnerabilityName}`);
      await new Promise(r => setTimeout(r, 300));
    }
  }

  return threatsCreated;
}

async function run() {
  const runId = uuidv4().slice(0, 8);
  const db = getDb(join(ROOT, 'data/threats.db'));
  migrate(db);

  const settings = loadSettings();

  log(`\n${'═'.repeat(60)}`, 'blue');
  log(`  CLAUDE THREAT INTELLIGENCE — RUN ${runId}`, 'bold');
  log(`  Time: ${new Date().toUTCString()}`, 'cyan');
  log(`${'═'.repeat(60)}\n`, 'blue');

  if (!process.env.ANTHROPIC_API_KEY) {
    err('ANTHROPIC_API_KEY is not set in .env — Claude analysis will fail for all articles.');
    err('Add your key to .env: ANTHROPIC_API_KEY=sk-ant-...');
    db.close(); return;
  }

  const dedup = new Deduplicator(db);
  const correlator = new Correlator(db);

  let totalArticles = 0, totalThreats = 0;

  try {
    // Always fetch vulnerability APIs
    const vuln = await processVulnerabilityApis(db, correlator);
    totalThreats += vuln;

    // Always fetch all RSS feeds
    const { rssResults } = await runAllFeeds(db, info);
    const allItems = rssResults.flatMap(r =>
      r.items.map(item => ({
        ...item,
        source_tier: r.feed?.tier,
        source_credibility: r.feed?.source_credibility,
      }))
    );
    totalArticles = allItems.length;

    const { analyzed, threats, errors } = await processArticles(db, allItems, dedup, correlator, settings);
    totalThreats += threats;

    log(`\n${'─'.repeat(60)}`, 'blue');
    log(`  Run ${runId} complete`, 'green');
    log(`  Articles fetched:  ${totalArticles}`, 'white');
    log(`  Articles analyzed: ${analyzed}`, 'white');
    log(`  Threats created:   ${totalThreats}`, 'white');
    if (errors > 0) log(`  Errors: ${errors}`, 'yellow');
    log(`${'─'.repeat(60)}\n`, 'blue');

  } catch (e) {
    err(`Fatal pipeline error: ${e.message}`);
    console.error(e);
  } finally {
    db.close();
  }
}

run();
