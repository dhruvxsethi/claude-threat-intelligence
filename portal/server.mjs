import express from 'express';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, readFileSync } from 'fs';
import { getDb, migrate } from '../scripts/migrate.mjs';
import { loadSettings, loadFeedsConfig } from '../ingestion/feed-fetcher.mjs';
import cron from 'node-cron';
import { spawn } from 'child_process';

// Load .env
const __envRoot = dirname(fileURLToPath(import.meta.url));
const _envPath = join(__envRoot, '..', '.env');
if (existsSync(_envPath)) {
  readFileSync(_envPath, 'utf8').split('\n').forEach(line => {
    const [k, ...v] = line.split('=');
    if (k?.trim() && !process.env[k.trim()]) process.env[k.trim()] = v.join('=').trim();
  });
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const settings = loadSettings();
const PORT = process.env.PORT || settings.platform.port || 3000;
const DB_PATH = join(ROOT, settings.database.path);

let db;

const COMMODITY_SOURCES = new Set([
  'NIST NVD',
  'GitHub Security Advisories',
  'CISA Known Exploited Vulnerabilities',
]);

function sourceGroupForName(name = '') {
  const s = String(name || '').toLowerCase();
  if (!s) return { key: 'unknown', label: 'Unknown' };
  if (s.includes('nvd') || s.includes('cisa') || s.includes('github security')) {
    return { key: 'commodity', label: 'NVD/CISA/GitHub' };
  }
  if (s.includes('bleeping') || s.includes('hacker news') || s.includes('securityweek') || s.includes('dark reading') || s.includes('cyberscoop')) {
    return { key: 'mainstream_news', label: 'Mainstream Security News' };
  }
  if (s.includes('talos') || s.includes('mandiant') || s.includes('unit 42') || s.includes('microsoft') || s.includes('google') || s.includes('crowdstrike') || s.includes('kaspersky') || s.includes('checkpoint') || s.includes('proofpoint') || s.includes('sentinelone') || s.includes('recorded future') || s.includes('rapid7') || s.includes('red canary') || s.includes('elastic') || s.includes('huntress') || s.includes('greynoise')) {
    return { key: 'vendor_intel', label: 'Major Vendor Intel' };
  }
  if (s.includes('cert-eu') || s.includes('cert eu') || s.includes('ncsc')) {
    return { key: 'official_advisory', label: 'Official Advisory Sources' };
  }
  if (s.includes('bankinfo') || s.includes('govinfo') || s.includes('healthcare') || s.includes('hipaa') || s.includes('finextra')) {
    return { key: 'sector_sources', label: 'Sector Sources' };
  }
  return { key: 'other_sources', label: 'Other Monitored Sources' };
}

function isCommoditySource(name) {
  return sourceGroupForName(name).key === 'commodity';
}

function ensureDb() {
  if (!db || !db.open) {
    db = getDb(DB_PATH);
    migrate(db);
  }
  return db;
}

// SSE clients for real-time push
const sseClients = new Set();

function broadcastSse(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(client => {
    try { client.write(msg); } catch {}
  });
}

function spawnPipeline(reason = 'manual') {
  if (_pipelineRunning) return { started: false, status: 'already_running' };
  _pipelineRunning = true;
  broadcastSse('pipeline_started', { runId: Date.now(), reason });

  const child = spawn('node', ['scripts/run-pipeline.mjs'], {
    cwd: ROOT,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdoutBuf = '';
  child.stdout.on('data', d => { stdoutBuf += d.toString(); process.stdout.write(d); });
  child.stderr.on('data', d => process.stderr.write(d));
  child.on('close', (code) => {
    _pipelineRunning = false;
    const m = stdoutBuf.match(/Threats saved:\s+(\d+)/);
    const threats_created = m ? parseInt(m[1]) : 0;
    broadcastSse('pipeline_done', { threats_created, code, reason });
  });

  return { started: true, status: 'started' };
}

const app = express();
app.use(express.json());
app.use(express.static(join(__dirname, 'public')));

// ─── SSE endpoint ──────────────────────────────────────────────────────────

app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();

  sseClients.add(res);
  res.write(`event: connected\ndata: {"status":"ok"}\n\n`);

  req.on('close', () => sseClients.delete(res));
});

// ─── Threats API ───────────────────────────────────────────────────────────

app.get('/api/threats', (req, res) => {
  const db = ensureDb();
  const {
    page = 1, limit = 25, severity, sector, threat_type,
    days = 7, search, sort = 'ingested_at', order = 'desc',
    has_cves, has_iocs, source_kind, min_credibility,
  } = req.query;

  const offset = (parseInt(page) - 1) * parseInt(limit);
  const cutoff = new Date(Date.now() - parseInt(days) * 86400000).toISOString();

  let where = ['t.ingested_at >= ?'];
  const params = [cutoff];

  if (severity) { where.push('t.severity = ?'); params.push(severity); }
  if (threat_type) { where.push('t.threat_type = ?'); params.push(threat_type); }
  if (sector) { where.push(`json_extract(t.sectors, '$') LIKE ?`); params.push(`%${sector}%`); }
  if (search) {
    where.push('(t.title LIKE ? OR t.summary LIKE ? OR t.source_name LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  if (has_cves === 'true') {
    where.push('EXISTS (SELECT 1 FROM threat_cves WHERE threat_id = t.id)');
  }
  if (has_iocs === 'true') {
    where.push('EXISTS (SELECT 1 FROM threat_iocs WHERE threat_id = t.id)');
  }
  const articleSourceSql = `COALESCE(t.source_name, '') NOT IN (
    'NIST NVD',
    'GitHub Security Advisories',
    'CISA Known Exploited Vulnerabilities'
  )`;
  const notSeenElsewhereSql = `NOT EXISTS (SELECT 1 FROM external_sightings es WHERE es.threat_id = t.id)
    AND NOT EXISTS (
      SELECT 1
      FROM threat_cves c
      JOIN threat_cves c2 ON upper(c2.cve_id) = upper(c.cve_id)
      JOIN threats tx ON tx.id = c2.threat_id
      WHERE c.threat_id = t.id AND tx.id != t.id AND COALESCE(tx.source_name, '') != COALESCE(t.source_name, '')
    )
    AND NOT EXISTS (
      SELECT 1
      FROM threat_iocs i
      JOIN threat_iocs i2 ON i2.ioc_type = i.ioc_type AND lower(i2.ioc_value) = lower(i.ioc_value)
      JOIN threats tx ON tx.id = i2.threat_id
      WHERE i.threat_id = t.id AND tx.id != t.id AND COALESCE(tx.source_name, '') != COALESCE(t.source_name, '')
    )`;
  const actorCampaignSql = `(
    t.threat_type IN ('apt','espionage','malware','ransomware','phishing')
    OR t.title LIKE '%APT%'
    OR t.summary LIKE '%state-sponsored%'
    OR t.summary LIKE '%nation-state%'
    OR t.summary LIKE '%espionage%'
  )`;

  if (source_kind === 'articles') {
    where.push(`COALESCE(t.source_name, '') NOT IN (
      'NIST NVD',
      'GitHub Security Advisories',
      'CISA Known Exploited Vulnerabilities'
    )`);
  }
  if (source_kind === 'unique') {
    where.push(articleSourceSql);
    where.push(notSeenElsewhereSql);
  }
  if (source_kind === 'ioc_rich') {
    where.push('EXISTS (SELECT 1 FROM threat_iocs WHERE threat_id = t.id)');
  }
  if (source_kind === 'ioc_rich_unique') {
    where.push(articleSourceSql);
    where.push(notSeenElsewhereSql);
    where.push('EXISTS (SELECT 1 FROM threat_iocs WHERE threat_id = t.id)');
  }
  if (source_kind === 'actor_campaign') {
    where.push(actorCampaignSql);
  }
  if (source_kind === 'actor_campaign_unique') {
    where.push(articleSourceSql);
    where.push(notSeenElsewhereSql);
    where.push(actorCampaignSql);
  }
  if (min_credibility) { where.push('t.credibility_score >= ?'); params.push(parseInt(min_credibility)); }

  const validSorts = ['ingested_at', 'published_at', 'severity', 'credibility_score', 'threat_type'];
  const sortCol = validSorts.includes(sort) ? sort : 'ingested_at';
  const sortOrder = order === 'asc' ? 'ASC' : 'DESC';

  const whereClause = `WHERE ${where.join(' AND ')}`;
  const total = db.prepare(`SELECT COUNT(*) as cnt FROM threats t ${whereClause}`).get(...params).cnt;

  const rows = db.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM threat_cves WHERE threat_id = t.id) as cve_count,
      (SELECT COUNT(*) FROM threat_iocs WHERE threat_id = t.id) as ioc_count,
      (SELECT COUNT(*) FROM threat_ttps WHERE threat_id = t.id) as ttp_count,
      (SELECT COUNT(*) FROM threat_actors WHERE threat_id = t.id) as actor_count
    FROM threats t
    ${whereClause}
    ORDER BY t.${sortCol} ${sortOrder}
    LIMIT ? OFFSET ?
  `).all(...params, parseInt(limit), offset);

  res.json({
    total,
    page: parseInt(page),
    pages: Math.ceil(total / parseInt(limit)),
    threats: rows.map(parseThreat),
  });
});

app.get('/api/threats/:id', (req, res) => {
  const db = ensureDb();
  const threat = db.prepare('SELECT * FROM threats WHERE id = ?').get(req.params.id);
  if (!threat) return res.status(404).json({ error: 'Not found' });

  const cves = db.prepare('SELECT * FROM threat_cves WHERE threat_id = ?').all(req.params.id);
  const iocs = db.prepare('SELECT * FROM threat_iocs WHERE threat_id = ? ORDER BY confidence DESC').all(req.params.id);
  const ttps = db.prepare('SELECT * FROM threat_ttps WHERE threat_id = ?').all(req.params.id);
  const actors = db.prepare('SELECT * FROM threat_actors WHERE threat_id = ?').all(req.params.id);
  let evidence = db.prepare('SELECT * FROM threat_evidence WHERE threat_id = ? ORDER BY observed_at DESC, id DESC').all(req.params.id);
  const externalSightings = db.prepare('SELECT * FROM external_sightings WHERE threat_id = ? ORDER BY first_seen_at ASC').all(req.params.id);

  const relatedIds = JSON.parse(threat.related_threat_ids || '[]');
  const related = relatedIds.length > 0
    ? db.prepare(`SELECT id, title, severity, threat_type, ingested_at, credibility_score FROM threats WHERE id IN (${relatedIds.map(() => '?').join(',')})`).all(...relatedIds)
    : [];

  const parsed = parseThreat(threat);
  if (!evidence.length) evidence = fallbackEvidence(parsed);
  const parsedActors = actors.map(a => ({ ...a, aliases: JSON.parse(a.aliases || '[]') }));
  const displayActors = parsedActors.length ? parsedActors : deriveActorsFromThreat(parsed);

  res.json({
    ...parsed,
    cves: cves.map(c => ({ ...c, affected_products: JSON.parse(c.affected_products || '[]') })),
    iocs,
    ttps,
    actors: displayActors,
    evidence: evidence.map(e => ({ ...e, metadata: JSON.parse(e.metadata || '{}') })),
    external_sightings: externalSightings.map(s => ({ ...s, metadata: JSON.parse(s.metadata || '{}') })),
    related,
  });
});

// ─── Stats API ─────────────────────────────────────────────────────────────

app.get('/api/stats', (req, res) => {
  const db = ensureDb();
  const { days = 7 } = req.query;
  const cutoff = new Date(Date.now() - parseInt(days) * 86400000).toISOString();
  const today = new Date(Date.now() - 86400000).toISOString();

  const total = db.prepare('SELECT COUNT(*) as cnt FROM threats WHERE ingested_at >= ?').get(cutoff).cnt;
  const today_count = db.prepare('SELECT COUNT(*) as cnt FROM threats WHERE ingested_at >= ?').get(today).cnt;

  const by_severity = db.prepare(`
    SELECT severity, COUNT(*) as cnt FROM threats WHERE ingested_at >= ? GROUP BY severity
  `).all(cutoff);

  const by_type = db.prepare(`
    SELECT threat_type, COUNT(*) as cnt FROM threats WHERE ingested_at >= ?
    GROUP BY threat_type ORDER BY cnt DESC LIMIT 10
  `).all(cutoff);

  const by_source = db.prepare(`
    SELECT source_name, COUNT(*) as cnt FROM threats WHERE ingested_at >= ?
    GROUP BY source_name ORDER BY cnt DESC LIMIT 10
  `).all(cutoff);

  const by_day = db.prepare(`
    SELECT date(ingested_at) as day, COUNT(*) as cnt
    FROM threats WHERE ingested_at >= ?
    GROUP BY day ORDER BY day ASC
  `).all(cutoff);

  // Sector stats
  const sector_stats = ['banking', 'government', 'healthcare'].map(sector => {
    const count = db.prepare(`
      SELECT COUNT(*) as cnt FROM threats WHERE ingested_at >= ? AND sectors LIKE ?
    `).get(cutoff, `%${sector}%`).cnt;
    return { sector, count };
  });

  // CVE stats
  const cve_count = db.prepare(`
    SELECT COUNT(DISTINCT cve_id) as cnt FROM threat_cves c
    JOIN threats t ON c.threat_id = t.id WHERE t.ingested_at >= ?
  `).get(cutoff).cnt;

  const critical_cves = db.prepare(`
    SELECT c.cve_id, c.cvss_score, t.title, t.id as threat_id FROM threat_cves c
    JOIN threats t ON c.threat_id = t.id
    WHERE t.ingested_at >= ? AND c.cvss_score >= 9.0
    ORDER BY c.cvss_score DESC LIMIT 5
  `).all(cutoff);

  const kev_count = db.prepare(`
    SELECT COUNT(*) as cnt FROM threat_cves WHERE in_kev = 1
  `).get().cnt;

  const ioc_count = db.prepare(`
    SELECT COUNT(*) as cnt FROM threat_iocs ti
    JOIN threats t ON ti.threat_id = t.id WHERE t.ingested_at >= ?
  `).get(cutoff).cnt;

  // Top threat actors
  let top_actors = db.prepare(`
    SELECT ta.name, COUNT(*) as cnt FROM threat_actors ta
    JOIN threats t ON ta.threat_id = t.id
    WHERE t.ingested_at >= ? AND ta.name != '' AND ta.name IS NOT NULL
    GROUP BY ta.name ORDER BY cnt DESC LIMIT 10
  `).all(cutoff);

  if (!top_actors.length) {
    const threatRows = db.prepare(`
      SELECT id, title, summary, severity, source_name, ingested_at, published_at,
             sectors, geography, threat_type, malware_families
      FROM threats WHERE ingested_at >= ?
      ORDER BY
        CASE
          WHEN source_name IN ('NIST NVD','GitHub Security Advisories','CISA Known Exploited Vulnerabilities') THEN 1
          ELSE 0
        END,
        ingested_at DESC
      LIMIT 1000
    `).all(cutoff).map(parseThreat);
    top_actors = aggregateDerivedActors(threatRows)
      .slice(0, 10)
      .map(a => ({ name: a.name, cnt: a.threat_count, derived: true }));
  }

  // Feed health
  const feed_health = db.prepare(`
    SELECT feed_id, feed_name, last_success, consecutive_failures, is_healthy, total_threats_contributed
    FROM feed_health ORDER BY is_healthy DESC, total_threats_contributed DESC
  `).all();

  // Active feeds count
  const feeds_active = db.prepare('SELECT COUNT(*) as cnt FROM feed_health WHERE is_healthy = 1').get().cnt;

  res.json({
    summary: { total, today_count, cve_count, ioc_count, kev_count, feeds_active },
    by_severity,
    by_type,
    by_source,
    by_day,
    sector_stats,
    critical_cves,
    top_actors,
    feed_health,
  });
});

// ─── Unique Finds / External Coverage API ─────────────────────────────────

app.get('/api/unique-finds', (req, res) => {
  const db = ensureDb();
  const { days = 7, limit = 8 } = req.query;
  const cutoff = new Date(Date.now() - parseInt(days) * 86400000).toISOString();

  const articleRows = db.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM threat_cves WHERE threat_id = t.id) as cve_count,
      (SELECT COUNT(*) FROM threat_iocs WHERE threat_id = t.id) as ioc_count,
      (SELECT COUNT(*) FROM threat_ttps WHERE threat_id = t.id) as ttp_count,
      (SELECT COUNT(*) FROM threat_actors WHERE threat_id = t.id) as actor_count
    FROM threats t
    WHERE t.ingested_at >= ?
      AND COALESCE(t.source_name, '') NOT IN (
        'NIST NVD',
        'GitHub Security Advisories',
        'CISA Known Exploited Vulnerabilities'
      )
    ORDER BY t.ingested_at DESC
    LIMIT 500
  `).all(cutoff).map(parseThreat);

  const enriched = articleRows.map(t => {
    const coverage = coverageForThreat(db, t);
    const derivedActors = deriveActorsFromThreat(t);
    return {
      ...t,
      coverage,
      actor_count: t.actor_count || derivedActors.length,
      derived_actors: derivedActors.map(a => a.name),
      unique_candidate: coverage.status === 'unique_candidate',
      ioc_rich: (t.ioc_count || 0) > 0,
      actor_campaign: derivedActors.length > 0 || ['apt','espionage','ransomware','malware','phishing'].includes(t.threat_type),
    };
  });

  const unique = enriched.filter(t => t.unique_candidate);
  const seenElsewhere = enriched.filter(t => !t.unique_candidate);
  const iocRichUnique = unique.filter(t => t.ioc_rich);
  const actorCampaignUnique = unique.filter(t => t.actor_campaign);

  res.json({
    summary: {
      article_sourced: enriched.length,
      unique_candidates: unique.length,
      seen_elsewhere: seenElsewhere.length,
      ioc_rich_unique: iocRichUnique.length,
      actor_campaign_unique: actorCampaignUnique.length,
      external_seen: enriched.filter(t => t.coverage.external_providers.length > 0).length,
      otx_seen: enriched.filter(t => t.coverage.external_providers.includes('otx')).length,
    },
    latest_unique: unique.slice(0, parseInt(limit)).map(compactThreatForCoverage),
    ioc_rich_unique: iocRichUnique.slice(0, parseInt(limit)).map(compactThreatForCoverage),
    actor_campaign_unique: actorCampaignUnique.slice(0, parseInt(limit)).map(compactThreatForCoverage),
    seen_elsewhere: seenElsewhere.slice(0, parseInt(limit)).map(compactThreatForCoverage),
  });
});

app.get('/api/coverage-gap', (req, res) => {
  const db = ensureDb();
  const { days = 7, limit = 100 } = req.query;
  res.json(getCoverageGapData(db, parseInt(days), parseInt(limit)));
});

app.get('/api/reports/demo', (req, res) => {
  const db = ensureDb();
  const { days = 7 } = req.query;
  const data = getCoverageGapData(db, parseInt(days), 200);
  const markdown = buildDemoReport(data, parseInt(days));
  const filename = `radar-demo-gap-report-${new Date().toISOString().slice(0, 10)}.md`;
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(markdown);
});

// ─── IOCs API ─────────────────────────────────────────────────────────────

app.get('/api/iocs', (req, res) => {
  const db = ensureDb();
  const { type, search, days = 7, min_confidence = 50, limit = 100 } = req.query;
  const cutoff = new Date(Date.now() - parseInt(days) * 86400000).toISOString();

  let where = ['t.ingested_at >= ?', 'i.confidence >= ?'];
  const params = [cutoff, parseInt(min_confidence)];

  if (type) { where.push('i.ioc_type = ?'); params.push(type); }
  if (search) { where.push('i.ioc_value LIKE ?'); params.push(`%${search}%`); }

  const rows = db.prepare(`
    SELECT i.*, t.title as threat_title, t.severity, t.id as threat_id, t.source_name
    FROM threat_iocs i
    JOIN threats t ON i.threat_id = t.id
    WHERE ${where.join(' AND ')}
    ORDER BY i.confidence DESC, t.ingested_at DESC
    LIMIT ?
  `).all(...params, parseInt(limit));

  // IOC type counts
  const type_counts = db.prepare(`
    SELECT i.ioc_type, COUNT(*) as cnt FROM threat_iocs i
    JOIN threats t ON i.threat_id = t.id WHERE t.ingested_at >= ?
    GROUP BY i.ioc_type ORDER BY cnt DESC
  `).all(cutoff);

  res.json({ iocs: rows, type_counts });
});

// ─── Feeds API ─────────────────────────────────────────────────────────────

app.get('/api/feeds', (req, res) => {
  const db = ensureDb();
  const health = db.prepare('SELECT * FROM feed_health ORDER BY is_healthy DESC, total_threats_contributed DESC').all();
  const recentRuns = db.prepare(`
    SELECT * FROM feed_runs ORDER BY started_at DESC LIMIT 50
  `).all();
  const discoveredSources = db.prepare(`
    SELECT * FROM discovered_sources
    ORDER BY
      CASE status WHEN 'new' THEN 0 WHEN 'reviewed' THEN 1 WHEN 'added' THEN 2 ELSE 3 END,
      confidence DESC,
      discovered_at DESC
    LIMIT 50
  `).all();
  const articleStats = Object.fromEntries(db.prepare(`
    SELECT
      feed_id,
      COUNT(*) AS articles_seen,
      SUM(CASE WHEN analyzed = 1 THEN 1 ELSE 0 END) AS articles_processed,
      SUM(CASE WHEN threat_id IS NOT NULL THEN 1 ELSE 0 END) AS threats_linked,
      SUM(CASE WHEN skip_reason IS NOT NULL THEN 1 ELSE 0 END) AS articles_skipped,
      SUM(CASE WHEN skip_reason = 'duplicate_content' THEN 1 ELSE 0 END) AS duplicate_content,
      SUM(CASE WHEN skip_reason = 'stale_article' THEN 1 ELSE 0 END) AS stale_articles
    FROM articles
    GROUP BY feed_id
  `).all().map(r => [r.feed_id, r]));
  const threatStatsBySource = Object.fromEntries(db.prepare(`
    SELECT
      t.source_name,
      COUNT(*) AS threats_saved,
      SUM(CASE WHEN EXISTS (SELECT 1 FROM threat_cves c WHERE c.threat_id = t.id) THEN 1 ELSE 0 END) AS cve_threats,
      SUM(CASE WHEN EXISTS (SELECT 1 FROM threat_iocs i WHERE i.threat_id = t.id) THEN 1 ELSE 0 END) AS ioc_threats,
      SUM((SELECT COUNT(*) FROM threat_iocs i WHERE i.threat_id = t.id)) AS ioc_findings,
      SUM(CASE WHEN EXISTS (
        SELECT 1 FROM threat_actors a
        WHERE a.threat_id = t.id AND a.name IS NOT NULL AND a.name != ''
      ) THEN 1 ELSE 0 END) AS actor_threats
    FROM threats t
    GROUP BY t.source_name
  `).all().map(r => [r.source_name, r]));
  const kevThreats = db.prepare(`
    SELECT COUNT(DISTINCT threat_id) AS cnt
    FROM threat_cves
    WHERE in_kev = 1
  `).get().cnt;

  // Annotate health entries with enabled status from feeds config
  let feedsById = {};
  try {
    const cfg = loadFeedsConfig();
    (cfg.feeds || []).forEach(f => { feedsById[f.id] = f; });
  } catch {}
  const addMetrics = h => {
    const cfg = feedsById[h.feed_id];
    const stats = articleStats[h.feed_id] || {};
    let sourceStats = threatStatsBySource[cfg?.name] || threatStatsBySource[h.feed_name] || {};
    let computedThreats = stats.threats_linked || 0;

    if (h.feed_id === 'nvd_cve_api') sourceStats = threatStatsBySource['NIST NVD'] || sourceStats;
    if (h.feed_id === 'github_security_advisories') sourceStats = threatStatsBySource['GitHub Security Advisories'] || sourceStats;
    if (h.feed_id === 'cisa_kev_api') sourceStats = threatStatsBySource['CISA Known Exploited Vulnerabilities'] || sourceStats;
    computedThreats = sourceStats.threats_saved || computedThreats;
    if (h.feed_id === 'cisa_kev_api') computedThreats = kevThreats || computedThreats;

    const seen = stats.articles_seen || 0;
    const processed = stats.articles_processed || 0;
    const cveThreats = sourceStats.cve_threats || 0;
    const iocThreats = sourceStats.ioc_threats || 0;
    const actorThreats = sourceStats.actor_threats || 0;
    const saveRate = seen > 0 ? computedThreats / seen : (computedThreats > 0 ? 1 : 0);
    const technicalYield = computedThreats > 0 ? (cveThreats + iocThreats + actorThreats) / (computedThreats * 3) : 0;
    const qualityScore = Math.round(Math.min(100, (
      (h.is_healthy === 1 ? 25 : h.never_run ? 0 : 8) +
      Math.min(35, saveRate * 100) +
      Math.min(40, technicalYield * 80)
    )));

    return {
      ...h,
      enabled: cfg ? (cfg.enabled !== false) : true,
      tier: cfg?.tier || null,
      articles_seen: stats.articles_seen || 0,
      articles_processed: stats.articles_processed || 0,
      articles_skipped: stats.articles_skipped || 0,
      duplicate_content: stats.duplicate_content || 0,
      stale_articles: stats.stale_articles || 0,
      computed_threats: computedThreats,
      total_threats_contributed: computedThreats,
      raw_threat_counter: h.total_threats_contributed || 0,
      cve_threats: cveThreats,
      ioc_threats: iocThreats,
      ioc_findings: sourceStats.ioc_findings || 0,
      actor_threats: actorThreats,
      save_rate: saveRate,
      quality_score: qualityScore,
      source_group: sourceGroupForName(cfg?.name || h.feed_name || h.feed_id).label,
    };
  };
  const annotated = health.map(addMetrics);

  // Include configured feeds that have never run yet
  const seenIds = new Set(health.map(h => h.feed_id));
  let feedsConfig = [];
  try {
    const cfg = loadFeedsConfig();
    feedsConfig = (cfg.feeds || []).filter(f => !seenIds.has(f.id)).map(f => addMetrics({
      feed_id: f.id,
      feed_name: f.name,
      is_healthy: f.enabled !== false ? null : 0,
      total_threats_contributed: 0,
      consecutive_failures: 0,
      last_success: null,
      never_run: true,
    }));
  } catch {}

  const fullHealth = [...annotated, ...feedsConfig];
  const feedQuality = fullHealth
    .filter(f => f.enabled !== false)
    .sort((a, b) => (b.quality_score || 0) - (a.quality_score || 0) || (b.computed_threats || 0) - (a.computed_threats || 0))
    .slice(0, 12);

  res.json({ health: fullHealth, feedQuality, recentRuns, discoveredSources });
});

// ─── Trigger pipeline run manually ────────────────────────────────────────

let _pipelineRunning = false;
let _discoveryRunning = false;
let _otxRunning = false;
let _externalRunning = false;

app.post('/api/pipeline/run', (req, res) => {
  res.json(spawnPipeline('manual'));
});

// Called by the pipeline script at the end of each run to trigger browser refresh
app.post('/api/pipeline/done', (req, res) => {
  const { threats_created = 0, errors = 0 } = req.body || {};
  broadcastSse('pipeline_done', { threats_created, errors });
  res.json({ ok: true });
});

app.post('/api/otx/sync', (req, res) => {
  if (_otxRunning) return res.json({ status: 'already_running' });
  _otxRunning = true;
  broadcastSse('otx_started', { runId: Date.now() });
  res.json({ status: 'started' });

  const child = spawn('node', ['scripts/sync-otx-sightings.mjs'], {
    cwd: ROOT,
    env: {
      ...process.env,
      OTX_LOOKBACK_DAYS: String(settings.integrations?.otx?.lookback_days || process.env.OTX_LOOKBACK_DAYS || 14),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  child.stdout.on('data', d => process.stdout.write(d));
  child.stderr.on('data', d => process.stderr.write(d));
  child.on('close', code => {
    _otxRunning = false;
    broadcastSse('pipeline_done', { otx_synced: true, code });
  });
});

app.post('/api/external/sync', (req, res) => {
  if (_externalRunning) return res.json({ status: 'already_running' });
  _externalRunning = true;
  broadcastSse('external_sync_started', { runId: Date.now() });
  res.json({ status: 'started' });

  const child = spawn('node', ['scripts/sync-external-comparison.mjs'], {
    cwd: ROOT,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  child.stdout.on('data', d => process.stdout.write(d));
  child.stderr.on('data', d => process.stderr.write(d));
  child.on('close', code => {
    _externalRunning = false;
    broadcastSse('pipeline_done', { external_synced: true, code });
  });
});

// ─── Sectors API ──────────────────────────────────────────────────────────

app.get('/api/sectors/:sector', (req, res) => {
  const db = ensureDb();
  const { sector } = req.params;
  const { days = 7 } = req.query;
  const cutoff = new Date(Date.now() - parseInt(days) * 86400000).toISOString();

  const threats = db.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM threat_cves WHERE threat_id = t.id) as cve_count,
      (SELECT COUNT(*) FROM threat_iocs WHERE threat_id = t.id) as ioc_count
    FROM threats t
    WHERE t.ingested_at >= ? AND t.sectors LIKE ?
    ORDER BY t.credibility_score DESC, t.ingested_at DESC
    LIMIT 50
  `).all(cutoff, `%${sector}%`);

  let topActors = db.prepare(`
    SELECT ta.name, ta.origin_country, ta.motivation, COUNT(*) as cnt
    FROM threat_actors ta JOIN threats t ON ta.threat_id = t.id
    WHERE t.ingested_at >= ? AND t.sectors LIKE ?
      AND ta.name != '' AND ta.name IS NOT NULL
    GROUP BY ta.name ORDER BY cnt DESC LIMIT 5
  `).all(cutoff, `%${sector}%`);

  if (!topActors.length) {
    const actorThreatRows = db.prepare(`
      SELECT id, title, summary, severity, source_name, ingested_at, published_at,
             sectors, geography, threat_type, malware_families
      FROM threats
      WHERE ingested_at >= ? AND sectors LIKE ?
      ORDER BY ingested_at DESC LIMIT 1000
    `).all(cutoff, `%${sector}%`).map(parseThreat);

    topActors = aggregateDerivedActors(actorThreatRows)
      .filter(a => (a.sectors || []).includes(sector))
      .slice(0, 5)
      .map(a => ({
        name: a.name,
        origin_country: a.origin_country,
        motivation: a.motivation,
        cnt: a.threat_count,
        derived: true,
      }));
  }

  const topCves = db.prepare(`
    SELECT c.cve_id, c.cvss_score, c.cvss_severity, c.in_kev, t.title, t.id as threat_id
    FROM threat_cves c JOIN threats t ON c.threat_id = t.id
    WHERE t.ingested_at >= ? AND t.sectors LIKE ?
    ORDER BY c.cvss_score DESC NULLS LAST LIMIT 10
  `).all(cutoff, `%${sector}%`);

  res.json({
    sector,
    threats: threats.map(parseThreat),
    topActors,
    topCves,
  });
});

// ─── Threat Actors API ────────────────────────────────────────────────────

app.get('/api/actors', (req, res) => {
  const db = ensureDb();
  const { days = 30, search } = req.query;
  const cutoff = new Date(Date.now() - parseInt(days) * 86400000).toISOString();
  const threatCountInWindow = db.prepare('SELECT COUNT(*) as cnt FROM threats WHERE ingested_at >= ?').get(cutoff).cnt;
  const storedActorRows = db.prepare(`
    SELECT COUNT(*) as cnt
    FROM threat_actors ta JOIN threats t ON ta.threat_id = t.id
    WHERE t.ingested_at >= ? AND ta.name != '' AND ta.name IS NOT NULL
  `).get(cutoff).cnt;

  let where = 't.ingested_at >= ? AND ta.name != \'\' AND ta.name IS NOT NULL';
  const params = [cutoff];
  if (search) {
    where += ' AND (ta.name LIKE ? OR ta.origin_country LIKE ? OR ta.motivation LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  // Grouped actor list with aggregated stats
  const actors = db.prepare(`
    SELECT
      ta.name,
      ta.origin_country,
      ta.motivation,
      ta.sophistication,
      ta.active_since,
      ta.description,
      GROUP_CONCAT(DISTINCT ta.aliases) as aliases_raw,
      COUNT(DISTINCT ta.threat_id) as threat_count,
      MAX(t.ingested_at) as last_seen,
      MIN(t.ingested_at) as first_seen,
      GROUP_CONCAT(DISTINCT t.severity) as severities,
      GROUP_CONCAT(DISTINCT t.sectors) as sectors_raw,
      GROUP_CONCAT(DISTINCT ta.threat_id) as threat_ids_raw
    FROM threat_actors ta
    JOIN threats t ON ta.threat_id = t.id
    WHERE ${where}
    GROUP BY ta.name
    ORDER BY threat_count DESC, last_seen DESC
    LIMIT 100
  `).all(...params);

  // Motivation / sophistication breakdowns (exclude blank-named actors)
  const by_motivation = db.prepare(`
    SELECT ta.motivation, COUNT(DISTINCT ta.name) as cnt
    FROM threat_actors ta JOIN threats t ON ta.threat_id = t.id
    WHERE t.ingested_at >= ? AND ta.name != '' AND ta.name IS NOT NULL
    GROUP BY ta.motivation ORDER BY cnt DESC
  `).all(cutoff);

  const by_sophistication = db.prepare(`
    SELECT ta.sophistication, COUNT(DISTINCT ta.name) as cnt
    FROM threat_actors ta JOIN threats t ON ta.threat_id = t.id
    WHERE t.ingested_at >= ? AND ta.name != '' AND ta.name IS NOT NULL
    GROUP BY ta.sophistication ORDER BY cnt DESC
  `).all(cutoff);

  const by_country = db.prepare(`
    SELECT ta.origin_country, COUNT(DISTINCT ta.name) as cnt
    FROM threat_actors ta JOIN threats t ON ta.threat_id = t.id
    WHERE t.ingested_at >= ? AND ta.name != '' AND ta.name IS NOT NULL
      AND ta.origin_country IS NOT NULL AND ta.origin_country != ''
    GROUP BY ta.origin_country ORDER BY cnt DESC LIMIT 15
  `).all(cutoff);

  // Get recent threats per actor (for detail panel)
  const actorThreats = {};
  for (const actor of actors.slice(0, 20)) {
    const threats = db.prepare(`
      SELECT t.id, t.title, t.severity, t.ingested_at, t.source_name, t.credibility_score
      FROM threat_actors ta JOIN threats t ON ta.threat_id = t.id
      WHERE ta.name = ? AND t.ingested_at >= ?
      ORDER BY t.ingested_at DESC LIMIT 5
    `).all(actor.name, cutoff);
    actorThreats[actor.name] = threats;
  }

  let actorRows = actors.map(a => ({
      ...a,
      aliases: [...new Set((a.aliases_raw || '').split(',').flatMap(s => {
        try { return JSON.parse(s); } catch { return []; }
      }).filter(Boolean))],
      severities: [...new Set((a.severities || '').split(',').filter(Boolean))],
      sectors: [...new Set((a.sectors_raw || '').split(',').flatMap(s => {
        try { return JSON.parse(s); } catch { return []; }
      }).filter(Boolean))],
      threat_ids: (a.threat_ids_raw || '').split(',').filter(Boolean),
      recent_threats: actorThreats[a.name] || [],
    }));

  if (!actorRows.length) {
    const threatRows = db.prepare(`
      SELECT id, title, summary, severity, source_name, ingested_at, published_at,
             sectors, geography, threat_type, malware_families
      FROM threats WHERE ingested_at >= ?
      ORDER BY ingested_at DESC LIMIT 1000
    `).all(cutoff).map(parseThreat);
    actorRows = aggregateDerivedActors(threatRows);
    if (search) {
      const q = String(search).toLowerCase();
      actorRows = actorRows.filter(a =>
        [a.name, a.origin_country, a.motivation, a.sophistication]
          .some(v => String(v || '').toLowerCase().includes(q))
      );
    }
  }

  res.json({
    actors: actorRows,
    diagnostics: {
      threats_in_window: threatCountInWindow,
      stored_actor_rows: storedActorRows,
      derived_actor_rows: actorRows.filter(a => a.derived).length,
    },
    summary: {
      total_actors: actorRows.length,
      by_motivation: by_motivation.length ? by_motivation : summarizeActorField(actorRows, 'motivation'),
      by_sophistication: by_sophistication.length ? by_sophistication : summarizeActorField(actorRows, 'sophistication'),
      by_country: by_country.length ? by_country : summarizeActorCountries(actorRows),
    },
  });
});

// ─── Search API ────────────────────────────────────────────────────────────

app.get('/api/search', (req, res) => {
  const db = ensureDb();
  const { q, days = 30 } = req.query;
  if (!q || q.length < 2) return res.json({ threats: [], iocs: [], cves: [] });

  const cutoff = new Date(Date.now() - parseInt(days) * 86400000).toISOString();
  const term = `%${q}%`;

  const threats = db.prepare(`
    SELECT id, title, severity, threat_type, ingested_at, credibility_score, source_name
    FROM threats WHERE ingested_at >= ? AND (title LIKE ? OR summary LIKE ?)
    ORDER BY credibility_score DESC LIMIT 20
  `).all(cutoff, term, term);

  const cves = db.prepare(`
    SELECT c.cve_id, c.cvss_score, c.cvss_severity, t.id as threat_id, t.title
    FROM threat_cves c JOIN threats t ON c.threat_id = t.id
    WHERE t.ingested_at >= ? AND c.cve_id LIKE ?
    LIMIT 20
  `).all(cutoff, term);

  const iocs = db.prepare(`
    SELECT i.ioc_type, i.ioc_value, i.confidence, t.id as threat_id, t.title
    FROM threat_iocs i JOIN threats t ON i.threat_id = t.id
    WHERE t.ingested_at >= ? AND i.ioc_value LIKE ?
    ORDER BY i.confidence DESC LIMIT 20
  `).all(cutoff, term);

  const actors = db.prepare(`
    SELECT ta.name, ta.origin_country, ta.motivation, COUNT(*) as seen_in, t.ingested_at
    FROM threat_actors ta JOIN threats t ON ta.threat_id = t.id
    WHERE t.ingested_at >= ? AND ta.name LIKE ?
    GROUP BY ta.name ORDER BY seen_in DESC LIMIT 10
  `).all(cutoff, term);

  const derivedActors = actors.length ? [] : aggregateDerivedActors(
    db.prepare(`
      SELECT id, title, summary, severity, source_name, ingested_at, published_at,
             sectors, geography, threat_type, malware_families
      FROM threats WHERE ingested_at >= ? AND (title LIKE ? OR summary LIKE ?)
      ORDER BY ingested_at DESC LIMIT 50
    `).all(cutoff, term, term).map(parseThreat)
  ).filter(a => a.name.toLowerCase().includes(String(q).toLowerCase())).slice(0, 10);

  res.json({ threats, cves, iocs, actors: actors.length ? actors : derivedActors });
});

// ─── Helpers ──────────────────────────────────────────────────────────────

function parseThreat(t) {
  return {
    ...t,
    sectors: JSON.parse(t.sectors || '[]'),
    geography: JSON.parse(t.geography || '[]'),
    malware_families: JSON.parse(t.malware_families || '[]'),
    affected_products: JSON.parse(t.affected_products || '[]'),
    sector_impact: JSON.parse(t.sector_impact || '{}'),
    related_threat_ids: JSON.parse(t.related_threat_ids || '[]'),
  };
}

function fallbackEvidence(threat) {
  return [
    {
      id: null,
      threat_id: threat.id,
      evidence_type: 'source_article',
      title: threat.source_name || 'Source article',
      body: threat.summary || '',
      url: threat.source_url,
      observed_at: threat.published_at || threat.ingested_at,
      metadata: JSON.stringify({
        generated_from_existing_record: true,
        content_length: threat.content_length || 0,
        raw_content_hash: threat.raw_content_hash || null,
      }),
    },
    {
      id: null,
      threat_id: threat.id,
      evidence_type: 'gap_tracking',
      title: 'Gap tracking status',
      body: threat.gap_status === 'seen_elsewhere'
        ? 'This threat has at least one imported external sighting.'
        : 'No matching external/common-source sighting has been imported for this threat yet.',
      url: threat.source_url,
      observed_at: threat.gap_checked_at || threat.ingested_at,
      metadata: JSON.stringify({ status: threat.gap_status || 'not_checked' }),
    },
  ];
}

function compactThreatForCoverage(t) {
  return {
    id: t.id,
    title: t.title,
    severity: t.severity,
    threat_type: t.threat_type,
    source_name: t.source_name,
    published_at: t.published_at,
    ingested_at: t.ingested_at,
    sectors: t.sectors || [],
    cve_count: t.cve_count || 0,
    ioc_count: t.ioc_count || 0,
    actor_count: t.actor_count || 0,
    derived_actors: t.derived_actors || [],
    coverage: t.coverage,
  };
}

function coverageForThreat(db, threat) {
  const ownGroup = sourceGroupForName(threat.source_name);
  const seenGroups = new Map();
  const matchedSources = new Map();
  let matchCount = 0;

  const addSource = (sourceName, reason) => {
    if (!sourceName || sourceName === threat.source_name) return;
    const group = sourceGroupForName(sourceName);
    if (group.key === 'unknown') return;
    seenGroups.set(group.key, group.label);
    if (!matchedSources.has(sourceName)) {
      matchedSources.set(sourceName, { source_name: sourceName, group: group.label, reasons: new Set() });
    }
    matchedSources.get(sourceName).reasons.add(reason);
    matchCount++;
  };

  const cves = db.prepare('SELECT cve_id FROM threat_cves WHERE threat_id = ?').all(threat.id);
  for (const cve of cves) {
    const rows = db.prepare(`
      SELECT DISTINCT t.source_name
      FROM threat_cves c JOIN threats t ON c.threat_id = t.id
      WHERE upper(c.cve_id) = upper(?) AND t.id != ?
    `).all(cve.cve_id, threat.id);
    rows.forEach(r => addSource(r.source_name, cve.cve_id));
  }

  const iocs = db.prepare('SELECT ioc_type, ioc_value FROM threat_iocs WHERE threat_id = ? LIMIT 30').all(threat.id);
  for (const ioc of iocs) {
    const rows = db.prepare(`
      SELECT DISTINCT t.source_name
      FROM threat_iocs i JOIN threats t ON i.threat_id = t.id
      WHERE i.ioc_type = ? AND lower(i.ioc_value) = lower(?) AND t.id != ?
    `).all(ioc.ioc_type, ioc.ioc_value, threat.id);
    rows.forEach(r => addSource(r.source_name, `${ioc.ioc_type}:${ioc.ioc_value}`));
  }

  const sightings = db.prepare(`
    SELECT provider, match_type, match_value, first_seen_at
    FROM external_sightings
    WHERE threat_id = ?
    ORDER BY first_seen_at ASC
  `).all(threat.id);
  const externalProviders = [...new Set(sightings.map(s => s.provider).filter(Boolean))];
  sightings.forEach(s => {
    const label = s.provider === 'otx' ? 'OTX / AlienVault' : s.provider;
    seenGroups.set(`external_${s.provider}`, label);
  });

  const materialCount = cves.length + iocs.length;
  const seenElsewhere = seenGroups.size > 0 || externalProviders.length > 0;
  const status = isCommoditySource(threat.source_name)
    ? 'commodity_database'
    : seenElsewhere
      ? 'seen_elsewhere'
      : 'unique_candidate';
  const exactExternalMatches = sightings.filter(s => ['cve', 'ioc', 'url'].includes(s.match_type)).length;
  const exactLocalMatches = matchCount;
  const checkedProviders = [
    'NVD',
    'CISA KEV',
    'GitHub Advisories',
    'OTX',
    'MalwareBazaar',
    'URLHaus',
    process.env.SHODAN_API_KEY ? 'Shodan' : null,
    process.env.CENSYS_API_ID ? 'Censys' : null,
  ].filter(Boolean);
  let confidenceScore = 35;
  const confidenceReasons = [];
  if (materialCount > 0) {
    confidenceScore += 20;
    confidenceReasons.push('has exact CVE/IOC material');
  } else {
    confidenceReasons.push('source-only comparison');
  }
  if (exactExternalMatches > 0) {
    confidenceScore += 35;
    confidenceReasons.push('matched external source by exact CVE/IOC/URL');
  } else if (exactLocalMatches > 0) {
    confidenceScore += 25;
    confidenceReasons.push('matched monitored source by exact CVE/IOC');
  } else if (status === 'unique_candidate' && materialCount > 0) {
    confidenceScore += 15;
    confidenceReasons.push('no exact match in monitored comparison set');
  }
  if (checkedProviders.length >= 5) confidenceScore += 5;
  confidenceScore = Math.max(0, Math.min(100, confidenceScore));
  const confidenceLevel = confidenceScore >= 80 ? 'high' : confidenceScore >= 55 ? 'medium' : 'low';

  return {
    status,
    own_group: ownGroup.label,
    match_material: { cves: cves.length, iocs: iocs.length, total: materialCount },
    seen_groups: [...seenGroups.values()],
    external_providers: externalProviders,
    matched_sources: [...matchedSources.values()].map(s => ({
      source_name: s.source_name,
      group: s.group,
      reasons: [...s.reasons].slice(0, 5),
    })).slice(0, 8),
    match_count: matchCount + sightings.length,
    confidence: {
      level: confidenceLevel,
      score: confidenceScore,
      reasons: confidenceReasons,
      checked_providers: checkedProviders,
    },
  };
}

function getCoverageGapData(db, days = 7, limit = 100) {
  const cutoff = new Date(Date.now() - days * 86400000).toISOString();
  const rows = db.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM threat_cves WHERE threat_id = t.id) as cve_count,
      (SELECT COUNT(*) FROM threat_iocs WHERE threat_id = t.id) as ioc_count,
      (SELECT COUNT(*) FROM threat_ttps WHERE threat_id = t.id) as ttp_count,
      (SELECT COUNT(*) FROM threat_actors WHERE threat_id = t.id) as actor_count
    FROM threats t
    WHERE t.ingested_at >= ?
      AND COALESCE(t.source_name, '') NOT IN (
        'NIST NVD',
        'GitHub Security Advisories',
        'CISA Known Exploited Vulnerabilities'
      )
    ORDER BY t.ingested_at DESC
    LIMIT ?
  `).all(cutoff, limit).map(parseThreat);

  const threats = rows.map(t => {
    const coverage = coverageForThreat(db, t);
    let evidence = db.prepare(`
      SELECT evidence_type, title, body, url, observed_at, metadata
      FROM threat_evidence
      WHERE threat_id = ?
      ORDER BY observed_at DESC, id DESC
      LIMIT 8
    `).all(t.id);
    if (!evidence.length) evidence = fallbackEvidence(t);
    return {
      ...compactThreatForCoverage({ ...t, coverage }),
      summary: t.summary,
      source_url: t.source_url,
      first_seen_by_us_at: t.first_seen_by_us_at || t.ingested_at,
      external_seen_at: t.external_seen_at,
      gap_status: coverage.status,
      evidence: evidence.map(e => ({ ...e, metadata: JSON.parse(e.metadata || '{}') })),
    };
  });

  const unique = threats.filter(t => t.coverage.status === 'unique_candidate');
  const seenElsewhere = threats.filter(t => t.coverage.status === 'seen_elsewhere');
  const seenByUsFirst = threats.filter(t => t.external_seen_at && t.first_seen_by_us_at && new Date(t.first_seen_by_us_at) < new Date(t.external_seen_at));
  const providers = {};
  for (const t of threats) {
    for (const p of t.coverage.external_providers || []) providers[p] = (providers[p] || 0) + 1;
    for (const g of t.coverage.seen_groups || []) providers[g] = (providers[g] || 0) + 1;
  }

  return {
    generated_at: new Date().toISOString(),
    days,
    summary: {
      article_sourced: threats.length,
      not_seen_elsewhere: unique.length,
      seen_elsewhere: seenElsewhere.length,
      seen_by_us_first: seenByUsFirst.length,
      external_provider_count: Object.keys(providers).length,
    },
    providers: Object.entries(providers)
      .map(([provider, count]) => ({ provider, count }))
      .sort((a, b) => b.count - a.count),
    threats,
  };
}

function buildDemoReport(data, days = 7) {
  const lines = [];
  const unique = data.threats.filter(t => t.coverage.status === 'unique_candidate');
  const seen = data.threats.filter(t => t.coverage.status === 'seen_elsewhere');
  lines.push(`# Radar Coverage Gap Demo Report`);
  lines.push('');
  lines.push(`Generated: ${data.generated_at}`);
  lines.push(`Window: last ${days} day${days === 1 ? '' : 's'}`);
  lines.push('');
  lines.push(`## Executive Summary`);
  lines.push('');
  lines.push(`Radar reviewed ${data.summary.article_sourced} article-sourced threats in this window.`);
  lines.push(`${data.summary.not_seen_elsewhere} are currently not seen in monitored external/common sources based on imported sightings and shared CVE/IOC matches.`);
  lines.push(`${data.summary.seen_elsewhere} were also visible in monitored external/common sources.`);
  lines.push('');
  lines.push(`## External/Common Coverage`);
  lines.push('');
  if (data.providers.length) {
    for (const p of data.providers.slice(0, 12)) lines.push(`- ${p.provider}: ${p.count}`);
  } else {
    lines.push('- No external/common coverage imported yet.');
  }
  lines.push('');
  lines.push(`## Radar Caught These Before Monitored/Common Sources`);
  lines.push('');
  if (!unique.length) {
    lines.push('No not-seen-elsewhere items in this window.');
  } else {
    for (const t of unique.slice(0, 25)) {
      lines.push(`### ${t.title}`);
      lines.push(`- Severity: ${t.severity}`);
      lines.push(`- Source: ${t.source_name}`);
      lines.push(`- Source URL: ${t.source_url || 'n/a'}`);
      lines.push(`- First seen by Radar: ${t.first_seen_by_us_at || t.ingested_at}`);
      lines.push(`- CVEs: ${t.cve_count || 0}; IOCs: ${t.ioc_count || 0}; actors: ${t.actor_count || 0}`);
      lines.push(`- Why it matters: ${(t.summary || '').replace(/\s+/g, ' ').slice(0, 320) || 'Source article contained extractable threat intelligence.'}`);
      lines.push('');
    }
  }
  lines.push(`## Seen Elsewhere`);
  lines.push('');
  if (!seen.length) {
    lines.push('No seen-elsewhere article threats in this window.');
  } else {
    for (const t of seen.slice(0, 25)) {
      const elsewhere = [...(t.coverage.external_providers || []), ...(t.coverage.seen_groups || [])].join(', ') || 'monitored source';
      lines.push(`- ${t.title} — also seen in ${elsewhere}`);
    }
  }
  lines.push('');
  lines.push(`## Method`);
  lines.push('');
  lines.push('Radar compares article-sourced threats against imported external sightings and local records from commodity/common sources using exact CVE and IOC matches. Items without external sightings or shared CVE/IOC matches are treated as not-seen-elsewhere candidates, not as proof that the rest of the internet has no coverage.');
  lines.push('');
  return `${lines.join('\n')}\n`;
}

const NAMED_ACTOR_PATTERNS = [
  { re: /\bAPT ?28\b/i, name: 'APT28', origin_country: 'Russia', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bAPT ?29\b/i, name: 'APT29', origin_country: 'Russia', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bAPT ?41\b/i, name: 'APT41', origin_country: 'China', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bAPT ?42\b/i, name: 'APT42', origin_country: 'Iran', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bLazarus\b/i, name: 'Lazarus Group', origin_country: 'North Korea', motivation: 'financial', sophistication: 'nation_state' },
  { re: /\bKimsuky\b/i, name: 'Kimsuky', origin_country: 'North Korea', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bSandworm\b/i, name: 'Sandworm', origin_country: 'Russia', motivation: 'sabotage', sophistication: 'nation_state' },
  { re: /\bFIN7\b/i, name: 'FIN7', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
  { re: /\bScattered Spider\b/i, name: 'Scattered Spider', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
  { re: /\bLockBit\b/i, name: 'LockBit', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
  { re: /\bCl0?p\b/i, name: 'Clop', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
  { re: /\bBlackCat\b|\bALPHV\b/i, name: 'ALPHV/BlackCat', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
];

const COUNTRY_ACTOR_PATTERNS = [
  { re: /\bChina(?:-linked|-backed|-nexus)?\b|\bChinese state-sponsored\b/i, name: 'China-linked activity', origin_country: 'China' },
  { re: /\bRussia(?:n)?(?:-linked|-backed|-nexus)?\b|\bRussian state-sponsored\b/i, name: 'Russia-linked activity', origin_country: 'Russia' },
  { re: /\bNorth Korea(?:n)?(?:-linked|-backed|-nexus)?\b|\bDPRK(?:-linked|-backed|-nexus)?\b/i, name: 'North Korea-linked activity', origin_country: 'North Korea' },
  { re: /\bIran(?:ian)?(?:-linked|-backed|-nexus)?\b|\bIranian state-sponsored\b/i, name: 'Iran-linked activity', origin_country: 'Iran' },
];

function deriveActorsFromThreat(threat) {
  const text = `${threat.title || ''}\n${threat.summary || ''}`.trim();
  if (!text) return [];

  const actors = [];
  for (const pattern of NAMED_ACTOR_PATTERNS) {
    if (pattern.re.test(text)) {
      actors.push({
        name: pattern.name,
        aliases: [],
        origin_country: pattern.origin_country,
        motivation: pattern.motivation,
        sophistication: pattern.sophistication,
        active_since: null,
        description: `Derived from explicit source text in "${threat.title}".`,
        derived: true,
      });
    }
  }

  if (actors.length === 0 && /state-sponsored|nation-state|apt|espionage/i.test(text)) {
    for (const pattern of COUNTRY_ACTOR_PATTERNS) {
      if (pattern.re.test(text)) {
        actors.push({
          name: pattern.name,
          aliases: [],
          origin_country: pattern.origin_country,
          motivation: 'espionage',
          sophistication: 'nation_state',
          active_since: null,
          description: `Derived from explicit country-linked activity in "${threat.title}".`,
          derived: true,
        });
      }
    }
  }

  return actors;
}

function aggregateDerivedActors(threats) {
  const byName = new Map();
  for (const threat of threats) {
    for (const actor of deriveActorsFromThreat(threat)) {
      if (!byName.has(actor.name)) {
        byName.set(actor.name, {
          ...actor,
          threat_count: 0,
          first_seen: threat.ingested_at,
          last_seen: threat.ingested_at,
          severities: [],
          sectors: [],
          threat_ids: [],
          recent_threats: [],
        });
      }
      const row = byName.get(actor.name);
      row.threat_count += 1;
      row.first_seen = row.first_seen && row.first_seen < threat.ingested_at ? row.first_seen : threat.ingested_at;
      row.last_seen = row.last_seen && row.last_seen > threat.ingested_at ? row.last_seen : threat.ingested_at;
      row.severities.push(threat.severity);
      row.sectors.push(...(threat.sectors || []));
      row.threat_ids.push(threat.id);
      if (row.recent_threats.length < 5) {
        row.recent_threats.push({
          id: threat.id,
          title: threat.title,
          severity: threat.severity,
          ingested_at: threat.ingested_at,
          source_name: threat.source_name,
          credibility_score: threat.credibility_score,
        });
      }
    }
  }

  return [...byName.values()].map(actor => ({
    ...actor,
    severities: [...new Set(actor.severities.filter(Boolean))],
    sectors: [...new Set(actor.sectors.filter(Boolean))],
    threat_ids: [...new Set(actor.threat_ids)],
  })).sort((a, b) => b.threat_count - a.threat_count || String(b.last_seen).localeCompare(String(a.last_seen)));
}

function summarizeActorField(actors, field) {
  const counts = new Map();
  for (const actor of actors) counts.set(actor[field] || 'unknown', (counts.get(actor[field] || 'unknown') || 0) + 1);
  return [...counts.entries()].map(([key, cnt]) => ({ [field]: key, cnt })).sort((a, b) => b.cnt - a.cnt);
}

function summarizeActorCountries(actors) {
  const counts = new Map();
  for (const actor of actors) {
    if (actor.origin_country) counts.set(actor.origin_country, (counts.get(actor.origin_country) || 0) + 1);
  }
  return [...counts.entries()].map(([origin_country, cnt]) => ({ origin_country, cnt })).sort((a, b) => b.cnt - a.cnt);
}

// ─── Built-in cron (runs alongside portal) ────────────────────────────────

function schedulePipeline() {
  const schedule = settings.pipeline?.cron_schedule || '0 * * * *';
  // Full scan on the configured schedule; dedupe keeps repeat runs cheap.
  cron.schedule(schedule, () => {
    if (_pipelineRunning) {
      console.log('[CRON] Pipeline already running, skipping scheduled run');
      return;
    }
    console.log('[CRON] Starting scheduled threat intelligence scan...');
    _pipelineRunning = true;
    broadcastSse('pipeline_started', { time: new Date().toISOString() });

    const child = spawn('node', ['scripts/run-pipeline.mjs'], {
      cwd: ROOT,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdoutBuf = '';
    child.stdout.on('data', d => { stdoutBuf += d.toString(); process.stdout.write(d); });
    child.stderr.on('data', d => process.stderr.write(d));

    child.on('close', () => {
      _pipelineRunning = false;
      const m = stdoutBuf.match(/Threats saved:\s+(\d+)/);
      broadcastSse('pipeline_done', { threats_created: m ? parseInt(m[1]) : 0 });
    });
  }, { timezone: 'UTC' });

  console.log(`✓ Pipeline scheduled: ${schedule}`);
}

function scheduleSourceDiscovery() {
  const schedule = settings.feeds?.discovery_cron_schedule || '0 2 * * 1';
  cron.schedule(schedule, () => {
    if (_discoveryRunning) {
      console.log('[CRON] Source discovery already running, skipping');
      return;
    }
    console.log('[CRON] Starting source discovery...');
    _discoveryRunning = true;
    const child = spawn('node', ['scripts/discover-sources.mjs'], {
      cwd: ROOT,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', d => process.stdout.write(d));
    child.stderr.on('data', d => process.stderr.write(d));
    child.on('close', () => { _discoveryRunning = false; });
  }, { timezone: 'UTC' });

  console.log(`✓ Source discovery scheduled: ${schedule}`);
}

function scheduleOtxSync() {
  if (!process.env.OTX_API_KEY) {
    console.log('○ OTX sync disabled: OTX_API_KEY not set');
    return;
  }

  const schedule = settings.integrations?.otx?.cron_schedule || '30 * * * *';
  cron.schedule(schedule, () => {
    if (_otxRunning) {
      console.log('[CRON] OTX sync already running, skipping');
      return;
    }
    console.log('[CRON] Starting OTX external sighting sync...');
    _otxRunning = true;
    const child = spawn('node', ['scripts/sync-otx-sightings.mjs'], {
      cwd: ROOT,
      env: {
        ...process.env,
        OTX_LOOKBACK_DAYS: String(settings.integrations?.otx?.lookback_days || process.env.OTX_LOOKBACK_DAYS || 14),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', d => process.stdout.write(d));
    child.stderr.on('data', d => process.stderr.write(d));
    child.on('close', code => {
      _otxRunning = false;
      broadcastSse('pipeline_done', { otx_synced: true, code });
    });
  }, { timezone: 'UTC' });

  console.log(`✓ OTX sync scheduled: ${schedule}`);
}

function scheduleExternalComparison() {
  const schedule = settings.integrations?.external_comparison?.cron_schedule || '45 */2 * * *';
  cron.schedule(schedule, () => {
    if (_externalRunning) {
      console.log('[CRON] External comparison already running, skipping');
      return;
    }
    console.log('[CRON] Starting external comparison sync...');
    _externalRunning = true;
    const child = spawn('node', ['scripts/sync-external-comparison.mjs'], {
      cwd: ROOT,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', d => process.stdout.write(d));
    child.stderr.on('data', d => process.stderr.write(d));
    child.on('close', code => {
      _externalRunning = false;
      broadcastSse('pipeline_done', { external_synced: true, code });
    });
  }, { timezone: 'UTC' });

  console.log(`✓ External comparison scheduled: ${schedule}`);
}

function scheduleStartupCatchup() {
  if (settings.pipeline?.startup_catchup_enabled === false) {
    console.log('○ Startup catch-up disabled');
    return;
  }

  const thresholdHours = settings.pipeline?.startup_catchup_after_hours || 3;
  const row = ensureDb().prepare(`
    SELECT completed_at
    FROM feed_runs
    WHERE feed_id = 'pipeline' AND status IN ('success','partial') AND completed_at IS NOT NULL
    ORDER BY completed_at DESC
    LIMIT 1
  `).get();

  const completedAt = Date.parse(row?.completed_at || '');
  const hoursSince = Number.isFinite(completedAt) ? (Date.now() - completedAt) / 3600000 : Infinity;

  if (hoursSince < thresholdHours) {
    console.log(`○ Startup catch-up not needed: last pipeline ${hoursSince.toFixed(1)}h ago`);
    return;
  }

  const reason = Number.isFinite(hoursSince)
    ? `startup_catchup_${Math.round(hoursSince)}h`
    : 'startup_catchup_first_run';
  console.log(`✓ Startup catch-up queued: ${reason}`);
  setTimeout(() => {
    const result = spawnPipeline(reason);
    if (!result.started) console.log('[CATCHUP] Pipeline already running, startup catch-up skipped');
  }, 2500);
}

// ─── Start ────────────────────────────────────────────────────────────────

ensureDb();
schedulePipeline();
scheduleSourceDiscovery();
scheduleOtxSync();
scheduleExternalComparison();
scheduleStartupCatchup();

app.listen(PORT, () => {
  console.log(`\n  Radar — Threat Intelligence`);
  console.log(`  ━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`  Portal:  http://localhost:${PORT}`);
  const backend = process.env.OLLAMA_MODEL
    ? `Ollama (${process.env.OLLAMA_MODEL})`
    : process.env.ANTHROPIC_API_KEY
      ? 'Anthropic Claude'
      : 'NONE — add OLLAMA_MODEL or ANTHROPIC_API_KEY to .env';
  console.log(`  Backend: ${backend}`);
  console.log(`  Sync:    ${settings.pipeline?.cron_schedule || '0 * * * *'} UTC\n`);
});
