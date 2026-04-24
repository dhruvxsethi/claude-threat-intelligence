import express from 'express';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, readFileSync } from 'fs';
import { getDb, migrate } from '../scripts/migrate.mjs';
import { loadSettings } from '../ingestion/feed-fetcher.mjs';
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
    has_cves, has_iocs, min_credibility,
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

  const relatedIds = JSON.parse(threat.related_threat_ids || '[]');
  const related = relatedIds.length > 0
    ? db.prepare(`SELECT id, title, severity, threat_type, ingested_at, credibility_score FROM threats WHERE id IN (${relatedIds.map(() => '?').join(',')})`).all(...relatedIds)
    : [];

  res.json({
    ...parseThreat(threat),
    cves: cves.map(c => ({ ...c, affected_products: JSON.parse(c.affected_products || '[]') })),
    iocs,
    ttps,
    actors: actors.map(a => ({ ...a, aliases: JSON.parse(a.aliases || '[]') })),
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
  const top_actors = db.prepare(`
    SELECT ta.name, COUNT(*) as cnt FROM threat_actors ta
    JOIN threats t ON ta.threat_id = t.id WHERE t.ingested_at >= ?
    GROUP BY ta.name ORDER BY cnt DESC LIMIT 10
  `).all(cutoff);

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
  res.json({ health, recentRuns });
});

// ─── Trigger pipeline run manually ────────────────────────────────────────

app.post('/api/pipeline/run', (req, res) => {
  const child = spawn('node', ['scripts/run-pipeline.mjs'], { cwd: ROOT, detached: true, stdio: 'ignore' });
  child.unref();

  broadcastSse('pipeline_started', { runId: Date.now() });
  res.json({ status: 'started' });
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

  const topActors = db.prepare(`
    SELECT ta.name, ta.origin_country, ta.motivation, COUNT(*) as cnt
    FROM threat_actors ta JOIN threats t ON ta.threat_id = t.id
    WHERE t.ingested_at >= ? AND t.sectors LIKE ?
    GROUP BY ta.name ORDER BY cnt DESC LIMIT 5
  `).all(cutoff, `%${sector}%`);

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

  res.json({ threats, cves, iocs, actors });
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

// ─── Built-in cron (runs alongside portal) ────────────────────────────────

function schedulePipeline() {
  // Full scan every 3 hours — all feeds + vulnerability APIs
  cron.schedule('0 */3 * * *', () => {
    console.log('[CRON] Starting full threat intelligence scan...');
    const child = spawn('node', ['scripts/run-pipeline.mjs'], { cwd: ROOT, detached: true, stdio: 'ignore' });
    child.unref();
    broadcastSse('pipeline_started', { time: new Date().toISOString() });
  }, { timezone: 'UTC' });

  console.log('✓ Pipeline scheduled: full scan every 3 hours');
}

// ─── Start ────────────────────────────────────────────────────────────────

ensureDb();
schedulePipeline();

app.listen(PORT, () => {
  console.log(`\n  Claude Threat Intelligence Portal`);
  console.log(`  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`  → http://localhost:${PORT}`);
  console.log(`  → Press Ctrl+C to stop\n`);
});
