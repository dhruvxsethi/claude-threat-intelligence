#!/usr/bin/env node
import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

export function getDb(path) {
  const db = new Database(path || join(ROOT, 'data/threats.db'));
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('cache_size = -64000'); // 64MB cache
  return db;
}

export function migrate(db) {
  db.exec(`
    -- Core threats table
    CREATE TABLE IF NOT EXISTS threats (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      summary TEXT,
      severity TEXT CHECK(severity IN ('critical','high','medium','low','unknown')) DEFAULT 'unknown',
      threat_type TEXT,
      kill_chain_stage TEXT,
      credibility_score INTEGER DEFAULT 0,
      source_url TEXT UNIQUE,
      source_name TEXT,
      source_tier INTEGER DEFAULT 5,
      published_at TEXT,
      ingested_at TEXT DEFAULT (datetime('now')),
      analyzed_at TEXT,
      sector_impact TEXT,         -- JSON: {banking: {score, reason}, government: {score, reason}, healthcare: {score, reason}}
      sectors TEXT DEFAULT '[]',  -- JSON array
      geography TEXT DEFAULT '[]',-- JSON array of targeted countries/regions
      malware_families TEXT DEFAULT '[]', -- JSON array
      affected_products TEXT DEFAULT '[]', -- JSON array
      raw_content_hash TEXT,
      content_length INTEGER DEFAULT 0,
      is_corroborated INTEGER DEFAULT 0,
      corroboration_count INTEGER DEFAULT 0,
      related_threat_ids TEXT DEFAULT '[]', -- JSON array
      slot TEXT CHECK(slot IN ('A','B','BOTH')),
      UNIQUE(raw_content_hash)
    );

    -- CVEs linked to threats
    CREATE TABLE IF NOT EXISTS threat_cves (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      threat_id TEXT REFERENCES threats(id) ON DELETE CASCADE,
      cve_id TEXT NOT NULL,
      cvss_score REAL,
      cvss_vector TEXT,
      cvss_severity TEXT,
      description TEXT,
      affected_products TEXT DEFAULT '[]', -- JSON array
      patch_available INTEGER DEFAULT 0,
      patch_url TEXT,
      in_kev INTEGER DEFAULT 0,           -- Is in CISA Known Exploited Vulnerabilities
      exploited_in_wild INTEGER DEFAULT 0,
      published_date TEXT,
      UNIQUE(threat_id, cve_id)
    );

    -- IOCs linked to threats
    CREATE TABLE IF NOT EXISTS threat_iocs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      threat_id TEXT REFERENCES threats(id) ON DELETE CASCADE,
      ioc_type TEXT CHECK(ioc_type IN (
        'ip','ipv6','domain','subdomain','url','email',
        'hash_md5','hash_sha1','hash_sha256','hash_sha512',
        'file_name','file_path','registry_key','mutex',
        'user_agent','asn','bitcoin_address','yara_rule'
      )) NOT NULL,
      ioc_value TEXT NOT NULL,
      confidence INTEGER DEFAULT 70,     -- 0-100
      malware_family TEXT,
      context TEXT,                       -- short description of what this IOC does
      first_seen TEXT,
      last_seen TEXT,
      UNIQUE(threat_id, ioc_type, ioc_value)
    );

    -- MITRE ATT&CK TTPs
    CREATE TABLE IF NOT EXISTS threat_ttps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      threat_id TEXT REFERENCES threats(id) ON DELETE CASCADE,
      mitre_id TEXT NOT NULL,            -- e.g. T1566.001
      tactic TEXT,                        -- e.g. Initial Access
      technique TEXT,                     -- e.g. Phishing: Spearphishing Attachment
      sub_technique TEXT,
      procedure TEXT,                     -- specific observed procedure
      UNIQUE(threat_id, mitre_id)
    );

    -- Threat actors
    CREATE TABLE IF NOT EXISTS threat_actors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      threat_id TEXT REFERENCES threats(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      aliases TEXT DEFAULT '[]',          -- JSON array
      origin_country TEXT,
      motivation TEXT CHECK(motivation IN (
        'financial','espionage','sabotage','hacktivism',
        'cyberwarfare','unknown'
      )) DEFAULT 'unknown',
      sophistication TEXT CHECK(sophistication IN (
        'nation_state','advanced','intermediate','basic','script_kiddie','unknown'
      )) DEFAULT 'unknown',
      active_since TEXT,
      description TEXT
    );

    -- Feed run history
    CREATE TABLE IF NOT EXISTS feed_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      feed_id TEXT NOT NULL,
      feed_name TEXT,
      slot TEXT,
      started_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT,
      status TEXT CHECK(status IN ('running','success','failed','partial')) DEFAULT 'running',
      articles_fetched INTEGER DEFAULT 0,
      articles_new INTEGER DEFAULT 0,
      articles_analyzed INTEGER DEFAULT 0,
      threats_created INTEGER DEFAULT 0,
      error_message TEXT
    );

    -- Individual article tracking
    CREATE TABLE IF NOT EXISTS articles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT UNIQUE NOT NULL,
      content_hash TEXT UNIQUE,
      feed_id TEXT,
      title TEXT,
      published_at TEXT,
      fetched_at TEXT DEFAULT (datetime('now')),
      analyzed INTEGER DEFAULT 0,
      threat_id TEXT REFERENCES threats(id),
      skip_reason TEXT                   -- why we skipped analysis (too short, duplicate, off-topic)
    );

    -- Corroboration links (when multiple sources report same event)
    CREATE TABLE IF NOT EXISTS corroborations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      primary_threat_id TEXT REFERENCES threats(id),
      secondary_threat_id TEXT REFERENCES threats(id),
      similarity_score REAL,
      match_reason TEXT,               -- what matched (CVE, actor, IOC, title similarity)
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(primary_threat_id, secondary_threat_id)
    );

    -- Feed health tracking
    CREATE TABLE IF NOT EXISTS feed_health (
      feed_id TEXT PRIMARY KEY,
      feed_name TEXT,
      last_checked TEXT,
      last_success TEXT,
      consecutive_failures INTEGER DEFAULT 0,
      avg_articles_per_run REAL DEFAULT 0,
      total_threats_contributed INTEGER DEFAULT 0,
      is_healthy INTEGER DEFAULT 1,
      redirect_url TEXT,
      error_message TEXT
    );

    -- IOC global dedup index (across all threats)
    CREATE TABLE IF NOT EXISTS ioc_index (
      ioc_type TEXT NOT NULL,
      ioc_value TEXT NOT NULL,
      first_seen TEXT DEFAULT (datetime('now')),
      last_seen TEXT DEFAULT (datetime('now')),
      occurrence_count INTEGER DEFAULT 1,
      threat_ids TEXT DEFAULT '[]',      -- JSON array of threat IDs
      PRIMARY KEY (ioc_type, ioc_value)
    );

    -- Evidence trail for why a threat exists and how it was extracted.
    CREATE TABLE IF NOT EXISTS threat_evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      threat_id TEXT REFERENCES threats(id) ON DELETE CASCADE,
      evidence_type TEXT CHECK(evidence_type IN (
        'source_article','extraction','gap_tracking','external_sighting','source_discovery'
      )) NOT NULL,
      title TEXT,
      body TEXT,
      url TEXT,
      observed_at TEXT DEFAULT (datetime('now')),
      metadata TEXT DEFAULT '{}'
    );

    -- External sightings from OTX or other comparison systems.
    CREATE TABLE IF NOT EXISTS external_sightings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      threat_id TEXT REFERENCES threats(id) ON DELETE CASCADE,
      provider TEXT NOT NULL,
      external_id TEXT,
      match_type TEXT,
      match_value TEXT,
      first_seen_at TEXT,
      last_seen_at TEXT,
      imported_at TEXT DEFAULT (datetime('now')),
      metadata TEXT DEFAULT '{}',
      UNIQUE(provider, external_id, threat_id)
    );

    -- Candidate sources discovered by the discovery job, pending review.
    CREATE TABLE IF NOT EXISTS discovered_sources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT UNIQUE NOT NULL,
      title TEXT,
      source_type TEXT DEFAULT 'rss',
      discovered_from TEXT,
      confidence INTEGER DEFAULT 50,
      status TEXT CHECK(status IN ('new','reviewed','rejected','added')) DEFAULT 'new',
      reason TEXT,
      discovered_at TEXT DEFAULT (datetime('now')),
      last_checked TEXT,
      metadata TEXT DEFAULT '{}'
    );

    -- Indexes for common queries
    CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
    CREATE INDEX IF NOT EXISTS idx_threats_ingested ON threats(ingested_at DESC);
    CREATE INDEX IF NOT EXISTS idx_threats_published ON threats(published_at DESC);
    CREATE INDEX IF NOT EXISTS idx_threats_credibility ON threats(credibility_score DESC);
    CREATE INDEX IF NOT EXISTS idx_threats_source ON threats(source_name);
    CREATE INDEX IF NOT EXISTS idx_cves_id ON threat_cves(cve_id);
    CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON threat_iocs(ioc_type, ioc_value);
    CREATE INDEX IF NOT EXISTS idx_iocs_threat ON threat_iocs(threat_id);
    CREATE INDEX IF NOT EXISTS idx_actors_name ON threat_actors(name);
    CREATE INDEX IF NOT EXISTS idx_articles_url ON articles(url);
    CREATE INDEX IF NOT EXISTS idx_feed_runs_feed ON feed_runs(feed_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_evidence_threat ON threat_evidence(threat_id, observed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_external_sightings_threat ON external_sightings(threat_id);
    CREATE INDEX IF NOT EXISTS idx_discovered_sources_status ON discovered_sources(status, discovered_at DESC);
  `);

  ensureColumn(db, 'threats', 'first_seen_by_us_at', 'TEXT');
  ensureColumn(db, 'threats', 'external_seen_at', 'TEXT');
  ensureColumn(db, 'threats', 'gap_status', "TEXT CHECK(gap_status IN ('not_checked','not_seen_elsewhere','seen_by_us_first','seen_elsewhere')) DEFAULT 'not_checked'");
  ensureColumn(db, 'threats', 'gap_checked_at', 'TEXT');

  console.log('✓ Database schema migrated');
}

function ensureColumn(db, table, column, definition) {
  const exists = db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === column);
  if (!exists) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

// Run directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const db = getDb();
  migrate(db);
  db.close();
  console.log('Migration complete.');
}
