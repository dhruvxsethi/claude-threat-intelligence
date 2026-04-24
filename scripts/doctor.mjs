#!/usr/bin/env node
/**
 * Health check — validates all platform components
 * Run: node scripts/doctor.mjs
 */

import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import { readFileSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

let pass = 0, fail = 0, warnings = 0;

const ok = (msg) => { console.log(`  \x1b[32m✓\x1b[0m ${msg}`); pass++; };
const warn = (msg) => { console.log(`  \x1b[33m⚠\x1b[0m ${msg}`); warnings++; };
const err = (msg) => { console.log(`  \x1b[31m✗\x1b[0m ${msg}`); fail++; };

console.log('\n\x1b[1m  CTI Platform — Health Check\x1b[0m');
console.log('  ══════════════════════════════\n');

// Node version
const nodeVer = parseInt(process.versions.node.split('.')[0]);
nodeVer >= 20 ? ok(`Node.js ${process.versions.node}`) : err(`Node.js 20+ required (have ${process.versions.node})`);

// .env
if (existsSync(join(ROOT, '.env'))) {
  const env = readFileSync(join(ROOT, '.env'), 'utf8');
  env.includes('ANTHROPIC_API_KEY=sk-') ? ok('.env with ANTHROPIC_API_KEY') : warn('.env exists but ANTHROPIC_API_KEY looks unset');
} else {
  err('.env not found — run: node scripts/setup.mjs');
}

// node_modules
existsSync(join(ROOT, 'node_modules/@anthropic-ai'))
  ? ok('npm dependencies installed')
  : err('Dependencies missing — run: npm install');

// Config files
const configs = ['config/feeds.yml', 'config/sectors.yml', 'config/settings.yml'];
for (const cfg of configs) {
  if (existsSync(join(ROOT, cfg))) {
    try {
      yaml.load(readFileSync(join(ROOT, cfg), 'utf8'));
      ok(cfg);
    } catch (e) {
      err(`${cfg} — YAML parse error: ${e.message}`);
    }
  } else {
    err(`${cfg} — missing`);
  }
}

// Feed count
try {
  const feeds = yaml.load(readFileSync(join(ROOT, 'config/feeds.yml'), 'utf8'));
  const enabled = feeds.feeds?.filter(f => f.enabled).length || 0;
  enabled >= 20
    ? ok(`${enabled} feeds enabled`)
    : warn(`Only ${enabled} feeds enabled — add more in config/feeds.yml`);
} catch {}

// Database
const dbPath = join(ROOT, 'data/threats.db');
if (existsSync(dbPath)) {
  try {
    const { getDb } = await import('./migrate.mjs');
    const db = getDb(dbPath);
    const count = db.prepare('SELECT COUNT(*) as cnt FROM threats').get().cnt;
    const feeds = db.prepare('SELECT COUNT(*) as cnt FROM feed_health').get().cnt;
    ok(`Database: ${count} threats, ${feeds} feed health records`);
    db.close();
  } catch (e) {
    err(`Database error: ${e.message}`);
  }
} else {
  warn('Database not initialized — run: node scripts/setup.mjs');
}

// Required source files
const sources = [
  'ingestion/feed-fetcher.mjs',
  'ingestion/article-scraper.mjs',
  'ingestion/dedup.mjs',
  'intelligence/analyzer.mjs',
  'intelligence/credibility.mjs',
  'intelligence/normalizer.mjs',
  'intelligence/correlator.mjs',
  'portal/server.mjs',
  'scripts/run-pipeline.mjs',
];
for (const src of sources) {
  existsSync(join(ROOT, src)) ? ok(src) : err(`${src} — missing`);
}

// Test RSS feed reachability
console.log('\n  Testing feed connectivity...');
try {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 5000);
  const res = await fetch('https://krebsonsecurity.com/feed/', { signal: controller.signal });
  res.ok ? ok('RSS feeds reachable (tested krebsonsecurity.com)') : warn(`RSS feed returned HTTP ${res.status}`);
} catch (e) {
  warn(`RSS feed test failed: ${e.message} (may be offline)`);
}

// Test CISA KEV API
try {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 5000);
  const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { signal: controller.signal });
  res.ok ? ok('CISA KEV API reachable') : warn(`CISA KEV returned HTTP ${res.status}`);
} catch (e) {
  warn(`CISA KEV test failed: ${e.message}`);
}

// Summary
console.log(`\n  ${'─'.repeat(36)}`);
console.log(`  \x1b[32m✓ Pass: ${pass}\x1b[0m  \x1b[33m⚠ Warn: ${warnings}\x1b[0m  \x1b[31m✗ Fail: ${fail}\x1b[0m`);
if (fail > 0) {
  console.log('\n  \x1b[31mFix failures before running the pipeline.\x1b[0m');
  process.exit(1);
} else if (warnings > 0) {
  console.log('\n  \x1b[33mPlatform operational with warnings.\x1b[0m');
} else {
  console.log('\n  \x1b[32mAll systems go.\x1b[0m');
}
console.log('');
