#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import { getDb, migrate } from './migrate.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const log = (msg) => console.log(`  ${msg}`);
const ok = (msg) => console.log(`  \x1b[32m✓\x1b[0m ${msg}`);
const warn = (msg) => console.log(`  \x1b[33m⚠\x1b[0m ${msg}`);
const err = (msg) => console.log(`  \x1b[31m✗\x1b[0m ${msg}`);
const step = (msg) => console.log(`\n\x1b[34m→\x1b[0m ${msg}`);

console.log('\n\x1b[1m  Claude Threat Intelligence Platform — Setup\x1b[0m');
console.log('  ════════════════════════════════════════════\n');

// 1. Check Node version
step('Checking environment...');
const nodeVersion = parseInt(process.versions.node.split('.')[0]);
if (nodeVersion < 20) {
  err(`Node.js 20+ required (found ${process.versions.node})`);
  process.exit(1);
}
ok(`Node.js ${process.versions.node}`);

// 2. Check .env
step('Checking environment variables...');
if (!existsSync(join(ROOT, '.env'))) {
  if (existsSync(join(ROOT, '.env.example'))) {
    warn('.env not found — copying from .env.example');
    const example = require('fs').readFileSync(join(ROOT, '.env.example'), 'utf8');
    writeFileSync(join(ROOT, '.env'), example);
  } else {
    writeFileSync(join(ROOT, '.env'), 'ANTHROPIC_API_KEY=\nPORT=3000\nNODE_ENV=development\n');
    warn('.env created — add your ANTHROPIC_API_KEY');
  }
}

// Load .env manually
const envContent = (existsSync(join(ROOT, '.env'))
  ? require('fs').readFileSync(join(ROOT, '.env'), 'utf8')
  : '').split('\n').filter(Boolean);
for (const line of envContent) {
  const [k, ...v] = line.split('=');
  if (k && !process.env[k]) process.env[k] = v.join('=');
}

if (!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY === 'sk-ant-...') {
  warn('ANTHROPIC_API_KEY not set in .env — Claude analysis will fail');
} else {
  ok(`ANTHROPIC_API_KEY set (${process.env.ANTHROPIC_API_KEY.slice(0, 15)}...)`);
}

// 3. Create required directories
step('Creating directories...');
const dirs = ['data', 'data/raw', 'reports', 'logs'];
dirs.forEach(d => {
  const full = join(ROOT, d);
  if (!existsSync(full)) {
    mkdirSync(full, { recursive: true });
    ok(`Created ${d}/`);
  } else {
    ok(`${d}/ exists`);
  }
});

// 4. Install dependencies
step('Checking npm dependencies...');
if (!existsSync(join(ROOT, 'node_modules'))) {
  log('Installing dependencies...');
  try {
    execSync('npm install', { cwd: ROOT, stdio: 'inherit' });
    ok('Dependencies installed');
  } catch (e) {
    err('npm install failed — run manually: npm install');
    process.exit(1);
  }
} else {
  ok('node_modules exists');
}

// 5. Initialize database
step('Initializing database...');
try {
  const db = getDb(join(ROOT, 'data/threats.db'));
  migrate(db);
  db.close();
  ok('Database initialized at data/threats.db');
} catch (e) {
  err(`Database init failed: ${e.message}`);
  process.exit(1);
}

// 6. Validate config files
step('Validating config files...');
const { default: yaml } = await import('js-yaml');
const { readFileSync } = await import('fs');
try {
  const feeds = yaml.load(readFileSync(join(ROOT, 'config/feeds.yml'), 'utf8'));
  ok(`feeds.yml — ${feeds.feeds?.length} feeds configured`);
  const sectors = yaml.load(readFileSync(join(ROOT, 'config/sectors.yml'), 'utf8'));
  ok(`sectors.yml — ${Object.keys(sectors.sectors || {}).length} sectors defined`);
  const settings = yaml.load(readFileSync(join(ROOT, 'config/settings.yml'), 'utf8'));
  ok(`settings.yml — model: ${settings.claude?.model}`);
} catch (e) {
  err(`Config validation failed: ${e.message}`);
  process.exit(1);
}

console.log('\n\x1b[32m  ✓ Setup complete!\x1b[0m\n');
console.log('  Next steps:');
console.log('  1. Add your ANTHROPIC_API_KEY to .env');
console.log('  2. Start the portal:  \x1b[36mnode portal/server.mjs\x1b[0m');
console.log('  3. Open in browser:   \x1b[36mhttp://localhost:3000\x1b[0m');
console.log('  4. Run first ingest:  \x1b[36mnode scripts/run-pipeline.mjs\x1b[0m\n');
