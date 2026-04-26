#!/usr/bin/env node
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb, migrate } from './migrate.mjs';
import { deriveActorsFromText } from '../intelligence/actor-extractor.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const db = getDb(join(ROOT, 'data/threats.db'));
migrate(db);

const existing = db.prepare('SELECT COUNT(*) cnt FROM threat_actors WHERE threat_id = ?');
const insert = db.prepare(`
  INSERT INTO threat_actors (
    threat_id, name, aliases, origin_country, motivation, sophistication, active_since, description
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const threats = db.prepare(`
  SELECT id, title, summary, source_name, threat_type
  FROM threats
  WHERE source_name NOT IN ('NIST NVD','GitHub Security Advisories','CISA Known Exploited Vulnerabilities')
  ORDER BY ingested_at DESC
`).all();

let inserted = 0;
const run = db.transaction(() => {
  for (const t of threats) {
    if (existing.get(t.id).cnt > 0) continue;
    const actors = deriveActorsFromText(t);
    for (const a of actors) {
      insert.run(
        t.id,
        a.name,
        JSON.stringify(a.aliases || []),
        a.origin_country || null,
        a.motivation || 'unknown',
        a.sophistication || 'unknown',
        a.active_since || null,
        a.description || null
      );
      inserted++;
    }
  }
});

run();
db.close();
console.log(`Actor backfill complete: ${inserted} actor rows inserted.`);
