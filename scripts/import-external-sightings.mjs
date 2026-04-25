#!/usr/bin/env node
/**
 * Import sightings from OTX or another external comparison platform.
 *
 * Input: JSON array of objects with any of:
 *   provider, external_id, first_seen_at, last_seen_at, url,
 *   cve_id, ioc_type, ioc_value, title, metadata
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb, migrate } from './migrate.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const file = process.argv[2];
if (!file) {
  console.error('Usage: node scripts/import-external-sightings.mjs <sightings.json>');
  process.exit(1);
}

const input = JSON.parse(readFileSync(file, 'utf8'));
const rows = Array.isArray(input) ? input : input.sightings || [];
const db = getDb(join(ROOT, 'data/threats.db'));
migrate(db);

const insert = db.prepare(`
  INSERT OR IGNORE INTO external_sightings (
    threat_id, provider, external_id, match_type, match_value,
    first_seen_at, last_seen_at, metadata
  ) VALUES (
    @threat_id, @provider, @external_id, @match_type, @match_value,
    @first_seen_at, @last_seen_at, @metadata
  )
`);

const insertEvidence = db.prepare(`
  INSERT INTO threat_evidence (
    threat_id, evidence_type, title, body, url, observed_at, metadata
  ) VALUES (?, 'external_sighting', ?, ?, ?, ?, ?)
`);

const updateThreat = db.prepare(`
  UPDATE threats SET
    external_seen_at = COALESCE(external_seen_at, ?),
    gap_checked_at = datetime('now'),
    gap_status = CASE
      WHEN first_seen_by_us_at IS NOT NULL
       AND ? IS NOT NULL
       AND datetime(first_seen_by_us_at) < datetime(?)
      THEN 'seen_by_us_first'
      ELSE 'seen_elsewhere'
    END
  WHERE id = ?
`);

function findThreat(row) {
  if (row.url) {
    const byUrl = db.prepare('SELECT id FROM threats WHERE source_url = ?').get(row.url);
    if (byUrl) return { threat_id: byUrl.id, match_type: 'url', match_value: row.url };
  }

  if (row.cve_id) {
    const byCve = db.prepare('SELECT threat_id FROM threat_cves WHERE cve_id = ? ORDER BY id DESC LIMIT 1').get(row.cve_id);
    if (byCve) return { threat_id: byCve.threat_id, match_type: 'cve', match_value: row.cve_id };
  }

  if (row.ioc_type && row.ioc_value) {
    const byIoc = db.prepare(`
      SELECT threat_id FROM threat_iocs
      WHERE ioc_type = ? AND ioc_value = ?
      ORDER BY confidence DESC LIMIT 1
    `).get(row.ioc_type, row.ioc_value);
    if (byIoc) return { threat_id: byIoc.threat_id, match_type: 'ioc', match_value: `${row.ioc_type}:${row.ioc_value}` };
  }

  return null;
}

let imported = 0;
let unmatched = 0;

const run = db.transaction(() => {
  for (const row of rows) {
    const match = findThreat(row);
    if (!match) {
      unmatched++;
      continue;
    }

    const firstSeen = row.first_seen_at || row.last_seen_at || new Date().toISOString();
    const provider = row.provider || 'external';
    const externalId = row.external_id || `${provider}:${match.match_type}:${match.match_value}`;

    insert.run({
      threat_id: match.threat_id,
      provider,
      external_id: externalId,
      match_type: match.match_type,
      match_value: match.match_value,
      first_seen_at: firstSeen,
      last_seen_at: row.last_seen_at || firstSeen,
      metadata: JSON.stringify(row.metadata || row),
    });

    updateThreat.run(firstSeen, firstSeen, firstSeen, match.threat_id);
    insertEvidence.run(
      match.threat_id,
      `${provider} sighting`,
      `Matched externally by ${match.match_type}: ${match.match_value}`,
      row.url || null,
      firstSeen,
      JSON.stringify({ provider, external_id: externalId, raw: row })
    );
    imported++;
  }
});

run();
db.close();

console.log(`Imported ${imported} external sightings; ${unmatched} unmatched.`);
