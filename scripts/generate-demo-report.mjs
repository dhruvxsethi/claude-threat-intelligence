#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb, migrate } from './migrate.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

function argValue(name, fallback) {
  const prefix = `--${name}=`;
  const arg = process.argv.find(a => a.startsWith(prefix));
  return arg ? arg.slice(prefix.length) : fallback;
}

function parseJson(v, fallback) {
  try { return JSON.parse(v || ''); } catch { return fallback; }
}

function isCommoditySource(name = '') {
  return ['NIST NVD', 'GitHub Security Advisories', 'CISA Known Exploited Vulnerabilities'].includes(name);
}

function coverageForThreat(db, threat) {
  const cves = db.prepare('SELECT cve_id FROM threat_cves WHERE threat_id = ?').all(threat.id);
  const iocs = db.prepare('SELECT ioc_type, ioc_value FROM threat_iocs WHERE threat_id = ? LIMIT 30').all(threat.id);
  const sightings = db.prepare('SELECT provider FROM external_sightings WHERE threat_id = ?').all(threat.id);
  const checks = db.prepare(`
    SELECT observed_at, metadata
    FROM threat_evidence
    WHERE threat_id = ? AND evidence_type = 'gap_tracking'
    ORDER BY observed_at DESC, id DESC
    LIMIT 100
  `).all(threat.id).map(r => {
    const meta = parseJson(r.metadata, {});
    return meta.provider ? { ...meta, checked_at: meta.checked_at || r.observed_at } : null;
  }).filter(Boolean);
  const seenSources = new Set();

  for (const cve of cves) {
    db.prepare(`
      SELECT DISTINCT t.source_name
      FROM threat_cves c JOIN threats t ON c.threat_id = t.id
      WHERE upper(c.cve_id) = upper(?) AND t.id != ?
    `).all(cve.cve_id, threat.id).forEach(r => {
      if (r.source_name && r.source_name !== threat.source_name) seenSources.add(r.source_name);
    });
  }

  for (const ioc of iocs) {
    db.prepare(`
      SELECT DISTINCT t.source_name
      FROM threat_iocs i JOIN threats t ON i.threat_id = t.id
      WHERE i.ioc_type = ? AND lower(i.ioc_value) = lower(?) AND t.id != ?
    `).all(ioc.ioc_type, ioc.ioc_value, threat.id).forEach(r => {
      if (r.source_name && r.source_name !== threat.source_name) seenSources.add(r.source_name);
    });
  }

  const external = [...new Set(sightings.map(s => s.provider).filter(Boolean))];
  const completedChecks = checks.filter(c => ['found', 'not_found'].includes(c.status));
  const coverageState = completedChecks.length >= 4
    ? 'fully_checked'
    : completedChecks.length > 0
      ? 'partially_checked'
      : 'not_checked';
  return {
    status: isCommoditySource(threat.source_name) ? 'commodity_database' : (seenSources.size || external.length ? 'seen_elsewhere' : 'unique_candidate'),
    seen_sources: [...seenSources],
    external_providers: external,
    match_material: { cves: cves.length, iocs: iocs.length },
    checked_sources: checks,
    coverage_state: coverageState,
    coverage_counts: {
      checked: completedChecks.length,
      total: 6,
      missing: Math.max(0, 6 - completedChecks.length),
    },
    confidence: {
      level: cves.length + iocs.length ? 'medium' : 'low',
      score: Math.max(0, Math.min(100, (cves.length + iocs.length ? 70 : 35) + (coverageState === 'fully_checked' ? 8 : coverageState === 'partially_checked' ? 3 : -15))),
    },
  };
}

function buildReport(data, days) {
  const unique = data.filter(t => t.coverage.status === 'unique_candidate');
  const seen = data.filter(t => t.coverage.status === 'seen_elsewhere');
  const lines = [
    '# Radar Coverage Gap Demo Report',
    '',
    `Generated: ${new Date().toISOString()}`,
    `Window: last ${days} day${days === 1 ? '' : 's'}`,
    '',
    '## Executive Summary',
    '',
    `Radar reviewed ${data.length} article-sourced threats.`,
    `${unique.length} are not seen elsewhere candidates based on external sightings and shared CVE/IOC matches.`,
    `${seen.length} were also seen in monitored common sources.`,
    '',
    '## Radar Caught These Before Monitored/Common Sources',
    '',
  ];

  if (!unique.length) lines.push('No not-seen-elsewhere items in this window.', '');
  for (const t of unique.slice(0, 30)) {
    lines.push(`### ${t.title}`);
    lines.push(`- Severity: ${t.severity}`);
    lines.push(`- Source: ${t.source_name}`);
    lines.push(`- Source URL: ${t.source_url || 'n/a'}`);
    lines.push(`- First seen by Radar: ${t.first_seen_by_us_at || t.ingested_at}`);
    lines.push(`- Coverage confidence: ${t.coverage.confidence.level} (${t.coverage.confidence.score})`);
    lines.push(`- Coverage completeness: ${formatCoverageState(t.coverage)}`);
    lines.push(`- Checked sources: ${formatChecks(t.coverage.checked_sources)}`);
    lines.push(`- CVEs: ${t.cve_count}; IOCs: ${t.ioc_count}`);
    lines.push(`- Timeline: published ${t.published_at || 'n/a'}; Radar ingested ${t.first_seen_by_us_at || t.ingested_at}; coverage checked ${latestCheck(t.coverage.checked_sources) || 'n/a'}`);
    lines.push(`- Why it matters: ${(t.summary || '').replace(/\s+/g, ' ').slice(0, 320) || 'Source article contained extractable threat intelligence.'}`);
    lines.push('');
  }

  lines.push('## Seen Elsewhere', '');
  if (!seen.length) lines.push('No seen-elsewhere items in this window.', '');
  for (const t of seen.slice(0, 30)) {
    const sources = [...t.coverage.external_providers, ...t.coverage.seen_sources].join(', ') || 'monitored source';
    lines.push(`- ${t.title} — also seen in ${sources}`);
  }

  lines.push('', '## Method', '');
  lines.push('Radar compares article-sourced threats against imported external sightings and local records from commodity/common sources using exact CVE and IOC matches. Not-seen-elsewhere means no match was found in the monitored set, not that no platform globally has the item.');
  return `${lines.join('\n')}\n`;
}

function latestCheck(checks = []) {
  return checks.map(c => c.checked_at).filter(Boolean).sort().pop();
}

function formatChecks(checks = []) {
  if (!checks.length) return 'none recorded';
  return checks.map(c => `${c.provider}:${c.status || 'unknown'}`).join(', ');
}

function formatCoverageState(coverage = {}) {
  const state = String(coverage.coverage_state || 'not_checked').replace(/_/g, ' ');
  const counts = coverage.coverage_counts;
  return counts ? `${state} (${counts.checked}/${counts.total} checks)` : state;
}

const days = parseInt(argValue('days', '7'), 10);
const cutoff = new Date(Date.now() - days * 86400000).toISOString();
const db = getDb(join(ROOT, 'data/threats.db'));
migrate(db);

const rows = db.prepare(`
  SELECT t.*,
    (SELECT COUNT(*) FROM threat_cves WHERE threat_id = t.id) as cve_count,
    (SELECT COUNT(*) FROM threat_iocs WHERE threat_id = t.id) as ioc_count
  FROM threats t
  WHERE t.ingested_at >= ?
    AND COALESCE(t.source_name, '') NOT IN (
      'NIST NVD',
      'GitHub Security Advisories',
      'CISA Known Exploited Vulnerabilities'
    )
  ORDER BY t.ingested_at DESC
  LIMIT 200
`).all(cutoff).map(t => ({
  ...t,
  sectors: parseJson(t.sectors, []),
  coverage: coverageForThreat(db, t),
}));

db.close();

const outDir = join(ROOT, 'reports');
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
const outPath = join(outDir, `radar-demo-gap-report-${new Date().toISOString().slice(0, 10)}.md`);
writeFileSync(outPath, buildReport(rows, days));
console.log(outPath);
