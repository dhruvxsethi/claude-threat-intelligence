// Cross-threat correlation engine
// Links threats sharing CVEs, IOCs, threat actors, or similar content

export class Correlator {
  constructor(db) {
    this.db = db;
  }

  // After inserting a new threat, find and link related ones
  correlate(newThreatId) {
    const threat = this.db.prepare('SELECT * FROM threats WHERE id = ?').get(newThreatId);
    if (!threat) return;

    const relatedIds = new Set();

    // 1. Share CVEs
    const cveRows = this.db.prepare('SELECT cve_id FROM threat_cves WHERE threat_id = ?').all(newThreatId);
    if (cveRows.length > 0) {
      const placeholders = cveRows.map(() => '?').join(',');
      const cveIds = cveRows.map(r => r.cve_id);
      const sharedCve = this.db.prepare(`
        SELECT DISTINCT threat_id FROM threat_cves
        WHERE cve_id IN (${placeholders}) AND threat_id != ?
      `).all(...cveIds, newThreatId);
      sharedCve.forEach(r => relatedIds.add({ id: r.threat_id, reason: `shared CVE: ${cveIds.join(', ')}`, score: 0.9 }));
    }

    // 2. Share threat actors (by name)
    const actorRows = this.db.prepare('SELECT name FROM threat_actors WHERE threat_id = ?').all(newThreatId);
    if (actorRows.length > 0) {
      const actorNames = actorRows.map(r => r.name.toLowerCase());
      const allActors = this.db.prepare(`
        SELECT DISTINCT ta.threat_id, ta.name FROM threat_actors ta
        WHERE ta.threat_id != ?
      `).all(newThreatId);
      allActors.forEach(a => {
        if (actorNames.includes(a.name.toLowerCase())) {
          relatedIds.add({ id: a.threat_id, reason: `shared actor: ${a.name}`, score: 0.85 });
        }
      });
    }

    // 3. Share IOCs (high-confidence only)
    const iocRows = this.db.prepare(`
      SELECT ioc_type, ioc_value FROM threat_iocs
      WHERE threat_id = ? AND confidence >= 70
    `).all(newThreatId);
    if (iocRows.length > 0) {
      iocRows.forEach(ioc => {
        const shared = this.db.prepare(`
          SELECT DISTINCT threat_id FROM threat_iocs
          WHERE ioc_type = ? AND ioc_value = ? AND threat_id != ?
        `).all(ioc.ioc_type, ioc.ioc_value, newThreatId);
        shared.forEach(r => relatedIds.add({ id: r.threat_id, reason: `shared IOC: ${ioc.ioc_value}`, score: 0.95 }));
      });
    }

    // 4. Same malware family
    const malwareFamilies = JSON.parse(threat.malware_families || '[]').map(m => m.name?.toLowerCase()).filter(Boolean);
    if (malwareFamilies.length > 0) {
      const allThreats = this.db.prepare(`
        SELECT id, malware_families FROM threats WHERE id != ? AND malware_families != '[]'
      `).all(newThreatId);
      allThreats.forEach(t => {
        const tFamilies = JSON.parse(t.malware_families || '[]').map(m => m.name?.toLowerCase()).filter(Boolean);
        if (tFamilies.some(f => malwareFamilies.includes(f))) {
          relatedIds.add({ id: t.id, reason: `shared malware family`, score: 0.75 });
        }
      });
    }

    // Convert Set to array (deduplicate by id)
    const relatedMap = new Map();
    relatedIds.forEach(r => {
      if (!relatedMap.has(r.id) || relatedMap.get(r.id).score < r.score) {
        relatedMap.set(r.id, r);
      }
    });

    const related = [...relatedMap.values()].slice(0, 10);

    if (related.length === 0) return;

    // Store corroboration links
    const insertCorr = this.db.prepare(`
      INSERT OR IGNORE INTO corroborations (primary_threat_id, secondary_threat_id, similarity_score, match_reason)
      VALUES (?, ?, ?, ?)
    `);
    const updateRelated = this.db.prepare(`
      UPDATE threats SET related_threat_ids = ?, is_corroborated = 1, corroboration_count = corroboration_count + 1
      WHERE id = ?
    `);

    const relatedIdsOnly = related.map(r => r.id);
    updateRelated.run(JSON.stringify(relatedIdsOnly), newThreatId);

    related.forEach(r => {
      insertCorr.run(newThreatId, r.id, r.score, r.reason);

      // Update the related threat's links too
      const existing = this.db.prepare('SELECT related_threat_ids FROM threats WHERE id = ?').get(r.id);
      if (existing) {
        const existingIds = JSON.parse(existing.related_threat_ids || '[]');
        if (!existingIds.includes(newThreatId)) {
          existingIds.push(newThreatId);
          this.db.prepare(`
            UPDATE threats SET related_threat_ids = ?, is_corroborated = 1, corroboration_count = corroboration_count + 1
            WHERE id = ?
          `).run(JSON.stringify(existingIds), r.id);
        }
      }
    });

    // Update credibility score after corroboration
    if (related.length > 0) {
      this.db.prepare(`
        UPDATE threats SET credibility_score = MIN(100, credibility_score + ?)
        WHERE id = ?
      `).run(related.length * 3, newThreatId);
    }

    return related;
  }

  // Update global IOC index
  updateIocIndex(iocs, threatId) {
    const upsert = this.db.prepare(`
      INSERT INTO ioc_index (ioc_type, ioc_value, threat_ids)
      VALUES (?, ?, json_array(?))
      ON CONFLICT(ioc_type, ioc_value) DO UPDATE SET
        last_seen = datetime('now'),
        occurrence_count = occurrence_count + 1,
        threat_ids = json_insert(threat_ids, '$[#]', ?)
    `);
    for (const ioc of iocs) {
      upsert.run(ioc.ioc_type, ioc.ioc_value, threatId, threatId);
    }
  }
}
