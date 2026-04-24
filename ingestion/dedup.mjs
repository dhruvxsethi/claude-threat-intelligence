import { createHash } from 'crypto';

export function hashContent(text) {
  return createHash('sha256').update(text.trim().toLowerCase()).digest('hex');
}

export function normalizeUrl(url) {
  try {
    const u = new URL(url);
    // Remove tracking params
    const noiseParams = ['utm_source','utm_medium','utm_campaign','utm_content','utm_term','ref','source','fbclid','gclid'];
    noiseParams.forEach(p => u.searchParams.delete(p));
    return u.toString().replace(/\/$/, '');
  } catch {
    return url.trim();
  }
}

export class Deduplicator {
  constructor(db) {
    this.db = db;
    this._stmtCheckUrl = db.prepare('SELECT id, analyzed FROM articles WHERE url = ?');
    this._stmtCheckHash = db.prepare('SELECT id FROM articles WHERE content_hash = ?');
    this._stmtInsert = db.prepare(`
      INSERT OR IGNORE INTO articles (url, content_hash, feed_id, title, published_at, fetched_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `);
    this._stmtMarkAnalyzed = db.prepare(
      'UPDATE articles SET analyzed = 1, threat_id = ? WHERE url = ?'
    );
    this._stmtMarkSkipped = db.prepare(
      'UPDATE articles SET analyzed = 1, skip_reason = ? WHERE url = ?'
    );
  }

  isNewUrl(url) {
    const normalized = normalizeUrl(url);
    const existing = this._stmtCheckUrl.get(normalized);
    return !existing;
  }

  isNewContent(contentHash) {
    return !this._stmtCheckHash.get(contentHash);
  }

  registerArticle(url, feedId, title, publishedAt, contentHash = null) {
    const normalized = normalizeUrl(url);
    this._stmtInsert.run(normalized, contentHash, feedId, title, publishedAt);
    return normalized;
  }

  markAnalyzed(url, threatId) {
    this._stmtMarkAnalyzed.run(threatId, normalizeUrl(url));
  }

  markSkipped(url, reason) {
    this._stmtMarkSkipped.run(reason, normalizeUrl(url));
  }

  filterNewItems(items) {
    return items.filter(item => {
      if (!item.url) return false;
      return this.isNewUrl(item.url);
    });
  }

  // Find existing threats that might be related (by CVE or title similarity)
  findRelatedThreats(cveIds = [], title = '', limit = 5) {
    const related = new Set();

    if (cveIds.length > 0) {
      const placeholders = cveIds.map(() => '?').join(',');
      const stmt = this.db.prepare(`
        SELECT DISTINCT t.id FROM threats t
        JOIN threat_cves c ON c.threat_id = t.id
        WHERE c.cve_id IN (${placeholders})
      `);
      const rows = stmt.all(...cveIds);
      rows.forEach(r => related.add(r.id));
    }

    return [...related].slice(0, limit);
  }
}
