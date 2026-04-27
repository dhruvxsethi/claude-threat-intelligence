import { v4 as uuidv4 } from 'uuid';
import { scoreCredibility, normalizeSeverity, adjustIocConfidence } from './credibility.mjs';
import { deriveActorsFromText, mergeActors } from './actor-extractor.mjs';

function scoreCveCredibility(cve = {}, sourceName = 'NIST NVD') {
  let score = sourceName.includes('CISA') ? 88 : 68;
  const cvss = Number(cve.cvss_score || 0);
  if (cvss >= 9) score += 12;
  else if (cvss >= 7) score += 9;
  else if (cvss >= 4) score += 5;
  else if (cvss > 0) score += 2;
  if (cve.in_kev || cve.exploited_in_wild) score += 10;
  if ((cve.affected_products || []).length) score += 4;
  if ((cve.references || []).length) score += 3;
  return Math.max(55, Math.min(98, score));
}

export function normalizeArticleThreat(analysisData, article, feedMeta) {
  const id = uuidv4();
  const sourceTier = feedMeta?.source_tier || 5;
  const sourceCredibility = feedMeta?.source_credibility || 50;

  const cvssScores = (analysisData.cves || []).map(c => c.cvss_score).filter(Boolean);
  const severity = normalizeSeverity(analysisData, cvssScores);

  const adjustedIocs = adjustIocConfidence(analysisData.iocs, sourceCredibility, sourceTier);

  const { score: credScore } = scoreCredibility(analysisData, sourceTier, 0);

  // Filter sectors to only our 3 target sectors
  const validSectors = ['banking', 'government', 'healthcare'];
  const sectors = (analysisData.sectors || []).filter(s => validSectors.includes(s));

  // Ensure sector_impact has all 3 sectors
  const sectorImpact = {
    banking: analysisData.sector_impact?.banking || { score: 0, reason: 'Not directly relevant' },
    government: analysisData.sector_impact?.government || { score: 0, reason: 'Not directly relevant' },
    healthcare: analysisData.sector_impact?.healthcare || { score: 0, reason: 'Not directly relevant' },
  };

  const actors = mergeActors(
    analysisData.threat_actors || [],
    deriveActorsFromText({
      title: analysisData.title || article.title || '',
      summary: analysisData.summary || '',
      content: article.content || '',
    })
  );

  return {
    id,
    title: (analysisData.title || article.title || 'Untitled Threat').slice(0, 200),
    summary: analysisData.summary || '',
    severity,
    threat_type: analysisData.threat_type || 'other',
    kill_chain_stage: analysisData.kill_chain_stage || 'unknown',
    credibility_score: credScore,
    source_url: article.url,
    source_name: feedMeta?.name || article.source_name || 'Unknown',
    source_tier: sourceTier,
    published_at: article.published_at || new Date().toISOString(),
    ingested_at: new Date().toISOString(),
    analyzed_at: new Date().toISOString(),
    sector_impact: JSON.stringify(sectorImpact),
    sectors: JSON.stringify(sectors),
    geography: JSON.stringify(analysisData.geography || []),
    malware_families: JSON.stringify(analysisData.malware_families || []),
    affected_products: JSON.stringify(analysisData.affected_products || []),
    raw_content_hash: article.content_hash || null,
    content_length: article.content_length || 0,
    is_corroborated: 0,
    corroboration_count: 0,
    related_threat_ids: JSON.stringify([]),
    slot: feedMeta?.rotation_slot || 'B',
    first_seen_by_us_at: new Date().toISOString(),
    external_seen_at: null,
    gap_status: 'not_seen_elsewhere',
    gap_checked_at: null,
    // Relational data (stored separately)
    _cves: normalizeCves(analysisData.cves || [], id),
    _iocs: normalizeIocs(adjustedIocs || [], id),
    _ttps: normalizeTtps(analysisData.ttps || [], id),
    _actors: normalizeActors(actors, id),
  };
}

export function normalizeCveThreat(analysisData, cve, sourceUrl) {
  const id = uuidv4();
  const severity = normalizeSeverity(analysisData, [cve.cvss_score]);

  return {
    id,
    title: (analysisData.title || `${cve.cve_id}: Vulnerability`).slice(0, 200),
    summary: analysisData.summary || cve.description || '',
    severity,
    threat_type: 'vulnerability',
    kill_chain_stage: 'exploitation',
    credibility_score: scoreCveCredibility(cve),
    source_url: sourceUrl || `https://nvd.nist.gov/vuln/detail/${cve.cve_id}`,
    source_name: 'NIST NVD',
    source_tier: 1,
    published_at: cve.published_date || new Date().toISOString(),
    ingested_at: new Date().toISOString(),
    analyzed_at: new Date().toISOString(),
    sector_impact: JSON.stringify(analysisData.sector_impact || {
      banking: { score: 0, reason: 'Unknown' },
      government: { score: 0, reason: 'Unknown' },
      healthcare: { score: 0, reason: 'Unknown' },
    }),
    sectors: JSON.stringify(analysisData.sectors || []),
    geography: JSON.stringify([]),
    malware_families: JSON.stringify([]),
    affected_products: JSON.stringify(analysisData.affected_products || []),
    raw_content_hash: null,
    content_length: 0,
    is_corroborated: 0,
    corroboration_count: 0,
    related_threat_ids: JSON.stringify([]),
    slot: 'A',
    first_seen_by_us_at: new Date().toISOString(),
    external_seen_at: null,
    gap_status: 'seen_elsewhere',
    gap_checked_at: null,
    _cves: [{
      threat_id: id,
      cve_id: cve.cve_id,
      cvss_score: cve.cvss_score,
      cvss_vector: cve.cvss_vector,
      cvss_severity: cve.cvss_severity,
      description: cve.description,
      affected_products: JSON.stringify(cve.affected_products || []),
      patch_available: 1,
      patch_url: null,
      in_kev: cve.in_kev ? 1 : 0,
      exploited_in_wild: cve.exploited_in_wild ? 1 : 0,
      published_date: cve.published_date,
    }],
    _iocs: [],
    _ttps: normalizeTtps(analysisData.ttps || [], id),
    _actors: [],
  };
}

function normalizeCves(cves, threatId) {
  return cves.map(c => ({
    threat_id: threatId,
    cve_id: c.cve_id,
    cvss_score: c.cvss_score || null,
    cvss_vector: c.cvss_vector || null,
    cvss_severity: c.cvss_severity || null,
    description: c.description || '',
    affected_products: JSON.stringify(c.affected_products || []),
    patch_available: c.patch_available ? 1 : 0,
    patch_url: c.patch_url || null,
    in_kev: c.in_kev ? 1 : 0,
    exploited_in_wild: c.exploited_in_wild ? 1 : 0,
    published_date: c.published_date || null,
  }));
}

function normalizeIocs(iocs, threatId) {
  return (iocs || []).filter(i => i.value && i.type).map(i => ({
    threat_id: threatId,
    ioc_type: i.type,
    ioc_value: i.value.trim(),
    confidence: Math.max(0, Math.min(100, i.confidence || 70)),
    malware_family: i.malware_family || null,
    context: i.context || null,
    first_seen: null,
    last_seen: null,
  }));
}

function normalizeTtps(ttps, threatId) {
  return (ttps || []).filter(t => t.mitre_id).map(t => ({
    threat_id: threatId,
    mitre_id: t.mitre_id,
    tactic: t.tactic || null,
    technique: t.technique || null,
    sub_technique: t.sub_technique || null,
    procedure: t.procedure || null,
  }));
}

function normalizeActors(actors, threatId) {
  return (actors || []).filter(a => a.name && a.name.trim()).map(a => ({
    threat_id: threatId,
    name: a.name.trim(),
    aliases: JSON.stringify(a.aliases || []),
    origin_country: a.origin_country || null,
    motivation: a.motivation || 'unknown',
    sophistication: a.sophistication || 'unknown',
    active_since: a.active_since || null,
    description: a.description || null,
  }));
}
