// Credibility scoring engine
// Score = source_tier (0-40) + technical_richness (0-30) + corroboration (0-20) + specificity (0-10)

const TIER_SCORES = { 1: 40, 2: 32, 3: 24, 4: 16, 5: 8 };

export function scoreCredibility(threat, sourceTier = 5, corroborationCount = 0) {
  let score = 0;
  const breakdown = {};

  // Source tier (0-40)
  const tierScore = TIER_SCORES[sourceTier] || 8;
  breakdown.source_tier = tierScore;
  score += tierScore;

  // Technical richness (0-30)
  let richness = 0;
  if (threat.cves?.length > 0) richness += 12;
  if (threat.iocs?.length > 0) richness += 10;
  if (threat.ttps?.length > 0) richness += 8;
  breakdown.technical_richness = richness;
  score += richness;

  // Corroboration (0-20) — other sources reporting same event
  const corrScore = Math.min(corroborationCount * 5, 20);
  breakdown.corroboration = corrScore;
  score += corrScore;

  // Specificity (0-10)
  let specificity = 0;
  if (threat.threat_actors?.length > 0) specificity += 3;
  if (threat.affected_products?.length > 0) specificity += 3;
  if (threat.geography?.length > 0) specificity += 2;
  if (threat.attack_timeline?.first_seen || threat.attack_timeline?.discovered) specificity += 2;
  breakdown.specificity = specificity;
  score += specificity;

  return {
    score: Math.min(score, 100),
    breakdown,
    label: scoreLabel(score),
  };
}

export function scoreLabel(score) {
  if (score >= 80) return 'Very High';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Moderate';
  if (score >= 20) return 'Low';
  return 'Very Low';
}

export function adjustIocConfidence(iocs, credibilityScore, sourceTier) {
  if (!iocs?.length) return iocs;
  const baseAdjustment = (credibilityScore - 50) / 10; // -5 to +5
  return iocs.map(ioc => ({
    ...ioc,
    confidence: Math.max(10, Math.min(100, (ioc.confidence || 70) + baseAdjustment)),
  }));
}

// Determine severity from credibility + CVSS + threat type
export function normalizeSeverity(analysisData, cvssScores = []) {
  if (analysisData.severity && analysisData.severity !== 'unknown') {
    return analysisData.severity;
  }

  const maxCvss = Math.max(0, ...cvssScores.filter(s => s !== null));
  if (maxCvss >= 9.0) return 'critical';
  if (maxCvss >= 7.0) return 'high';
  if (maxCvss >= 4.0) return 'medium';
  if (maxCvss > 0) return 'low';

  // Infer from threat type and actors
  const { threat_type, threat_actors } = analysisData;
  if (threat_type === 'zero_day') return 'critical';
  if (threat_actors?.some(a => a.sophistication === 'nation_state')) return 'high';
  if (['ransomware', 'apt', 'supply_chain'].includes(threat_type)) return 'high';
  if (['phishing', 'data_breach', 'malware'].includes(threat_type)) return 'medium';

  return 'medium';
}
