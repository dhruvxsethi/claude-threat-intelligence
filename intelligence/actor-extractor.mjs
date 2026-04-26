const NAMED_ACTOR_PATTERNS = [
  { re: /\bAPT ?28\b/i, name: 'APT28', origin_country: 'Russia', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bAPT ?29\b/i, name: 'APT29', origin_country: 'Russia', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bAPT ?41\b/i, name: 'APT41', origin_country: 'China', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bAPT ?42\b/i, name: 'APT42', origin_country: 'Iran', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bLazarus\b/i, name: 'Lazarus Group', origin_country: 'North Korea', motivation: 'financial', sophistication: 'nation_state' },
  { re: /\bKimsuky\b/i, name: 'Kimsuky', origin_country: 'North Korea', motivation: 'espionage', sophistication: 'nation_state' },
  { re: /\bSandworm\b/i, name: 'Sandworm', origin_country: 'Russia', motivation: 'sabotage', sophistication: 'nation_state' },
  { re: /\bFIN7\b/i, name: 'FIN7', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
  { re: /\bScattered Spider\b/i, name: 'Scattered Spider', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
  { re: /\bLockBit\b/i, name: 'LockBit', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
  { re: /\bCl0?p\b/i, name: 'Clop', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
  { re: /\bBlackCat\b|\bALPHV\b/i, name: 'ALPHV/BlackCat', origin_country: null, motivation: 'financial', sophistication: 'advanced' },
];

const COUNTRY_ACTOR_PATTERNS = [
  { re: /\bChina(?:-linked|-backed|-nexus)?\b|\bChinese state-sponsored\b/i, name: 'China-linked activity', origin_country: 'China' },
  { re: /\bRussia(?:n)?(?:-linked|-backed|-nexus)?\b|\bRussian state-sponsored\b/i, name: 'Russia-linked activity', origin_country: 'Russia' },
  { re: /\bNorth Korea(?:n)?(?:-linked|-backed|-nexus)?\b|\bDPRK(?:-linked|-backed|-nexus)?\b/i, name: 'North Korea-linked activity', origin_country: 'North Korea' },
  { re: /\bIran(?:ian)?(?:-linked|-backed|-nexus)?\b|\bIranian state-sponsored\b/i, name: 'Iran-linked activity', origin_country: 'Iran' },
];

export function deriveActorsFromText({ title = '', summary = '', content = '' } = {}) {
  const text = `${title}\n${summary}\n${content}`.trim();
  if (!text) return [];

  const actors = [];
  for (const pattern of NAMED_ACTOR_PATTERNS) {
    if (pattern.re.test(text)) {
      actors.push({
        name: pattern.name,
        aliases: [],
        origin_country: pattern.origin_country,
        motivation: pattern.motivation,
        sophistication: pattern.sophistication,
        active_since: null,
        description: `Derived from explicit source text mentioning ${pattern.name}.`,
        derived: true,
      });
    }
  }

  if (/state-sponsored|nation-state|apt|espionage/i.test(text)) {
    for (const pattern of COUNTRY_ACTOR_PATTERNS) {
      if (pattern.re.test(text)) {
        actors.push({
          name: pattern.name,
          aliases: [],
          origin_country: pattern.origin_country,
          motivation: 'espionage',
          sophistication: 'nation_state',
          active_since: null,
          description: `Derived from explicit country-linked activity in source text.`,
          derived: true,
        });
      }
    }
  }

  return mergeActors(actors);
}

export function mergeActors(...groups) {
  const byName = new Map();
  for (const actor of groups.flat().filter(Boolean)) {
    const name = String(actor.name || '').trim();
    if (!name) continue;
    const key = name.toLowerCase();
    const existing = byName.get(key) || {
      name,
      aliases: [],
      origin_country: null,
      motivation: 'unknown',
      sophistication: 'unknown',
      active_since: null,
      description: null,
      derived: false,
    };
    byName.set(key, {
      ...existing,
      ...actor,
      name,
      aliases: [...new Set([...(existing.aliases || []), ...(actor.aliases || [])].filter(Boolean))],
      origin_country: actor.origin_country || existing.origin_country,
      motivation: actor.motivation || existing.motivation,
      sophistication: actor.sophistication || existing.sophistication,
      description: actor.description || existing.description,
      derived: existing.derived || actor.derived || false,
    });
  }
  return [...byName.values()];
}
