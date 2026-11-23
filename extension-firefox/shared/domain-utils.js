/**
 * Domain normalization, root-domain extraction, matching, and PAC generation.
 * Shared across Chromium MV3, Firefox/Tor WebExtension, popup UI, and unit tests.
 */

export const YOUTUBE_DOMAINS = Object.freeze([
  'youtube.com',
  'googlevideo.com',
  'ytimg.com',
  'ggpht.com',
  'youtu.be',
  'youtubei.googleapis.com',
  'jnn-pa.googleapis.com',
  'youtube-nocookie.com',
  'yt.be',
  'yt3.googleusercontent.com',
  'yt4.googleusercontent.com',
  'gvt1.com',
]);

// Common 2-level public suffixes so root extraction does not collapse them to e.g. "co.uk"
const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
  'com.ru', 'net.ru', 'org.ru', 'pp.ru', 'spb.ru', 'msk.ru',
  'com.ua', 'net.ua', 'org.ua', 'kiev.ua', 'in.ua',
  'com.by', 'com.kz', 'com.tr', 'com.br', 'com.au', 'com.cn',
  'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'co.in', 'com.mx', 'com.sg',
  'co.il', 'com.pl', 'com.ar', 'com.tw', 'com.hk',
]);

const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export function isLocalOrInternalHost(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase().trim();
  if (
    h === 'localhost' ||
    h === '127.0.0.1' ||
    h === '::1' ||
    h.endsWith('.local') ||
    h.endsWith('.internal') ||
    h.endsWith('.lan')
  ) {
    return true;
  }
  if (IPV4_RE.test(h)) {
    const [a, b] = h.split('.').map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
  }
  return false;
}

/**
 * Cleans user input (full URL, host:port, wildcard, whitespace) into a valid hostname.
 * Returns null if input is invalid or internal.
 */
export function normalizeHostname(raw) {
  if (typeof raw !== 'string') return null;
  let value = raw.trim().toLowerCase();
  if (!value) return null;

  // Strip wildcard prefix like *.example.com or .example.com
  value = value.replace(/^\*\./, '').replace(/^\.+/, '');

  // Extract hostname if user pasted a full URL or path
  if (value.includes('://')) {
    try {
      const parsed = new URL(value);
      value = parsed.hostname.toLowerCase();
    } catch {
      return null;
    }
  } else {
    // Strip path/query/hash/port
    value = value.split(/[/?#]/)[0];
    value = value.split(':')[0];
  }

  value = value.replace(/\.+$/, '');
  if (!value || isLocalOrInternalHost(value)) return null;
  if (!DOMAIN_RE.test(value)) return null;
  return value;
}

/**
 * Extracts the registrable root domain (eTLD+1) for most domains.
 * Example: "www.music.youtube.com" -> "youtube.com", "sub.site.co.uk" -> "site.co.uk"
 */
export function extractRootDomain(raw) {
  const host = normalizeHostname(raw);
  if (!host) return null;

  const clean = host.startsWith('www.') ? host.slice(4) : host;
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;

  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (MULTI_PART_TLDS.has(lastTwo)) {
    return parts.length >= 3 ? parts.slice(-3).join('.') : clean;
  }
  return lastTwo;
}

/**
 * Checks whether a hostname matches a rule.
 */
export function hostMatchesRule(hostname, rule) {
  if (!hostname || !rule || !rule.enabled || !rule.domain) return false;
  const host = hostname.toLowerCase();
  const domain = rule.domain.toLowerCase();
  if (host === domain) return true;
  if (rule.includeSubdomains !== false) {
    return host.endsWith(`.${domain}`);
  }
  return false;
}

/**
 * Returns effective rules list (YouTube preset + custom user rules).
 */
export function getActiveRules(state) {
  const rules = [];
  const seen = new Set();

  if (state?.youtubeEnabled) {
    for (const domain of YOUTUBE_DOMAINS) {
      if (!seen.has(domain)) {
        seen.add(domain);
        rules.push({ domain, includeSubdomains: true, enabled: true, preset: 'youtube' });
      }
    }
  }

  const custom = Array.isArray(state?.customRules) ? state.customRules : [];
  for (const item of custom) {
    if (!item || !item.enabled) continue;
    const domain = normalizeHostname(item.domain);
    if (!domain || seen.has(domain)) continue;
    seen.add(domain);
    rules.push({
      domain,
      includeSubdomains: item.includeSubdomains !== false,
      enabled: true,
      preset: null,
    });
  }

  return rules;
}

/**
 * Checks if a hostname is currently covered by active rules (YouTube preset or custom).
 */
export function findMatchingRule(hostname, state) {
  const host = normalizeHostname(hostname);
  if (!host) return null;
  const rules = getActiveRules(state);
  for (const rule of rules) {
    if (hostMatchesRule(host, rule)) return rule;
  }
  return null;
}

/**
 * Generates a compact, zero-dependency PAC script for Chromium browsers.
 * Uses strict SOCKS5 without "; DIRECT" fallback when the bridge is verified online
 * so Chrome never bans 127.0.0.1:10880 in its 5-minute BadProxy cache.
 * A changing `rev` header forces Chromium to flush any stale ProxyRetryInfoMap entries.
 */
export function buildPacScript(state, options = {}) {
  const rules = getActiveRules(state);
  const routeAll = Boolean(state?.routeAllSites);
  const socksHost = (state?.socksHost || '127.0.0.1').replace(/[^a-zA-Z0-9.:-]/g, '');
  const socksPort = Number.isInteger(Number(state?.socksPort)) ? Number(state.socksPort) : 10880;
  const rev = options.rev ?? 1;

  if (!state?.enabled || (!routeAll && rules.length === 0)) {
    return `// rev=${rev}\nfunction FindProxyForURL(url, host) { return "DIRECT"; }`;
  }

  const proxyTarget = `SOCKS5 ${socksHost}:${socksPort}`;

  if (routeAll) {
    return [
      `// rev=${rev} mode=all`,
      'function FindProxyForURL(url, host) {',
      '  if (!host) return "DIRECT";',
      '  var h = host.toLowerCase();',
      '  if (h === "localhost" || h === "127.0.0.1" || h === "::1" || isPlainHostName(h)) return "DIRECT";',
      '  if (/\\.(local|internal|lan)$/.test(h)) return "DIRECT";',
      '  if (/^(10\\.|127\\.|192\\.168\\.|169\\.254\\.)/.test(h)) return "DIRECT";',
      '  if (/^172\\.(1[6-9]|2\\d|3[01])\\./.test(h)) return "DIRECT";',
      `  return ${JSON.stringify(proxyTarget)};`,
      '}',
    ].join('\n');
  }

  const wildcardDomains = rules.filter((r) => r.includeSubdomains !== false).map((r) => r.domain);
  const exactDomains = rules.filter((r) => r.includeSubdomains === false).map((r) => r.domain);

  return [
    `// rev=${rev} mode=selected`,
    'function FindProxyForURL(url, host) {',
    '  if (!host) return "DIRECT";',
    '  var h = host.toLowerCase();',
    '  if (h === "localhost" || h === "127.0.0.1" || h === "::1" || isPlainHostName(h)) return "DIRECT";',
    `  var exact = ${JSON.stringify(exactDomains)};`,
    '  for (var i = 0; i < exact.length; i++) {',
    `    if (h === exact[i]) return ${JSON.stringify(proxyTarget)};`,
    '  }',
    `  var suffixes = ${JSON.stringify(wildcardDomains)};`,
    '  for (var j = 0; j < suffixes.length; j++) {',
    '    var d = suffixes[j];',
    `    if (h === d || dnsDomainIs(h, "." + d)) return ${JSON.stringify(proxyTarget)};`,
    '  }',
    '  return "DIRECT";',
    '}',
  ].join('\n');
}

/**
 * Parses a GitHub repository URL into { owner, repo, cleanUrl } or null.
 */
export function parseGitHubRepoUrl(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const u = new URL(withProto);
    if (u.hostname.toLowerCase() !== 'github.com' && u.hostname.toLowerCase() !== 'www.github.com') {
      return null;
    }
    const parts = u.pathname.replace(/^\/+|\/+$/g, '').split('/');
    if (parts.length < 2) return null;
    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/i, '');
    if (!/^[a-zA-Z0-9_.-]+$/.test(owner) || !/^[a-zA-Z0-9_.-]+$/.test(repo)) {
      return null;
    }
    return {
      owner,
      repo,
      cleanUrl: `https://github.com/${owner}/${repo}`,
    };
  } catch {
    return null;
  }
}

/**
 * Compares two semver strings (e.g. "v1.2.0" vs "1.0.0").
 * Returns 1 if a > b, -1 if a < b, 0 if equal.
 */
export function compareSemver(a, b) {
  const parse = (v) =>
    String(v || '0.0.0')
      .trim()
      .replace(/^v/i, '')
      .split('-')[0]
      .split('.')
      .map((n) => parseInt(n, 10) || 0);
  const pa = parse(a);
  const pb = parse(b);
  const len = Math.max(pa.length, pb.length, 3);
  for (let i = 0; i < len; i += 1) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}
