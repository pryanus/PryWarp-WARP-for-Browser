import assert from 'node:assert/strict';
import vm from 'node:vm';
import {
  YOUTUBE_DOMAINS,
  buildPacScript,
  compareSemver,
  extractRootDomain,
  findMatchingRule,
  getActiveRules,
  hostMatchesRule,
  normalizeHostname,
  parseGitHubRepoUrl,
} from '../src/shared/domain-utils.js';

// 1. Domain normalization & root extraction
assert.equal(normalizeHostname('https://www.rutracker.org/forum/index.php'), 'www.rutracker.org');
assert.equal(extractRootDomain('https://www.rutracker.org/forum/index.php'), 'rutracker.org');
assert.equal(extractRootDomain('music.youtube.com'), 'youtube.com');
assert.equal(extractRootDomain('sub.shop.co.uk'), 'shop.co.uk');
assert.equal(extractRootDomain('blog.example.com.ru'), 'example.com.ru');
assert.equal(extractRootDomain('*.discord.com'), 'discord.com');
assert.equal(extractRootDomain('127.0.0.1'), null);
assert.equal(extractRootDomain('192.168.100.1'), null);
assert.equal(extractRootDomain('localhost'), null);
assert.equal(extractRootDomain('not a domain'), null);

// 2. Subdomain matching
const rule = { domain: 'rutracker.org', includeSubdomains: true, enabled: true };
assert.equal(hostMatchesRule('rutracker.org', rule), true);
assert.equal(hostMatchesRule('www.rutracker.org', rule), true);
assert.equal(hostMatchesRule('dl.sub.rutracker.org', rule), true);
assert.equal(hostMatchesRule('notrutracker.org', rule), false);
assert.equal(hostMatchesRule('rutracker.org.evil.com', rule), false);

// 3. YouTube preset + custom rules
const state = {
  enabled: true,
  youtubeEnabled: true,
  socksHost: '127.0.0.1',
  socksPort: 10880,
  customRules: [
    { domain: 'rutracker.org', includeSubdomains: true, enabled: true },
    { domain: 'disabled.org', includeSubdomains: true, enabled: false },
  ],
};
assert.equal(getActiveRules(state).length, YOUTUBE_DOMAINS.length + 1);
assert.equal(findMatchingRule('rr2---sn-gvnuxaxjvh-2xxe.googlevideo.com', state)?.preset, 'youtube');
assert.equal(findMatchingRule('i.ytimg.com', state)?.preset, 'youtube');
assert.equal(findMatchingRule('forum.rutracker.org', state)?.domain, 'rutracker.org');
assert.equal(findMatchingRule('disabled.org', state), null);
assert.equal(findMatchingRule('avito.ru', state), null);

// 4. Execute generated PAC script in isolated VM sandbox
const pac = buildPacScript(state);
const sandbox = {
  isPlainHostName: (h) => !h.includes('.'),
  dnsDomainIs: (h, suffix) => h.endsWith(suffix),
};
vm.createContext(sandbox);
vm.runInContext(pac, sandbox);

assert.equal(
  sandbox.FindProxyForURL('https://rr1---sn-test.googlevideo.com/videoplayback', 'rr1---sn-test.googlevideo.com'),
  'SOCKS5 127.0.0.1:10880'
);
assert.equal(
  sandbox.FindProxyForURL('https://www.rutracker.org/', 'www.rutracker.org'),
  'SOCKS5 127.0.0.1:10880'
);
assert.equal(
  sandbox.FindProxyForURL('https://yt3.googleusercontent.com/avatar.jpg', 'yt3.googleusercontent.com'),
  'SOCKS5 127.0.0.1:10880'
);
assert.equal(sandbox.FindProxyForURL('https://www.avito.ru/', 'www.avito.ru'), 'DIRECT');
assert.equal(sandbox.FindProxyForURL('http://127.0.0.1:10881/api/status', '127.0.0.1'), 'DIRECT');
assert.equal(sandbox.FindProxyForURL('http://localhost:3000/', 'localhost'), 'DIRECT');

// Disabled master toggle must always return DIRECT
const disabledPac = buildPacScript({ ...state, enabled: false });
const sb2 = {
  isPlainHostName: (h) => !h.includes('.'),
  dnsDomainIs: (h, suffix) => h.endsWith(suffix),
};
vm.createContext(sb2);
vm.runInContext(disabledPac, sb2);
assert.equal(sb2.FindProxyForURL('https://www.youtube.com/', 'www.youtube.com'), 'DIRECT');

// All-sites mode must route external hosts via SOCKS5 but keep local/LAN DIRECT
const allSitesPac = buildPacScript({ ...state, routeAllSites: true });
const sb3 = {
  isPlainHostName: (h) => !h.includes('.'),
  dnsDomainIs: (h, suffix) => h.endsWith(suffix),
};
vm.createContext(sb3);
vm.runInContext(allSitesPac, sb3);
assert.equal(sb3.FindProxyForURL('https://example.org/', 'example.org'), 'SOCKS5 127.0.0.1:10880');
assert.equal(sb3.FindProxyForURL('https://avito.ru/', 'avito.ru'), 'SOCKS5 127.0.0.1:10880');
assert.equal(sb3.FindProxyForURL('http://127.0.0.1:10881/api/status', '127.0.0.1'), 'DIRECT');
assert.equal(sb3.FindProxyForURL('http://localhost:3000/', 'localhost'), 'DIRECT');
assert.equal(sb3.FindProxyForURL('http://192.168.1.1/', '192.168.1.1'), 'DIRECT');
assert.equal(sb3.FindProxyForURL('http://router.local/', 'router.local'), 'DIRECT');

// 5. GitHub URL parsing & semver comparison
assert.deepEqual(parseGitHubRepoUrl('https://github.com/user/warp-bridge/'), {
  owner: 'user',
  repo: 'warp-bridge',
  cleanUrl: 'https://github.com/user/warp-bridge',
});
assert.deepEqual(parseGitHubRepoUrl('github.com/user/repo.git'), {
  owner: 'user',
  repo: 'repo',
  cleanUrl: 'https://github.com/user/repo',
});
assert.equal(parseGitHubRepoUrl('https://gitlab.com/user/repo'), null);
assert.equal(parseGitHubRepoUrl(''), null);

assert.equal(compareSemver('v1.1.0', '1.0.0'), 1);
assert.equal(compareSemver('1.0.0', 'v1.0.0'), 0);
assert.equal(compareSemver('0.9.5', '1.0.0'), -1);

console.log('ALL DOMAIN & PAC UNIT TESTS PASSED');
