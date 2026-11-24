/**
 * Unified cross-browser background controller.
 * - Chromium (Chrome, Yandex, Opera, Edge, Brave, Vivaldi): bridge-aware PAC via chrome.proxy.settings.
 *   Clears proxy while the local bridge is offline so Chrome NEVER caches 127.0.0.1:10880 as BadProxy,
 *   and immediately applies a fresh revisioned PAC (without "; DIRECT") as soon as the bridge is online.
 * - Firefox / Tor Browser (Gecko): browser.proxy.onRequest with proxyDNS: true.
 * - Ephemeral-safe: persists state in storage, uses alarms for bridge health & update checks.
 */

import {
  buildPacScript,
  extractRootDomain,
  findMatchingRule,
  getActiveRules,
  isLocalOrInternalHost,
  normalizeHostname,
} from './domain-utils.js';
import { extApi, isFirefoxRuntime, loadState, saveState } from './storage.js';
import { checkGitHubReleaseUpdate } from './updater.js';

const UPDATE_ALARM_NAME = 'warp-bridge-auto-update';
const BRIDGE_HEALTH_ALARM = 'warp-bridge-health-sync';

let firefoxCachedState = null;
let bridgeReachable = false;
let pacRevision = 1;
let fastProbeTimer = null;
const recentAutoReloads = new Map();

function stopFastProbe() {
  if (fastProbeTimer !== null) {
    clearInterval(fastProbeTimer);
    fastProbeTimer = null;
  }
}

function ensureFastProbeWhileOffline() {
  if (bridgeReachable || fastProbeTimer !== null) return;
  fastProbeTimer = setInterval(async () => {
    try {
      const state = await loadState();
      if (!state.enabled) {
        stopFastProbe();
        return;
      }
      const { reachable } = await probeLocalBridge(state);
      if (reachable) {
        stopFastProbe();
        await applyProxySettings(state, { reachableOverride: true, forceRefresh: true });
      }
    } catch {
      // ignore transient errors
    }
  }, 3000);
}

async function refreshFirefoxCache(state) {
  firefoxCachedState = state || (await loadState());
}

async function probeLocalBridge(stateArg) {
  const state = stateArg || (await loadState());
  const port = Number(state?.apiPort) || 10881;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1800);
    const resp = await fetch(`http://127.0.0.1:${port}/api/status`, {
      cache: 'no-store',
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!resp.ok) return { reachable: false, data: null };
    const data = await resp.json();
    // Bridge HTTP API is up and usque is running/online
    const ready = Boolean(data && data.state && data.state !== 'offline' && data.state !== 'error');
    return { reachable: ready, data };
  } catch {
    return { reachable: false, data: null };
  }
}

const iconImageDataCache = { on: null, off: null };

function getRelativeIconPaths(isActive) {
  const prefix = isActive ? 'icons/icon-' : 'icons/icon-off-';
  return {
    16: `${prefix}16.png`,
    32: `${prefix}32.png`,
    48: `${prefix}48.png`,
    128: `${prefix}128.png`,
  };
}

async function getIconImageDataSet(isActive) {
  const key = isActive ? 'on' : 'off';
  if (iconImageDataCache[key]) return iconImageDataCache[key];
  if (typeof OffscreenCanvas === 'undefined' || typeof createImageBitmap === 'undefined') {
    return null;
  }
  const paths = getRelativeIconPaths(isActive);
  const result = {};
  for (const sizeStr of ['16', '32', '48']) {
    const size = Number(sizeStr);
    const url = extApi?.runtime?.getURL ? extApi.runtime.getURL(paths[sizeStr]) : paths[sizeStr];
    const resp = await fetch(url);
    const blob = await resp.blob();
    const bmp = await createImageBitmap(blob);
    const canvas = new OffscreenCanvas(size, size);
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, size, size);
    ctx.drawImage(bmp, 0, 0, size, size);
    if (typeof bmp.close === 'function') bmp.close();
    result[size] = ctx.getImageData(0, 0, size, size);
  }
  iconImageDataCache[key] = result;
  return result;
}

async function updateBadge(state, online = bridgeReachable) {
  const actionApi = extApi?.action || extApi?.browserAction;
  if (!actionApi) return;
  try {
    const hasTargets = Boolean(state.routeAllSites || getActiveRules(state).length > 0);
    const isActive = Boolean(state.enabled && hasTargets && online);
    if (actionApi.setBadgeText) {
      await actionApi.setBadgeText({ text: '' });
    }
    if (actionApi.setIcon) {
      const imageData = await getIconImageDataSet(isActive).catch(() => null);
      if (imageData) {
        await actionApi.setIcon({ imageData });
      } else {
        await actionApi.setIcon({ path: getRelativeIconPaths(isActive) });
      }
    }
  } catch (err) {
    console.warn('[PryWarp] Icon update skipped:', err);
  }
}

export async function applyProxySettings(stateArg, options = {}) {
  const state = stateArg || (await loadState());
  const { probe = false, reachableOverride = undefined, forceRefresh = false } = options;

  if (typeof reachableOverride === 'boolean') {
    bridgeReachable = reachableOverride;
  } else if (probe) {
    const res = await probeLocalBridge(state);
    bridgeReachable = res.reachable;
  }

  await updateBadge(state, bridgeReachable);

  if (isFirefoxRuntime()) {
    await refreshFirefoxCache(state);
    return {
      engine: 'firefox-onRequest',
      activeRules: getActiveRules(state).length,
      routeAllSites: Boolean(state.routeAllSites),
      bridgeReachable,
    };
  }

  if (!extApi?.proxy?.settings) {
    return { engine: 'none', activeRules: 0, bridgeReachable };
  }

  const activeRules = getActiveRules(state);
  const hasTargets = Boolean(state.routeAllSites || activeRules.length > 0);
  // Keep browser DIRECT whenever disabled, no targets, or local bridge is offline.
  // This guarantees Chrome never hits ECONNREFUSED and never triggers its 5-minute BadProxy ban.
  if (!state.enabled || !hasTargets || !bridgeReachable) {
    await extApi.proxy.settings.clear({ scope: 'regular' });
    if (state.enabled && hasTargets && !bridgeReachable) {
      ensureFastProbeWhileOffline();
    } else {
      stopFastProbe();
    }
    return {
      engine: 'chromium-pac',
      activeRules: activeRules.length,
      mode: 'direct',
      bridgeReachable,
    };
  }

  stopFastProbe();

  if (forceRefresh) {
    pacRevision = Date.now();
  } else {
    pacRevision += 1;
  }

  const pacScript = buildPacScript(state, { rev: pacRevision });
  await extApi.proxy.settings.set({
    value: {
      mode: 'pac_script',
      pacScript: { data: pacScript },
    },
    scope: 'regular',
  });
  return {
    engine: 'chromium-pac',
    activeRules: activeRules.length,
    mode: 'pac_script',
    bridgeReachable,
    rev: pacRevision,
  };
}

export async function syncUpdateAlarm(stateArg) {
  const state = stateArg || (await loadState());
  if (!extApi?.alarms) return;
  try {
    await extApi.alarms.clear(UPDATE_ALARM_NAME);
    if (state.autoUpdateCheck && state.githubUrl && state.githubUrl.trim()) {
      const hours = Math.max(1, Number(state.autoUpdateIntervalHours) || 24);
      extApi.alarms.create(UPDATE_ALARM_NAME, {
        periodInMinutes: hours * 60,
      });
    }
    extApi.alarms.create(BRIDGE_HEALTH_ALARM, {
      periodInMinutes: 1,
    });
  } catch (err) {
    console.warn('[WARP Bridge] Alarm sync error:', err);
  }
}

async function performUpdateCheck() {
  const state = await loadState();
  const info = await checkGitHubReleaseUpdate(state.githubUrl);
  const next = await saveState({
    lastUpdateCheck: info.checkedAt,
    updateInfo: info,
  });
  return { state: next, updateInfo: info };
}

function handleFirefoxProxyRequest(requestInfo) {
  const state = firefoxCachedState;
  if (!state || !state.enabled || !bridgeReachable) {
    return state?.torFriendlyPassthrough ? null : { type: 'direct' };
  }
  try {
    const url = new URL(requestInfo.url);
    if (state.routeAllSites) {
      if (!isLocalOrInternalHost(url.hostname)) {
        return {
          type: 'socks',
          host: state.socksHost || '127.0.0.1',
          port: Number(state.socksPort) || 10880,
          proxyDNS: true,
        };
      }
      return state.torFriendlyPassthrough ? null : { type: 'direct' };
    }
    const matched = findMatchingRule(url.hostname, state);
    if (matched) {
      return {
        type: 'socks',
        host: state.socksHost || '127.0.0.1',
        port: Number(state.socksPort) || 10880,
        proxyDNS: true,
      };
    }
  } catch {
    // Ignore malformed URLs
  }
  return state.torFriendlyPassthrough ? null : { type: 'direct' };
}

async function checkProxyControl() {
  if (isFirefoxRuntime() || !extApi?.proxy?.settings?.get) {
    return { conflict: false, levelOfControl: 'controllable' };
  }
  try {
    const details = await extApi.proxy.settings.get({ incognito: false });
    const level = details?.levelOfControl || 'controllable';
    return {
      conflict: level === 'controlled_by_other_extensions' || level === 'not_controllable',
      levelOfControl: level,
    };
  } catch {
    return { conflict: false, levelOfControl: 'unknown' };
  }
}

async function handleMessage(message) {
  if (!message || typeof message.type !== 'string') {
    return { ok: false, error: 'Unknown message' };
  }

  switch (message.type) {
    case 'GET_STATE': {
      const state = await loadState();
      const proxyRes = await applyProxySettings(state, { probe: true });
      const proxyControl = await checkProxyControl();
      return {
        ok: true,
        state,
        isFirefox: isFirefoxRuntime(),
        proxyControl,
        bridgeReachable: proxyRes.bridgeReachable,
      };
    }

    case 'SYNC_BRIDGE_PROXY': {
      const state = await loadState();
      const reachable = typeof message.reachable === 'boolean' ? message.reachable : undefined;
      const forceRefresh = Boolean(message.force);
      const proxyRes = await applyProxySettings(state, {
        probe: reachable === undefined,
        reachableOverride: reachable,
        forceRefresh,
      });
      const proxyControl = await checkProxyControl();
      return { ok: true, proxyRes, proxyControl, bridgeReachable: proxyRes.bridgeReachable };
    }

    case 'SET_ENABLED': {
      const next = await saveState({ enabled: Boolean(message.enabled) });
      await applyProxySettings(next, { probe: true, forceRefresh: true });
      const proxyControl = await checkProxyControl();
      return { ok: true, state: next, proxyControl };
    }

    case 'SET_ROUTE_ALL': {
      const next = await saveState({ routeAllSites: Boolean(message.enabled) });
      await applyProxySettings(next, { probe: true, forceRefresh: true });
      const proxyControl = await checkProxyControl();
      return { ok: true, state: next, proxyControl };
    }

    case 'SET_YOUTUBE_ENABLED': {
      const next = await saveState({ youtubeEnabled: Boolean(message.enabled) });
      await applyProxySettings(next, { probe: true, forceRefresh: true });
      return { ok: true, state: next };
    }

    case 'ADD_RULE': {
      const raw = message.domain || '';
      const domain = message.useRoot !== false ? extractRootDomain(raw) : normalizeHostname(raw);
      if (!domain) {
        return { ok: false, error: 'Некорректный домен' };
      }
      const state = await loadState();
      const exists = state.customRules.some((r) => r.domain === domain);
      if (exists) {
        const updatedRules = state.customRules.map((r) =>
          r.domain === domain ? { ...r, enabled: true } : r
        );
        const next = await saveState({ customRules: updatedRules });
        await applyProxySettings(next, { probe: true, forceRefresh: true });
        return { ok: true, state: next, domain, existed: true };
      }
      const nextRules = [
        {
          domain,
          includeSubdomains: message.includeSubdomains !== false,
          enabled: true,
          addedAt: new Date().toISOString(),
        },
        ...state.customRules,
      ];
      const next = await saveState({ customRules: nextRules });
      await applyProxySettings(next, { probe: true, forceRefresh: true });
      return { ok: true, state: next, domain, existed: false };
    }

    case 'TOGGLE_RULE': {
      const state = await loadState();
      const nextRules = state.customRules.map((r) =>
        r.domain === message.domain ? { ...r, enabled: Boolean(message.enabled) } : r
      );
      const next = await saveState({ customRules: nextRules });
      await applyProxySettings(next, { probe: true, forceRefresh: true });
      return { ok: true, state: next };
    }

    case 'REMOVE_RULE': {
      const state = await loadState();
      const nextRules = state.customRules.filter((r) => r.domain !== message.domain);
      const next = await saveState({ customRules: nextRules });
      await applyProxySettings(next, { probe: true, forceRefresh: true });
      return { ok: true, state: next };
    }

    case 'UPDATE_SETTINGS': {
      const allowed = {};
      if (typeof message.settings?.githubUrl === 'string') {
        allowed.githubUrl = message.settings.githubUrl.trim();
      }
      if (typeof message.settings?.autoUpdateCheck === 'boolean') {
        allowed.autoUpdateCheck = message.settings.autoUpdateCheck;
      }
      if (Number.isFinite(Number(message.settings?.autoUpdateIntervalHours))) {
        allowed.autoUpdateIntervalHours = Math.max(1, Number(message.settings.autoUpdateIntervalHours));
      }
      if (typeof message.settings?.socksHost === 'string' && message.settings.socksHost.trim()) {
        allowed.socksHost = message.settings.socksHost.trim();
      }
      if (Number.isFinite(Number(message.settings?.socksPort))) {
        allowed.socksPort = Math.min(65535, Math.max(1, Number(message.settings.socksPort)));
      }
      if (Number.isFinite(Number(message.settings?.apiPort))) {
        allowed.apiPort = Math.min(65535, Math.max(1, Number(message.settings.apiPort)));
      }
      if (['auto', 'awg', 'http2', 'quic'].includes(message.settings?.transportMode)) {
        allowed.transportMode = message.settings.transportMode;
      }
      if (typeof message.settings?.torFriendlyPassthrough === 'boolean') {
        allowed.torFriendlyPassthrough = message.settings.torFriendlyPassthrough;
      }
      const next = await saveState(allowed);
      await applyProxySettings(next, { probe: true, forceRefresh: true });
      await syncUpdateAlarm(next);
      return { ok: true, state: next };
    }

    case 'IMPORT_RULES': {
      const incoming = Array.isArray(message.rules) ? message.rules : [];
      const state = await loadState();
      const map = new Map(state.customRules.map((r) => [r.domain, r]));
      let added = 0;
      for (const item of incoming) {
        const domain = normalizeHostname(typeof item === 'string' ? item : item?.domain);
        if (!domain || map.has(domain)) continue;
        map.set(domain, {
          domain,
          includeSubdomains: typeof item === 'object' ? item.includeSubdomains !== false : true,
          enabled: typeof item === 'object' ? item.enabled !== false : true,
          addedAt: new Date().toISOString(),
        });
        added += 1;
      }
      const next = await saveState({ customRules: Array.from(map.values()) });
      await applyProxySettings(next, { probe: true, forceRefresh: true });
      return { ok: true, state: next, added };
    }

    case 'CHECK_UPDATES': {
      const res = await performUpdateCheck();
      return { ok: true, ...res };
    }

    default:
      return { ok: false, error: `Unsupported message type: ${message.type}` };
  }
}

export function initBackground() {
  if (isFirefoxRuntime()) {
    extApi.proxy.onRequest.addListener(handleFirefoxProxyRequest, { urls: ['<all_urls>'] });
    refreshFirefoxCache();
  }

  extApi.runtime.onInstalled.addListener(async () => {
    const state = await loadState();
    await saveState(state);
    await applyProxySettings(state, { probe: true, forceRefresh: true });
    await syncUpdateAlarm(state);
  });

  if (extApi.runtime.onStartup) {
    extApi.runtime.onStartup.addListener(async () => {
      const state = await loadState();
      await applyProxySettings(state, { probe: true, forceRefresh: true });
      await syncUpdateAlarm(state);
    });
  }

  if (extApi.alarms?.onAlarm) {
    extApi.alarms.onAlarm.addListener(async (alarm) => {
      if (alarm?.name === UPDATE_ALARM_NAME) {
        await performUpdateCheck();
      } else if (alarm?.name === BRIDGE_HEALTH_ALARM) {
        const state = await loadState();
        const prev = bridgeReachable;
        const { reachable } = await probeLocalBridge(state);
        if (reachable !== prev) {
          await applyProxySettings(state, {
            reachableOverride: reachable,
            forceRefresh: reachable,
          });
        }
      }
    });
  }

  if (extApi.tabs?.onUpdated) {
    extApi.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
      if (bridgeReachable) return;
      const candidateUrl = changeInfo.url || (changeInfo.status === 'loading' ? tab?.url : '');
      if (!candidateUrl || !/^https?:\/\//i.test(candidateUrl)) return;
      try {
        const state = await loadState();
        if (!state.enabled) return;
        const host = new URL(candidateUrl).hostname;
        const shouldRoute = state.routeAllSites ? !isLocalOrInternalHost(host) : Boolean(findMatchingRule(host, state));
        if (!shouldRoute) return;
        const { reachable } = await probeLocalBridge(state);
        if (reachable) {
          await applyProxySettings(state, { reachableOverride: true, forceRefresh: true });
          const now = Date.now();
          const prevReload = recentAutoReloads.get(tabId) || 0;
          if (now - prevReload > 15000 && extApi.tabs?.reload) {
            recentAutoReloads.set(tabId, now);
            try {
              await extApi.tabs.reload(tabId);
            } catch {
              // ignore restricted tabs
            }
          }
        }
      } catch {
        // ignore URL/probe errors
      }
    });
  }

  extApi.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    (async () => {
      try {
        const result = await handleMessage(message);
        sendResponse(result);
      } catch (err) {
        console.error('[WARP Bridge] Message handler error:', err);
        sendResponse({ ok: false, error: err?.message || 'Internal error' });
      }
    })();
    return true;
  });

  // Immediately probe bridge and sync proxy on worker wake
  (async () => {
    try {
      const state = await loadState();
      await applyProxySettings(state, { probe: true, forceRefresh: true });
      await syncUpdateAlarm(state);
    } catch (err) {
      console.warn('[WARP Bridge] Startup proxy sync failed:', err);
    }
  })();
}

initBackground();
