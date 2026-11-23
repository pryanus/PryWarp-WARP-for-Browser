/**
 * Cross-browser extension API helper and persistent state management.
 * Supports Chrome, Yandex, Opera, Edge, Brave, Vivaldi, Firefox, and Tor Browser.
 */

export const APP_VERSION = '1.0.1';
export const STORAGE_KEY = 'warpBridgeState';

export const DEFAULT_STATE = Object.freeze({
  enabled: true,
  routeAllSites: false,
  youtubeEnabled: true,
  customRules: [],
  socksHost: '127.0.0.1',
  socksPort: 10880,
  apiPort: 10881,
  transportMode: 'auto', // "auto" | "http2" | "quic"
  torFriendlyPassthrough: false,
  githubUrl: 'https://github.com/pryanus/PryWarp-WARP-for-Browser',
  autoUpdateCheck: false,
  autoUpdateIntervalHours: 24,
  lastUpdateCheck: null,
  updateInfo: null,
});

export const extApi = typeof globalThis.browser !== 'undefined' ? globalThis.browser : globalThis.chrome;

export function isFirefoxRuntime() {
  return Boolean(
    typeof globalThis.browser !== 'undefined' &&
      globalThis.browser?.proxy?.onRequest
  );
}

export async function loadState() {
  if (!extApi?.storage?.local) {
    return { ...DEFAULT_STATE };
  }
  const res = await extApi.storage.local.get(STORAGE_KEY);
  const stored = res?.[STORAGE_KEY];
  if (!stored || typeof stored !== 'object') {
    return { ...DEFAULT_STATE };
  }
  return {
    ...DEFAULT_STATE,
    ...stored,
    customRules: Array.isArray(stored.customRules) ? stored.customRules : [],
  };
}

export async function saveState(partialOrFull) {
  const current = await loadState();
  const next = {
    ...current,
    ...partialOrFull,
  };
  if (extApi?.storage?.local) {
    await extApi.storage.local.set({ [STORAGE_KEY]: next });
  }
  return next;
}
