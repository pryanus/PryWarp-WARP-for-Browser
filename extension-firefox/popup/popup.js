/**
 * WARP Bridge Popup UI Controller (Cross-Browser Chromium MV3 + Firefox/Tor).
 * Includes live status polling, proxy conflict detection, and 3-tab DNS Switcher layout.
 */

import {
  extractRootDomain,
  findMatchingRule,
  normalizeHostname,
  parseGitHubRepoUrl,
} from '../shared/domain-utils.js';
import { APP_VERSION, extApi } from '../shared/storage.js';

const el = {
  versionBadge: document.getElementById('versionBadge'),
  githubHeaderBtn: document.getElementById('githubHeaderBtn'),
  bridgeDot: document.getElementById('bridgeDot'),
  bridgeStateText: document.getElementById('bridgeStateText'),
  bridgeMeta: document.getElementById('bridgeMeta'),
  bridgeOfflineHint: document.getElementById('bridgeOfflineHint'),
  hintApiAddr: document.getElementById('hintApiAddr'),
  statusActions: document.getElementById('statusActions'),
  offlineActions: document.getElementById('offlineActions'),
  retryBridgeBtn: document.getElementById('retryBridgeBtn'),
  reconnectBtn: document.getElementById('reconnectBtn'),
  masterToggleBtn: document.getElementById('masterToggleBtn'),

  tabSites: document.getElementById('tabSites'),
  tabSettings: document.getElementById('tabSettings'),
  tabUpdates: document.getElementById('tabUpdates'),
  sitesCount: document.getElementById('sitesCount'),
  updateDot: document.getElementById('updateDot'),
  panelSites: document.getElementById('panelSites'),
  panelSettings: document.getElementById('panelSettings'),
  panelUpdates: document.getElementById('panelUpdates'),

  currentSiteCard: document.getElementById('currentSiteCard'),
  currentDomainText: document.getElementById('currentDomainText'),
  quickAddCurrentBtn: document.getElementById('quickAddCurrentBtn'),
  quickAddLabel: document.getElementById('quickAddLabel'),

  addDomainForm: document.getElementById('addDomainForm'),
  domainInput: document.getElementById('domainInput'),
  domainHint: document.getElementById('domainHint'),
  youtubeToggleBtn: document.getElementById('youtubeToggleBtn'),
  youtubeStatusBadge: document.getElementById('youtubeStatusBadge'),
  routeModeCard: document.getElementById('routeModeCard'),
  routeModeTitle: document.getElementById('routeModeTitle'),
  routeModeDesc: document.getElementById('routeModeDesc'),
  routeAllBtn: document.getElementById('routeAllBtn'),
  customRulesList: document.getElementById('customRulesList'),
  emptyRulesState: document.getElementById('emptyRulesState'),

  githubUrlInput: document.getElementById('githubUrlInput'),
  saveGithubBtn: document.getElementById('saveGithubBtn'),
  checkUpdatesBtn: document.getElementById('checkUpdatesBtn'),
  openReleaseLink: document.getElementById('openReleaseLink'),
  updateStatusText: document.getElementById('updateStatusText'),
  autoUpdateCheckbox: document.getElementById('autoUpdateCheckbox'),
  updateIntervalSelect: document.getElementById('updateIntervalSelect'),

  transportSelect: document.getElementById('transportSelect'),
  socksPortInput: document.getElementById('socksPortInput'),
  apiPortInput: document.getElementById('apiPortInput'),
  torPassthroughCheckbox: document.getElementById('torPassthroughCheckbox'),
  saveSettingsBtn: document.getElementById('saveSettingsBtn'),
  exportRulesBtn: document.getElementById('exportRulesBtn'),
  importRulesBtn: document.getElementById('importRulesBtn'),
  importFileInput: document.getElementById('importFileInput'),

  footerInfo: document.getElementById('footerInfo'),
  toastText: document.getElementById('toastText'),
};

let currentState = null;
let proxyConflict = false;
let currentTabRootDomain = null;
let currentTabId = null;
let lastBridgeReachable = null;
let toastTimer = null;
let pollTimer = null;

function showToast(text) {
  el.toastText.textContent = text;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.toastText.textContent = '';
  }, 2600);
}

async function sendBg(message) {
  if (!extApi?.runtime?.sendMessage) {
    return { ok: false, error: 'Extension runtime unavailable' };
  }
  return await extApi.runtime.sendMessage(message);
}

function getApiBase() {
  const port = Number(currentState?.apiPort) || 10881;
  return `http://127.0.0.1:${port}`;
}

function switchTab(tabName) {
  const tabs = [
    { name: 'sites', btn: el.tabSites, panel: el.panelSites },
    { name: 'settings', btn: el.tabSettings, panel: el.panelSettings },
    { name: 'updates', btn: el.tabUpdates, panel: el.panelUpdates },
  ];
  for (const t of tabs) {
    const active = t.name === tabName;
    t.btn.classList.toggle('active', active);
    t.btn.setAttribute('aria-selected', String(active));
    t.panel.hidden = !active;
  }
}

function renderCustomRules(state) {
  el.customRulesList.replaceChildren();
  const rules = Array.isArray(state.customRules) ? state.customRules : [];
  el.emptyRulesState.hidden = rules.length > 0;

  for (const rule of rules) {
    const card = document.createElement('div');
    card.className = `card rule-card${rule.enabled ? '' : ' is-disabled'}`;

    const body = document.createElement('div');
    body.className = 'rule-body';

    const head = document.createElement('div');
    head.className = 'rule-head';

    const title = document.createElement('span');
    title.className = 'rule-title';
    title.textContent = rule.domain;

    const st = document.createElement('span');
    st.className = `state-text ${rule.enabled ? 'state-ok' : 'state-off'}`;
    st.textContent = rule.enabled ? 'В обходе' : 'Пауза';

    head.append(title, st);

    const sub = document.createElement('p');
    sub.className = 'rule-domains';
    sub.textContent = rule.includeSubdomains !== false ? 'Основной домен + все поддомены' : 'Только точный домен';

    body.append(head, sub);

    const btns = document.createElement('div');
    btns.className = 'rule-btns';

    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'btn btn-outline btn-compact';
    toggleBtn.textContent = rule.enabled ? 'Выкл' : 'Вкл';
    toggleBtn.addEventListener('click', async () => {
      const res = await sendBg({
        type: 'TOGGLE_RULE',
        domain: rule.domain,
        enabled: !rule.enabled,
      });
      if (res?.ok) {
        currentState = res.state;
        renderState();
      }
    });

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'btn btn-danger btn-compact';
    delBtn.textContent = 'Удалить';
    delBtn.addEventListener('click', async () => {
      const res = await sendBg({ type: 'REMOVE_RULE', domain: rule.domain });
      if (res?.ok) {
        currentState = res.state;
        renderState();
        showToast(`Удалён ${rule.domain}`);
      }
    });

    btns.append(toggleBtn, delBtn);
    card.append(body, btns);
    el.customRulesList.appendChild(card);
  }
}

function renderCurrentTabAction() {
  if (!currentTabRootDomain || !currentState) {
    el.currentSiteCard.hidden = true;
    return;
  }

  el.currentSiteCard.hidden = false;
  el.currentDomainText.textContent = currentTabRootDomain;

  const matched = findMatchingRule(currentTabRootDomain, currentState);
  const customMatch = (currentState.customRules || []).find((r) => r.domain === currentTabRootDomain);

  if (matched?.preset === 'youtube') {
    el.quickAddCurrentBtn.className = 'btn btn-outline';
    el.quickAddCurrentBtn.disabled = true;
    el.quickAddLabel.textContent = 'Уже в YouTube';
  } else if (customMatch && customMatch.enabled) {
    el.quickAddCurrentBtn.className = 'btn btn-danger';
    el.quickAddCurrentBtn.disabled = false;
    el.quickAddLabel.textContent = 'Убрать';
  } else {
    el.quickAddCurrentBtn.className = 'btn btn-primary';
    el.quickAddCurrentBtn.disabled = false;
    el.quickAddLabel.textContent = 'Добавить сайт';
  }
}

function renderUpdateInfo(state) {
  const info = state.updateInfo;
  el.openReleaseLink.hidden = true;
  el.updateDot.hidden = true;
  el.updateStatusText.className = 'update-meta';

  if (!info) {
    el.updateStatusText.textContent = state.githubUrl
      ? 'Ещё не проверялось'
      : 'Ссылка на GitHub не задана';
    return;
  }

  const when = info.checkedAt ? new Date(info.checkedAt).toLocaleString('ru-RU') : '';
  if (info.status === 'available') {
    el.updateDot.hidden = false;
    el.updateStatusText.className = 'update-meta is-available';
    el.updateStatusText.textContent = `${info.message}${when ? ` · ${when}` : ''}`;
    if (info.releaseUrl) {
      el.openReleaseLink.href = info.releaseUrl;
      el.openReleaseLink.hidden = false;
    }
  } else if (info.status === 'error') {
    el.updateStatusText.className = 'update-meta is-error';
    el.updateStatusText.textContent = info.message || 'Ошибка проверки';
  } else {
    el.updateStatusText.textContent = `${info.message || 'Актуальная версия'}${when ? ` · ${when}` : ''}`;
  }
}

function renderState() {
  if (!currentState) return;
  const st = currentState;

  el.versionBadge.textContent = `v${APP_VERSION}`;
  el.footerInfo.textContent = `PryWarp — WARP for Browser · v${APP_VERSION}`;

  el.masterToggleBtn.textContent = st.enabled ? 'Выключить' : 'Включить';
  el.masterToggleBtn.className = st.enabled ? 'btn btn-danger-solid' : 'btn btn-success';
  el.masterToggleBtn.setAttribute('aria-pressed', String(Boolean(st.enabled)));

  const routeAll = Boolean(st.routeAllSites);
  el.routeModeCard.classList.toggle('is-all', routeAll);
  el.routeModeTitle.textContent = routeAll ? 'Все сайты через WARP' : 'Только избранные сайты';
  el.routeModeDesc.textContent = routeAll
    ? 'Весь трафик браузера через WARP (кроме локальных адресов)'
    : 'Через WARP идут YouTube и сайты из списка ниже';
  el.routeAllBtn.textContent = routeAll ? 'К избранным' : 'Ко всем сайтам';
  el.routeAllBtn.className = routeAll ? 'btn btn-success btn-compact' : 'btn btn-primary btn-compact';
  el.routeAllBtn.setAttribute('aria-pressed', String(routeAll));

  el.youtubeToggleBtn.textContent = st.youtubeEnabled ? 'Выкл' : 'Вкл';
  el.youtubeToggleBtn.setAttribute('aria-pressed', String(Boolean(st.youtubeEnabled)));
  el.youtubeStatusBadge.textContent = st.youtubeEnabled ? 'В обходе' : 'Отключён';
  el.youtubeStatusBadge.className = `state-text ${st.youtubeEnabled ? 'state-ok' : 'state-off'}`;

  const activeGroups = (st.youtubeEnabled ? 1 : 0) + (st.customRules || []).filter((r) => r.enabled).length;
  el.sitesCount.textContent = routeAll ? '(Все)' : `(${activeGroups})`;

  const parsedGh = parseGitHubRepoUrl(st.githubUrl);
  el.githubHeaderBtn.title = parsedGh
    ? `Открыть ${parsedGh.cleanUrl}`
    : 'Указать ссылку на GitHub во вкладке Обновление';

  el.githubUrlInput.value = st.githubUrl || '';
  el.autoUpdateCheckbox.checked = Boolean(st.autoUpdateCheck);
  el.updateIntervalSelect.value = String(st.autoUpdateIntervalHours || 24);
  el.transportSelect.value = st.transportMode || 'auto';
  el.socksPortInput.value = String(st.socksPort || 10880);
  el.apiPortInput.value = String(st.apiPort || 10881);
  el.torPassthroughCheckbox.checked = Boolean(st.torFriendlyPassthrough);
  el.hintApiAddr.textContent = `127.0.0.1:${st.apiPort || 10881}`;

  renderCustomRules(st);
  renderCurrentTabAction();
  renderUpdateInfo(st);
}

function renderBridgeStatus(data, reachable) {
  if (proxyConflict) {
    el.bridgeDot.className = 'status-dot dot-err';
    el.bridgeStateText.textContent = 'Конфликт прокси в браузере';
    el.bridgeMeta.textContent = 'Другое VPN-расширение перехватило управление прокси';
    el.statusActions.hidden = true;
    el.offlineActions.hidden = false;
    el.bridgeOfflineHint.hidden = false;
    el.bridgeOfflineHint.textContent = 'Отключи другие VPN/прокси-расширения в браузере (например, VeePN), иначе браузер не даёт PryWarp управлять маршрутами';
    return;
  }

  if (!reachable || !data) {
    el.bridgeDot.className = 'status-dot dot-err';
    el.bridgeStateText.textContent = 'Мост не запущен';
    el.bridgeMeta.textContent = 'Браузер идёт напрямую (без WARP)';
    el.statusActions.hidden = true;
    el.offlineActions.hidden = false;
    el.bridgeOfflineHint.hidden = false;
    return;
  }

  el.statusActions.hidden = false;
  el.offlineActions.hidden = true;
  el.bridgeOfflineHint.hidden = true;
  if (
    data.transport_mode &&
    ['auto', 'awg', 'http2', 'quic'].includes(data.transport_mode) &&
    document.activeElement !== el.transportSelect &&
    el.transportSelect.value !== data.transport_mode &&
    !el.transportSelect.disabled
  ) {
    el.transportSelect.value = data.transport_mode;
  }
  const transportLabel =
    data.transport === 'awg'
      ? 'AmneziaWG'
      : data.transport === 'http2'
        ? 'HTTP/2'
        : 'QUIC';
  const coloPart = data.colo ? `${data.colo} · ` : '';
  const latencyPart = Number.isFinite(data.latency_ms) ? `${data.latency_ms} мс · ` : '';

  if (data.state === 'online' && data.warp !== 'off') {
    el.bridgeDot.className = currentState?.enabled ? 'status-dot dot-ok' : 'status-dot dot-err';
    el.bridgeStateText.textContent = currentState?.enabled ? 'WARP работает' : 'WARP на паузе';
    el.bridgeMeta.textContent = `${coloPart}${transportLabel} · ${latencyPart}${data.socks_host}:${data.socks_port}`;
  } else if (data.state === 'connecting' || data.state === 'reconnecting' || data.state === 'starting') {
    el.bridgeDot.className = 'status-dot dot-warn';
    el.bridgeStateText.textContent = 'Подключение WARP...';
    el.bridgeMeta.textContent = `${transportLabel} · ${data.last_error || 'поднимаем туннель'}`;
  } else {
    el.bridgeDot.className = 'status-dot dot-err';
    el.bridgeStateText.textContent = 'Ошибка туннеля WARP';
    el.bridgeMeta.textContent = data.last_error || 'Туннель недоступен';
  }
}

async function reloadActiveTabIfProxied() {
  if (!currentTabId || !currentTabRootDomain || !currentState?.enabled) return false;
  if (!findMatchingRule(currentTabRootDomain, currentState)) return false;
  try {
    if (extApi?.tabs?.reload) {
      await extApi.tabs.reload(currentTabId);
      return true;
    }
  } catch {
    // ignore reload errors on restricted tabs
  }
  return false;
}

async function pollBridgeStatus(options = {}) {
  const { forceSync = false, reloadTabOnOnline = false } = options;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const resp = await fetch(`${getApiBase()}/api/status`, {
      cache: 'no-store',
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!resp.ok) {
      renderBridgeStatus(null, false);
      if (lastBridgeReachable !== false || forceSync) {
        lastBridgeReachable = false;
        await sendBg({ type: 'SYNC_BRIDGE_PROXY', reachable: false, force: forceSync });
      }
      return false;
    }
    const data = await resp.json();
    const ready = Boolean(data && data.state && data.state !== 'offline' && data.state !== 'error');
    const justCameOnline = lastBridgeReachable === false && ready;
    if (lastBridgeReachable !== ready || forceSync) {
      lastBridgeReachable = ready;
      const syncRes = await sendBg({
        type: 'SYNC_BRIDGE_PROXY',
        reachable: ready,
        force: ready || forceSync,
      });
      if (syncRes?.proxyControl) {
        proxyConflict = Boolean(syncRes.proxyControl.conflict);
      }
    }
    renderBridgeStatus(data, true);
    if (ready && reloadTabOnOnline) {
      const reloaded = await reloadActiveTabIfProxied();
      if (reloaded) showToast('WARP готов — вкладка обновлена');
    } else if (justCameOnline && currentTabRootDomain && findMatchingRule(currentTabRootDomain, currentState)) {
      showToast('WARP подключён — обнови вкладку (F5)');
    }
    return ready;
  } catch {
    renderBridgeStatus(null, false);
    if (lastBridgeReachable !== false || forceSync) {
      lastBridgeReachable = false;
      await sendBg({ type: 'SYNC_BRIDGE_PROXY', reachable: false, force: forceSync });
    }
    return false;
  }
}

async function detectCurrentTab() {
  try {
    if (!extApi?.tabs?.query) return;
    const tabs = await extApi.tabs.query({ active: true, currentWindow: true });
    const tab = tabs?.[0];
    const urlStr = tab?.url;
    currentTabId = tab?.id ?? null;
    if (!urlStr || !/^https?:\/\//i.test(urlStr)) {
      currentTabRootDomain = null;
      return;
    }
    const parsed = new URL(urlStr);
    currentTabRootDomain = extractRootDomain(parsed.hostname);
  } catch {
    currentTabId = null;
    currentTabRootDomain = null;
  }
}

async function waitForBridgeOnline(maxWaitMs = 12000) {
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2000);
      const resp = await fetch(`${getApiBase()}/api/status`, {
        cache: 'no-store',
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (resp.ok) {
        const data = await resp.json();
        renderBridgeStatus(data, true);
        if (data.state === 'online' && data.warp !== 'off') {
          lastBridgeReachable = true;
          await sendBg({ type: 'SYNC_BRIDGE_PROXY', reachable: true, force: true });
          return data;
        }
        if (data.state === 'error') {
          return data;
        }
      }
    } catch {
      // bridge momentarily restarting
    }
    await new Promise((r) => setTimeout(r, 350));
  }
  return null;
}

async function applyBridgeTransportSwitch(mode) {
  const label =
    mode === 'awg'
      ? 'AmneziaWG'
      : mode === 'http2'
        ? 'HTTP/2'
        : mode === 'quic'
          ? 'QUIC'
          : 'Авто';
  el.transportSelect.disabled = true;
  el.reconnectBtn.disabled = true;
  showToast(`Переключаю туннель на ${label}...`);
  try {
    const resp = await fetch(`${getApiBase()}/api/transport`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    });
    if (!resp.ok) {
      showToast('Мост не отвечает');
      return false;
    }
    const initData = await resp.json();
    renderBridgeStatus(initData, true);
    if (initData.state === 'online' && initData.warp !== 'off') {
      await sendBg({ type: 'SYNC_BRIDGE_PROXY', reachable: true, force: true });
      const reloaded = await reloadActiveTabIfProxied();
      showToast(reloaded ? `Туннель ${label} активен — вкладка обновлена` : `Туннель ${label} активен`);
      return true;
    }
    const readyData = await waitForBridgeOnline(12000);
    if (readyData && readyData.state === 'online') {
      const activeLabel =
        readyData.transport === 'awg'
          ? 'AmneziaWG'
          : readyData.transport === 'http2'
            ? 'HTTP/2'
            : 'QUIC';
      const reloaded = await reloadActiveTabIfProxied();
      showToast(reloaded ? `Туннель ${activeLabel} готов — вкладка обновлена` : `Туннель ${activeLabel} готов`);
      return true;
    }
    showToast('Туннель переподключается...');
    return false;
  } catch {
    renderBridgeStatus(null, false);
    showToast('Сначала запусти мост');
    return false;
  } finally {
    el.transportSelect.disabled = false;
    el.reconnectBtn.disabled = false;
  }
}

async function saveAllSettings(toastMsg = 'Сохранено') {
  const rawGithub = el.githubUrlInput.value.trim();
  if (rawGithub && !parseGitHubRepoUrl(rawGithub)) {
    showToast('Неверный URL GitHub');
    el.githubUrlInput.focus();
    return false;
  }

  const prevTransport = currentState?.transportMode || 'auto';
  const nextSettings = {
    githubUrl: rawGithub ? parseGitHubRepoUrl(rawGithub).cleanUrl : '',
    autoUpdateCheck: el.autoUpdateCheckbox.checked,
    autoUpdateIntervalHours: Number(el.updateIntervalSelect.value) || 24,
    transportMode: el.transportSelect.value,
    socksPort: Number(el.socksPortInput.value) || 10880,
    apiPort: Number(el.apiPortInput.value) || 10881,
    torFriendlyPassthrough: el.torPassthroughCheckbox.checked,
  };

  const res = await sendBg({ type: 'UPDATE_SETTINGS', settings: nextSettings });
  if (res?.ok) {
    currentState = res.state;
    proxyConflict = Boolean(res.proxyControl?.conflict);
    renderState();

    if (nextSettings.transportMode !== prevTransport) {
      await applyBridgeTransportSwitch(nextSettings.transportMode);
    } else {
      showToast(toastMsg);
    }
    return true;
  }
  return false;
}

function bindEvents() {
  el.tabSites.addEventListener('click', () => switchTab('sites'));
  el.tabSettings.addEventListener('click', () => switchTab('settings'));
  el.tabUpdates.addEventListener('click', () => switchTab('updates'));

  el.githubHeaderBtn.addEventListener('click', async () => {
    const parsed = parseGitHubRepoUrl(currentState?.githubUrl || '');
    if (parsed) {
      if (extApi?.tabs?.create) {
        await extApi.tabs.create({ url: parsed.cleanUrl });
      } else {
        window.open(parsed.cleanUrl, '_blank', 'noopener,noreferrer');
      }
    } else {
      switchTab('updates');
      el.githubUrlInput.focus();
      showToast('Укажи ссылку на GitHub');
    }
  });

  el.masterToggleBtn.addEventListener('click', async () => {
    const nextEnabled = !currentState.enabled;
    const res = await sendBg({ type: 'SET_ENABLED', enabled: nextEnabled });
    if (res?.ok) {
      currentState = res.state;
      proxyConflict = Boolean(res.proxyControl?.conflict);
      renderState();
      await pollBridgeStatus({ forceSync: true, reloadTabOnOnline: nextEnabled });
      showToast(nextEnabled ? 'Обход включён' : 'Обход выключен');
    }
  });

  el.routeAllBtn.addEventListener('click', async () => {
    const nextAll = !currentState.routeAllSites;
    const res = await sendBg({ type: 'SET_ROUTE_ALL', enabled: nextAll });
    if (res?.ok) {
      currentState = res.state;
      proxyConflict = Boolean(res.proxyControl?.conflict);
      renderState();
      await pollBridgeStatus({ forceSync: true, reloadTabOnOnline: nextAll });
      showToast(nextAll ? 'Режим: все сайты через WARP' : 'Режим: только избранные сайты');
    }
  });

  el.youtubeToggleBtn.addEventListener('click', async () => {
    const nextVal = !currentState.youtubeEnabled;
    const res = await sendBg({ type: 'SET_YOUTUBE_ENABLED', enabled: nextVal });
    if (res?.ok) {
      currentState = res.state;
      renderState();
      showToast(nextVal ? 'YouTube в обходе' : 'YouTube напрямую');
    }
  });

  el.retryBridgeBtn.addEventListener('click', async () => {
    el.retryBridgeBtn.disabled = true;
    showToast('Проверяю мост...');
    try {
      await pollBridgeStatus({ forceSync: true, reloadTabOnOnline: true });
    } finally {
      el.retryBridgeBtn.disabled = false;
    }
  });

  el.reconnectBtn.addEventListener('click', async () => {
    const prevLabel = el.reconnectBtn.textContent;
    el.reconnectBtn.disabled = true;
    el.reconnectBtn.textContent = 'Сброс...';
    el.bridgeDot.className = 'status-dot dot-warn';
    el.bridgeStateText.textContent = 'Переподключение WARP...';
    showToast('Сбрасываю и переподключаю туннель...');
    try {
      const resp = await fetch(`${getApiBase()}/api/reconnect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      if (resp.ok) {
        const data = await resp.json();
        renderBridgeStatus(data, true);
        const readyData =
          data.state === 'online' && data.warp !== 'off'
            ? data
            : await waitForBridgeOnline(12000);
        if (readyData && readyData.state === 'online') {
          await sendBg({ type: 'SYNC_BRIDGE_PROXY', reachable: true, force: true });
          const reloaded = await reloadActiveTabIfProxied();
          const latText = Number.isFinite(readyData.latency_ms) ? ` (${readyData.latency_ms} мс)` : '';
          showToast(
            reloaded
              ? `WARP переподключён${latText} — вкладка обновлена`
              : `WARP переподключён${latText}`
          );
        } else {
          showToast('Туннель переподключается...');
        }
      } else {
        renderBridgeStatus(null, false);
        showToast('Мост не отвечает');
      }
    } catch {
      renderBridgeStatus(null, false);
      showToast('Сначала запусти мост');
    } finally {
      el.reconnectBtn.textContent = prevLabel;
      el.reconnectBtn.disabled = false;
    }
  });

  el.quickAddCurrentBtn.addEventListener('click', async () => {
    if (!currentTabRootDomain) return;
    const existing = (currentState.customRules || []).find((r) => r.domain === currentTabRootDomain);
    if (existing && existing.enabled) {
      const res = await sendBg({ type: 'REMOVE_RULE', domain: currentTabRootDomain });
      if (res?.ok) {
        currentState = res.state;
        renderState();
        showToast(`Убран ${currentTabRootDomain}`);
      }
    } else {
      const res = await sendBg({
        type: 'ADD_RULE',
        domain: currentTabRootDomain,
        useRoot: true,
        includeSubdomains: true,
      });
      if (res?.ok) {
        currentState = res.state;
        renderState();
        showToast(`Добавлен ${res.domain}`);
      }
    }
  });

  el.addDomainForm.addEventListener('submit', async (evt) => {
    evt.preventDefault();
    const raw = el.domainInput.value.trim();
    const cleaned = extractRootDomain(raw) || normalizeHostname(raw);
    if (!cleaned) {
      el.domainHint.className = 'helper-text is-error';
      el.domainHint.textContent = 'Введи корректный домен, например rutracker.org';
      return;
    }
    el.domainHint.className = 'helper-text';
    el.domainHint.textContent = 'Достаточно основного домена — все поддомены подключатся сами';

    const res = await sendBg({
      type: 'ADD_RULE',
      domain: raw,
      useRoot: true,
      includeSubdomains: true,
    });
    if (res?.ok) {
      currentState = res.state;
      el.domainInput.value = '';
      renderState();
      showToast(res.existed ? `${res.domain} уже в списке` : `Добавлен ${res.domain}`);
    } else {
      el.domainHint.className = 'helper-text is-error';
      el.domainHint.textContent = res?.error || 'Не удалось добавить домен';
    }
  });

  el.transportSelect.addEventListener('change', async () => {
    const mode = el.transportSelect.value;
    const res = await sendBg({
      type: 'UPDATE_SETTINGS',
      settings: { transportMode: mode },
    });
    if (res?.ok) {
      currentState = res.state;
      renderState();
    }
    await applyBridgeTransportSwitch(mode);
  });

  el.saveSettingsBtn.addEventListener('click', async () => {
    await saveAllSettings('Настройки сохранены');
  });

  el.saveGithubBtn.addEventListener('click', async () => {
    await saveAllSettings('Ссылка GitHub сохранена');
  });

  el.autoUpdateCheckbox.addEventListener('change', async () => {
    await saveAllSettings(el.autoUpdateCheckbox.checked ? 'Автопроверка включена' : 'Автопроверка выключена');
  });

  el.updateIntervalSelect.addEventListener('change', async () => {
    await saveAllSettings('Интервал сохранён');
  });

  el.checkUpdatesBtn.addEventListener('click', async () => {
    const rawGithub = el.githubUrlInput.value.trim();
    if (rawGithub && parseGitHubRepoUrl(rawGithub)) {
      const saved = await sendBg({
        type: 'UPDATE_SETTINGS',
        settings: { githubUrl: parseGitHubRepoUrl(rawGithub).cleanUrl },
      });
      if (saved?.ok) currentState = saved.state;
    }

    el.checkUpdatesBtn.disabled = true;
    el.updateStatusText.textContent = 'Проверка...';
    try {
      const res = await sendBg({ type: 'CHECK_UPDATES' });
      if (res?.ok) {
        currentState = res.state;
        renderState();
        showToast(res.updateInfo?.message || 'Проверка завершена');
      }
    } finally {
      el.checkUpdatesBtn.disabled = false;
    }
  });

  el.exportRulesBtn.addEventListener('click', () => {
    if (!currentState) return;
    const payload = {
      version: APP_VERSION,
      youtubeEnabled: currentState.youtubeEnabled,
      customRules: currentState.customRules || [],
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'prywarp-bridge-sites.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast('Список экспортирован');
  });

  el.importRulesBtn.addEventListener('click', () => {
    el.importFileInput.click();
  });

  el.importFileInput.addEventListener('change', async () => {
    const file = el.importFileInput.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const list = Array.isArray(parsed) ? parsed : parsed?.customRules;
      if (!Array.isArray(list)) {
        showToast('Неверный формат JSON');
        return;
      }
      const res = await sendBg({ type: 'IMPORT_RULES', rules: list });
      if (res?.ok) {
        currentState = res.state;
        renderState();
        showToast(`Импортировано: ${res.added}`);
      }
    } catch {
      showToast('Ошибка чтения файла');
    } finally {
      el.importFileInput.value = '';
    }
  });
}

async function init() {
  bindEvents();
  const res = await sendBg({ type: 'GET_STATE' });
  if (res?.ok && res.state) {
    currentState = res.state;
    proxyConflict = Boolean(res.proxyControl?.conflict);
  }
  await detectCurrentTab();
  renderState();
  await pollBridgeStatus();

  // Auto-refresh live bridge status every 2.5s while popup is open
  pollTimer = setInterval(() => {
    pollBridgeStatus();
  }, 2500);
}

window.addEventListener('unload', () => {
  if (pollTimer) clearInterval(pollTimer);
});

init();
