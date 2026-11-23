/**
 * Update checker for the user's configured GitHub repository.
 * Never makes requests unless a GitHub URL is configured and check is triggered.
 */

import { compareSemver, parseGitHubRepoUrl } from './domain-utils.js';
import { APP_VERSION } from './storage.js';

export async function checkGitHubReleaseUpdate(githubUrl) {
  const parsed = parseGitHubRepoUrl(githubUrl);
  const checkedAt = new Date().toISOString();

  if (!parsed) {
    return {
      status: 'no_repo',
      currentVersion: APP_VERSION,
      latestVersion: null,
      releaseUrl: null,
      checkedAt,
      message: 'Укажите ссылку на GitHub в настройках',
    };
  }

  const apiUrl = `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/releases/latest`;
  try {
    const resp = await fetch(apiUrl, {
      method: 'GET',
      headers: { Accept: 'application/vnd.github+json' },
      cache: 'no-store',
    });

    if (resp.status === 404) {
      return {
        status: 'no_releases',
        currentVersion: APP_VERSION,
        latestVersion: null,
        releaseUrl: `${parsed.cleanUrl}/releases`,
        checkedAt,
        message: 'В репозитории пока нет релизов',
      };
    }

    if (!resp.ok) {
      return {
        status: 'error',
        currentVersion: APP_VERSION,
        latestVersion: null,
        releaseUrl: parsed.cleanUrl,
        checkedAt,
        message: `Ошибка GitHub API (HTTP ${resp.status})`,
      };
    }

    const data = await resp.json();
    const latestTag = String(data?.tag_name || '').trim();
    const releaseUrl = data?.html_url || `${parsed.cleanUrl}/releases`;
    const cmp = compareSemver(latestTag, APP_VERSION);

    if (cmp > 0) {
      return {
        status: 'available',
        currentVersion: APP_VERSION,
        latestVersion: latestTag,
        releaseUrl,
        checkedAt,
        message: `Доступна версия ${latestTag}`,
      };
    }

    return {
      status: 'up_to_date',
      currentVersion: APP_VERSION,
      latestVersion: latestTag || `v${APP_VERSION}`,
      releaseUrl,
      checkedAt,
      message: 'Установлена актуальная версия',
    };
  } catch (err) {
    return {
      status: 'error',
      currentVersion: APP_VERSION,
      latestVersion: null,
      releaseUrl: parsed.cleanUrl,
      checkedAt,
      message: `Нет связи с GitHub: ${err?.message || 'ошибка сети'}`,
    };
  }
}
