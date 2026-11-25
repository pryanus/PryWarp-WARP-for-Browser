"""
Builds store-compliant MV3 packages for:
  1. Opera Add-ons / Microsoft Edge Add-ons / Chrome Web Store (PryWarp-Opera-Edge-v<ver>.zip)
  2. Mozilla Firefox Add-ons / AMO (PryWarp-Firefox-AMO-v<ver>.zip)

Sanitizes store-sensitive wording (removes third-party trademarks, bypass/circumvention phrasing,
external self-updater tab/permissions) while preserving 100% of routing & local bridge functionality.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
OUT_DIR = ROOT / "store-release"

# Keep version in sync with build_extensions.py
from build_extensions import APP_VERSION  # noqa: E402


HTML_REPLACEMENTS = [
    ("<title>PryWarp — WARP for Browser</title>", "<title>PryWarp — Local Proxy Router</title>"),
    ('<span class="app-sub">— WARP for Browser</span>', '<span class="app-sub">— Local Proxy Router</span>'),
    ('aria-label="Состояние туннеля WARP"', 'aria-label="Состояние локального прокси"'),
    ('title="Переподключить WARP"', 'title="Переподключить локальный прокси"'),
    ("Запусти <span class=\"mono\">УСТАНОВИТЬ_МОСТ.cmd</span> из папки PryWarp", "Запусти локальный SOCKS5-мост PryWarp на ПК"),
    ("Через WARP идут YouTube и добавленные сайты", "Через прокси идут YouTube и добавленные сайты"),
    ('placeholder="Домен, например rutracker.org"', 'placeholder="Домен, например example.com"'),
    ('aria-label="Домен для обхода"', 'aria-label="Домен для маршрутизации"'),
    ('<span id="youtubeStatusBadge" class="state-text state-ok">В обходе</span>', '<span id="youtubeStatusBadge" class="state-text state-ok">Через прокси</span>'),
    ('<h2 class="section-title">Туннель Cloudflare WARP</h2>', '<h2 class="section-title">Локальный прокси-мост</h2>'),
    ("PryWarp — WARP for Browser · v", "PryWarp — Local Proxy Router · v"),
    # Hide GitHub self-updater tab in store builds (stores manage updates themselves)
    ('<button id="tabUpdates" class="tab-btn" role="tab" aria-selected="false" type="button">Обновление</button>',
     '<button id="tabUpdates" class="tab-btn" role="tab" aria-selected="false" type="button" hidden>Обновление</button>'),
]

JS_POPUP_REPLACEMENTS = [
    ("WARP Bridge Popup UI Controller", "PryWarp Popup UI Controller"),
    ("st.textContent = rule.enabled ? 'В обходе' : 'Пауза';", "st.textContent = rule.enabled ? 'Через прокси' : 'Пауза';"),
    ("`PryWarp — WARP for Browser · v${APP_VERSION}`", "`PryWarp — Local Proxy Router · v${APP_VERSION}`"),
    ("'Все сайты через WARP'", "'Все сайты через прокси'"),
    ("'Весь трафик браузера через WARP (кроме локальных адресов)'", "'Весь трафик браузера через прокси (кроме локальных адресов)'"),
    ("'Через WARP идут YouTube и сайты из списка ниже'", "'Через прокси идут YouTube и сайты из списка ниже'"),
    ("st.youtubeEnabled ? 'В обходе' : 'Отключён'", "st.youtubeEnabled ? 'Через прокси' : 'Отключён'"),
    ("'Другое VPN-расширение перехватило управление прокси'", "'Другое расширение перехватило управление прокси'"),
    ("'Отключи другие VPN/прокси-расширения в браузере (например, VeePN), иначе браузер не даёт PryWarp управлять маршрутами'",
     "'Отключи другие прокси-расширения в браузере, иначе браузер не даёт PryWarp управлять маршрутами'"),
    ("'Браузер идёт напрямую (без WARP)'", "'Браузер идёт напрямую (без прокси)'"),
    ("currentState?.enabled ? 'WARP работает' : 'WARP на паузе'", "currentState?.enabled ? 'Прокси работает' : 'Прокси на паузе'"),
    ("'Подключение WARP...'", "'Подключение моста...'"),
    ("'Ошибка туннеля WARP'", "'Ошибка локального моста'"),
    ("'WARP готов — вкладка обновлена'", "'Прокси готов — вкладка обновлена'"),
    ("'WARP подключён — обнови вкладку (F5)'", "'Прокси подключён — обнови вкладку (F5)'"),
    ("nextEnabled ? 'Обход включён' : 'Обход выключен'", "nextEnabled ? 'Прокси включён' : 'Прокси выключен'"),
    ("nextAll ? 'Режим: все сайты через WARP' : 'Режим: только избранные сайты'",
     "nextAll ? 'Режим: все сайты через прокси' : 'Режим: только избранные сайты'"),
    ("nextVal ? 'YouTube в обходе' : 'YouTube напрямую'", "nextVal ? 'YouTube через прокси' : 'YouTube напрямую'"),
    ("'Переподключение WARP...'", "'Переподключение моста...'"),
    ("`WARP переподключён${latText} — вкладка обновлена`", "`Прокси переподключён${latText} — вкладка обновлена`"),
    ("`WARP переподключён${latText}`", "`Прокси переподключён${latText}`"),
    ("'Введи корректный домен, например rutracker.org'", "'Введи корректный домен, например example.com'"),
]

JS_STORAGE_REPLACEMENTS = [
    ("githubUrl: 'https://github.com/pryanus/PryWarp-WARP-for-Browser',", "githubUrl: '',"),
    ("autoUpdateCheck: false,", "autoUpdateCheck: false,"),
]

JS_BG_REPLACEMENTS = [
    ("[WARP Bridge]", "[PryWarp]"),
]

FORBIDDEN_STORE_PATTERNS = [
    re.compile(r"rutracker", re.I),
    re.compile(r"veepn", re.I),
    re.compile(r"cloudflare", re.I),
    re.compile(r"обход", re.I),
    re.compile(r"блокиров", re.I),
]


def apply_replacements(text: str, pairs: list[tuple[str, str]]) -> str:
    for old, new in pairs:
        text = text.replace(old, new)
    return text


def prepare_sanitized_src(stage_dir: Path) -> None:
    for sub in ("shared", "popup", "icons"):
        shutil.copytree(SRC / sub, stage_dir / sub)

    # Sanitize popup.html
    html_p = stage_dir / "popup" / "popup.html"
    html_p.write_text(apply_replacements(html_p.read_text(encoding="utf-8"), HTML_REPLACEMENTS), encoding="utf-8")

    # Sanitize popup.js
    pjs = stage_dir / "popup" / "popup.js"
    pjs.write_text(apply_replacements(pjs.read_text(encoding="utf-8"), JS_POPUP_REPLACEMENTS), encoding="utf-8")

    # Sanitize storage.js (no default external GitHub update URL in store packages)
    sjs = stage_dir / "shared" / "storage.js"
    sjs.write_text(apply_replacements(sjs.read_text(encoding="utf-8"), JS_STORAGE_REPLACEMENTS), encoding="utf-8")

    # Sanitize background-core.js logs
    bjs = stage_dir / "shared" / "background-core.js"
    bjs.write_text(apply_replacements(bjs.read_text(encoding="utf-8"), JS_BG_REPLACEMENTS), encoding="utf-8")

    # Verify JS syntax of every generated file
    for js_file in stage_dir.rglob("*.js"):
        res = subprocess.run(["node", "--check", str(js_file)], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"JS syntax check failed for {js_file}: {res.stderr}")


def audit_clean_package(stage_dir: Path, label: str) -> None:
    violations = []
    for f in stage_dir.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in (".json", ".html", ".js", ".css"):
            continue
        txt = f.read_text(encoding="utf-8", errors="replace")
        for pat in FORBIDDEN_STORE_PATTERNS:
            m = pat.search(txt)
            if m:
                violations.append(f"{f.relative_to(stage_dir)} matched {pat.pattern!r}: {m.group(0)!r}")
    if violations:
        raise AssertionError(f"Store hygiene check failed for {label}:\n  " + "\n  ".join(violations))
    print(f"[AUDIT OK] {label}: 0 forbidden strings/trademarks found.")


def pack_zip(src_dir: Path, out_zip: Path) -> None:
    if out_zip.exists():
        out_zip.unlink()
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for f in sorted(src_dir.rglob("*")):
            if f.is_file():
                rel = f.relative_to(src_dir).as_posix()
                zf.write(f, rel)
    print(f"[PACKED] {out_zip.name} ({out_zip.stat().st_size} bytes)")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    icons_green = {
        "16": "icons/icon-16.png",
        "32": "icons/icon-32.png",
        "48": "icons/icon-48.png",
        "128": "icons/icon-128.png",
    }
    icons_red = {
        "16": "icons/icon-off-16.png",
        "32": "icons/icon-off-32.png",
        "48": "icons/icon-off-48.png",
        "128": "icons/icon-off-128.png",
    }

    store_name = "PryWarp — Local Proxy Router"
    store_desc = (
        "Route selected domains through your local SOCKS5 proxy (127.0.0.1) "
        "via PAC rules without affecting other browser traffic."
    )

    opera_edge_manifest = {
        "manifest_version": 3,
        "name": store_name,
        "version": APP_VERSION,
        "description": store_desc,
        "icons": icons_green,
        "action": {
            "default_title": store_name,
            "default_popup": "popup/popup.html",
            "default_icon": icons_red,
        },
        "background": {
            "service_worker": "shared/background-core.js",
            "type": "module",
        },
        "permissions": ["proxy", "storage", "tabs", "alarms"],
        "host_permissions": [
            "http://127.0.0.1/*",
        ],
    }

    firefox_amo_manifest = {
        "manifest_version": 3,
        "name": store_name,
        "version": APP_VERSION,
        "description": store_desc,
        "browser_specific_settings": {
            "gecko": {
                "id": "prywarp@pryanick.dev",
                "strict_min_version": "115.0",
                "data_collection_permissions": {
                    "required": ["none"],
                },
            }
        },
        "icons": icons_green,
        "action": {
            "default_title": store_name,
            "default_popup": "popup/popup.html",
            "default_icon": icons_red,
        },
        "background": {
            "scripts": ["shared/background-core.js"],
            "type": "module",
        },
        "permissions": ["proxy", "storage", "tabs", "alarms"],
        "host_permissions": ["<all_urls>"],
    }

    with tempfile.TemporaryDirectory(prefix="prywarp_store_") as tmp:
        tmp_path = Path(tmp)

        # 1. Opera Add-ons / Edge / Chrome Web Store package
        opera_dir = tmp_path / "opera-edge"
        prepare_sanitized_src(opera_dir)
        (opera_dir / "manifest.json").write_text(
            json.dumps(opera_edge_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        audit_clean_package(opera_dir, "Opera/Edge/Chromium")
        pack_zip(opera_dir, OUT_DIR / f"PryWarp-Opera-Edge-v{APP_VERSION}.zip")

        # 2. Firefox AMO package
        ff_dir = tmp_path / "firefox-amo"
        prepare_sanitized_src(ff_dir)
        (ff_dir / "manifest.json").write_text(
            json.dumps(firefox_amo_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        audit_clean_package(ff_dir, "Firefox AMO")
        pack_zip(ff_dir, OUT_DIR / f"PryWarp-Firefox-AMO-v{APP_VERSION}.zip")

    # Copy ready 128x128 store icon for dashboard upload
    shutil.copy2(SRC / "icons" / "icon-128.png", OUT_DIR / "store-icon-128.png")
    print(f"[ICON] Copied store-icon-128.png -> {OUT_DIR}")


if __name__ == "__main__":
    main()
