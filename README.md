# PryWarp — WARP for Browser

**Точечный обход блокировок в браузере (YouTube 4K60 и выбранные сайты) через локальный Cloudflare WARP на базе быстрого user-space AmneziaWG (`mihomo`) + резервного `HTTP/2` (`usque`) — без системного VPN-адаптера, прав администратора, правки `hosts`, смены DNS и влияния на игры или другие программы.**

---

## Скачать и установить за 2 шага

> **[Скачать готовый архив (Releases)](https://github.com/pryanus/PryWarp-WARP-for-Browser/releases/latest)** — содержит всё нужное для запуска (включая `mihomo.exe` и `usque.exe`), сборка и ручная регистрация аккаунтов не требуются.

**Требование для Windows:** установленный [Python 3.10+](https://www.python.org/downloads/) (при установке поставь галочку *«Add Python to PATH»*, либо в терминале: `winget install Python.Python.3.12`).

1. **Запусти мост:** распакуй архив в любую постоянную папку (например `D:\PryWarp`) и запусти **`УСТАНОВИТЬ_МОСТ.cmd`** — фоновый мост поднимется в `user-space` и добавится в автозагрузку текущего пользователя (`HKCU\...\Run\PryWarpBridge`).
2. **Подключи расширение в браузере (выбери папку под свой браузер):**
   - **Папка `extension-chromium`** — для всех браузеров на движке **Chromium** (**Google Chrome, Яндекс Браузер, Microsoft Edge, Opera / Opera GX, Brave, Vivaldi, Atom, Arc**):
     - Открой `chrome://extensions` (`browser://extensions` в Яндексе, `edge://extensions` в Edge, `opera://extensions` в Opera, `brave://extensions` в Brave).
     - Включи **Режим разработчика** → **Загрузить распакованное расширение** → укажи папку **`extension-chromium`**.
     - *Примечание для Brave:* обычные вкладки работают через WARP, а встроенное «Приватное окно с Tor» изолировано самим браузером.
   - **Папка `extension-firefox`** — для всех браузеров на движке **Firefox / Gecko** (**Mozilla Firefox, Tor Browser, Zen Browser, LibreWolf, Waterfox, Floorp**):
     - Открой `about:debugging#/runtime/this-firefox` → **Загрузить временное дополнение** → выбери `manifest.json` внутри папки **`extension-firefox`** (для постоянного режима без перезагрузки нужна подписанная или Developer Edition сборка; в Tor Browser временное дополнение работает до перезапуска, а режим совместимости с Tor в настройках расширения не даёт остальным сайтам уходить мимо цепочки Tor).

Готово! Закрепи иконку **PryWarp** на панели инструментов браузера:
- **Зелёные очки** — мост запущен, туннель Cloudflare WARP активен для выбранных сайтов.
- **Красные очки** — защита выключена в попапе или локальный мост остановлен.

---

## Что внутри скачанного архива

Архив с релиза намеренно содержит только минимально необходимый набор файлов:

| Файл / папка | Назначение |
| --- | --- |
| `ИНСТРУКЦИЯ.txt` | Короткая офлайн-памятка по установке, использованию и удалению |
| `УСТАНОВИТЬ_МОСТ.cmd` | Запуск локального WARP-моста в фоне + добавление в автозагрузку Windows |
| `УДАЛИТЬ_МОСТ.cmd` | Остановка моста и полное удаление из автозагрузки (реестр + процесс) |
| `extension-chromium/` | Папка расширения (MV3) для движка **Chromium**: Chrome, Яндекс Браузер, Edge, Opera / GX, Brave, Vivaldi, Atom, Arc |
| `extension-firefox/` | Папка расширения (MV3) для движка **Firefox / Gecko**: Firefox, Tor Browser, Zen, LibreWolf, Waterfox, Floorp |
| `bridge/` | Фоновый супервайзер (`warp_bridge.py`, `bridge_ctl.ps1`), основной движок `mihomo.exe` (AmneziaWG) и резервный `usque.exe` (HTTP/2) |

---

## Как это работает (под капотом)

### 1. База Cloudflare WARP (`MetaCubeX/mihomo` + `Diniboy1123/usque`)
Мост использует гибридную двухдвижковую схему для максимальной скорости и отказоустойчивости:

- **Основной движок (по умолчанию в `Авто`):** **[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)** (`MIT License`) в режиме **AmneziaWG 1.5 (`+i1` QUIC-маскировка)** поверх Cloudflare WARP.
  - При первом запуске `bridge/warp_bridge.py` сам за ~1 секунду генерирует X25519-ключ и анонимно регистрирует бесплатное устройство в официальном API Cloudflare WARP, сохраняя ключи локально в `bridge/warp_awg.json` (никаких логинов и ручных действий).
  - Работает по пулу из 4 проверенных эндпоинтов (`162.159.192.1:2408`, `188.114.96.1:2408`, `188.114.97.1:894`, `188.114.99.224:1002`) с автоматическим `url-test` (сам выбирает самый быстрый живой узел и держит `persistent-keepalive: 25`).
- **Резервный движок (`HTTP/2` / `QUIC`):** **[Diniboy1123/usque](https://github.com/Diniboy1123/usque)** (`MIT License`, MASQUE поверх `TCP:443`). Если у провайдера или в корпоративной сети полностью заблокирован UDP, мост в режиме `Авто` сам переключится на `HTTP/2 (TCP:443)` и будет периодически проверять возврат на `AmneziaWG`. В «Настройках» любой режим можно выбрать вручную в 1 клик.

### 2. Изоляция `user-space` (без VPN-адаптера и вмешательства в ОС)
- `usque.exe` работает **строго в user-space** в режиме локального SOCKS5-прокси на **`127.0.0.1:10880`**, а `warp_bridge.py` следит за стабильностью процесса, проверяет фактическую доступность WARP + YouTube (`cloudflare.com/cdn-cgi/trace` + `youtube.com/generate_204`) и отдаёт лёгкий локальный API статуса на **`127.0.0.1:10881`**.
- **Никаких драйверов, TUN/TAP-адаптеров, правки `hosts`, смены системного DNS или Windows `ProxyEnable`.**
- **Без установленного и включённого расширения ничего не меняется:** даже если фоновый мост запущен в трее/фоне, ни браузер, ни остальные программы не отправляют через него ни байта трафика до тех пор, пока расширение явно не направит нужный домен в `127.0.0.1:10880`.
- Если мост остановлен, Chrome/Firefox-расширение автоматически снимает PAC-правило прокси, чтобы браузер не получал 5-минутный таймаут `BadProxy` и продолжал работать напрямую.

### 3. Домены, поддомены и режим «Ко всем сайтам»
- **1 корневой домен = сайт целиком:** при добавлении, например, `discord.com` автоматически маршрутизируются и корень `discord.com`, и все поддомены `*.discord.com` (CDN, медиа, вебсокеты внутри этого домена).
- **Пресет YouTube (из коробки):** уже включает все 12 необходимых доменов воспроизведения, картинок, API и скриптов (`youtube.com`, `googlevideo.com`, `ytimg.com`, `ggpht.com`, `youtu.be`, `youtubei.googleapis.com`, `jnn-pa.googleapis.com`, `youtube-nocookie.com`, `yt.be`, `yt3.googleusercontent.com`, `yt4.googleusercontent.com`, `gvt1.com`).
- **Кнопка «Ко всем сайтам» / «К избранным»:** переключает режим маршрутизации прямо в один клик — либо только твой список доменов, либо **весь внешний трафик браузера** через WARP (локальные адреса `localhost`, `127.0.0.1`, `192.168.*`, `10.*`, `.local` всегда идут напрямую).
- **Только браузер (важное ограничение):** расширение управляет трафиком **только внутри браузера**. Отдельные настольные клиенты вроде `Discord.exe`, Steam или онлайн-игр работают мимо прокси браузера и затронуты не будут (веб-версия Discord в браузере заработает при добавлении доменов Discord или в режиме «Ко всем сайтам»).

### 4. Совместимость с `zapret-discord-youtube` (`winws.exe`)
Если параллельно с **PryWarp** на ПК запущен `zapret-discord-youtube` (`winws.exe`), его стандартный `list-general.txt` содержит `cloudflareclient.com`, из-за чего `winws.exe` может отправлять фейковые пакеты по самому зашифрованному туннелю `usque.exe` (`consumer-masque.cloudflareclient.com`), вызывая высокий пинг или откат на `HTTP/2`.

Чтобы они не мешали друг другу, добавь в папку `lists/` вашего `zapret`:
- В **`list-exclude-user.txt`**:
  ```text
  cloudflareclient.com
  consumer-masque.cloudflareclient.com
  ```
- В **`ipset-exclude-user.txt`**:
  ```text
  162.159.192.0/21
  188.114.96.0/22
  ```

---

## Сборка из исходников (для разработчиков)

Если ты клонируешь репозиторий вместо скачивания готового архива из Releases:

```powershell
git clone https://github.com/pryanus/PryWarp-WARP-for-Browser.git
cd PryWarp-WARP-for-Browser
```

1. Скачай официальные Windows-бинарники и положи их в папку `bridge/`:
   - `mihomo.exe` — из релизов **[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo/releases)** (`mihomo-windows-amd64-compatible-*.zip`, переименуй в `mihomo.exe`).
   - `usque.exe` *(резервный HTTP/2 транспорт)* — из релизов **[Diniboy1123/usque](https://github.com/Diniboy1123/usque/releases)** (`usque_*_windows_amd64.zip`).
2. При изменении файлов в `src/` пересобери обе папки расширений (`extension-chromium/` и `extension-firefox/`):
   ```powershell
   python build_extensions.py
   node tests/test_domain_utils.mjs
   ```
3. Запусти `УСТАНОВИТЬ_МОСТ.cmd`.

---

## Удаление

1. Запусти **`УДАЛИТЬ_МОСТ.cmd`** — процесс остановится, а запись автозагрузки `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PryWarpBridge` удалится.
2. Удали расширение в браузере и при желании сотри папку с программой. Никаких системных следов в сети или драйверах не остаётся.

---

## Благодарности

- **[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)** (`MIT`) — высокоскоростное ядро user-space AmneziaWG + SOCKS5.
- **[Diniboy1123/usque](https://github.com/Diniboy1123/usque)** (`MIT`) — открытый клиент Cloudflare WARP MASQUE для резервного `HTTP/2 (TCP:443)` транспорта.
