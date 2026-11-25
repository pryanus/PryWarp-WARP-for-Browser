# Privacy Policy — PryWarp Local Proxy Router

**Last Updated:** November 25, 2026

## Overview
**PryWarp — Local Proxy Router** is an open-source browser extension that routes user-selected domains through a local SOCKS5 proxy running on the user's own computer (`127.0.0.1`).

## Data Collection
**We do not collect, store, transmit, or sell any personal data, browsing history, or telemetry.**

- **No analytics or tracking:** The extension contains no analytics SDKs, advertising code, or third-party tracking scripts.
- **Local storage only:** Your domain rules, toggle states, and local proxy port settings are stored exclusively in your browser's local storage (`chrome.storage.local` / `browser.storage.local`) and never leave your device.
- **Local-only network communication:** The extension communicates solely with your local companion proxy bridge on `127.0.0.1` (default ports `10880` / `10881`) to check connection status and apply routing rules.
- **No remote servers:** The extension does not connect to any external servers operated by the developer.

## Permissions Used
- **`proxy`**: Applies domain-based PAC / proxy routing rules to send only user-selected hostnames to the user's local SOCKS5 proxy (`127.0.0.1`).
- **`storage`**: Saves the user's domain list and preferences locally in the browser.
- **`tabs`**: Reads the active tab's hostname when the popup is opened so the user can add or remove the current website in one click, and optionally reloads the active tab after toggling proxy rules.
- **`alarms`**: Periodically checks whether the local proxy bridge on `127.0.0.1` is reachable so the extension can keep the toolbar status icon accurate and automatically fall back to direct connections when the local proxy is stopped.
- **Host permissions (`http://127.0.0.1/*` on Chromium/Opera; `<all_urls>` on Firefox)**: Required to query the local proxy bridge status API on `127.0.0.1` and (on Firefox) to intercept per-request proxy routing via `browser.proxy.onRequest`.

## Open Source
The full source code is publicly available for inspection at:
https://github.com/pryanus/PryWarp-WARP-for-Browser

## Contact
If you have questions about this privacy policy, please open an issue on the GitHub repository:
https://github.com/pryanus/PryWarp-WARP-for-Browser/issues
