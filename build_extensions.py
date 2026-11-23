"""
Generates real PNG icons (16, 32, 48, 128 px) without external dependencies
and builds both cross-browser extension packages:
  - extension-chromium/  (Chrome, Yandex, Opera, Edge, Brave, Vivaldi)
  - extension-firefox/   (Firefox, Tor Browser, LibreWolf, Zen)
"""

from __future__ import annotations

import json
import math
import shutil
import struct
import zlib
from pathlib import Path
from typing import Tuple


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
ICONS_DIR = SRC / "icons"
DIST_CHROMIUM = ROOT / "extension-chromium"
DIST_FIREFOX = ROOT / "extension-firefox"

APP_VERSION = "1.0.0"


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack("!I", len(data)) + tag + data + struct.pack("!I", crc)


def _blend(dst: Tuple[int, int, int, int], src: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    sa = src[3] / 255.0
    da = dst[3] / 255.0
    out_a = sa + da * (1.0 - sa)
    if out_a <= 0:
        return (0, 0, 0, 0)
    r = int((src[0] * sa + dst[0] * da * (1.0 - sa)) / out_a)
    g = int((src[1] * sa + dst[1] * da * (1.0 - sa)) / out_a)
    b = int((src[2] * sa + dst[2] * da * (1.0 - sa)) / out_a)
    return (r, g, b, int(out_a * 255))


def _dist_segment(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    c1 = vx * wx + vy * wy
    if c1 <= 0:
        return math.hypot(px - ax, py - ay)
    c2 = vx * vx + vy * vy
    if c2 <= c1:
        return math.hypot(px - bx, py - by)
    t = c1 / c2
    return math.hypot(px - (ax + t * vx), py - (ay + t * vy))


def render_icon_png(size: int) -> bytes:
    """Renders a clean dark DNS-Switcher-style rounded tile with a crisp minimalist shield/check glyph."""
    bg_fill = (23, 26, 33, 255)      # #171a21
    border_col = (45, 51, 66, 255)   # #2d3342
    glyph_col = (56, 189, 248, 255)  # #38bdf8
    accent_dot = (52, 211, 153, 255) # #34d399

    radius = size * 0.22
    border_w = max(1.0, size * 0.06)
    stroke_w = max(1.1, size * 0.085)

    # Shield outline points in normalized [0..1] space
    shield_pts = [
        (0.50, 0.21),
        (0.75, 0.30),
        (0.75, 0.52),
        (0.67, 0.67),
        (0.50, 0.79),
        (0.33, 0.67),
        (0.25, 0.52),
        (0.25, 0.30),
        (0.50, 0.21),
    ]
    # Checkmark inside shield
    check_pts = [
        (0.39, 0.50),
        (0.47, 0.58),
        (0.62, 0.42),
    ]

    rows = bytearray()
    for y in range(size):
        rows.append(0)  # PNG filter type 0
        ny = (y + 0.5) / size
        for x in range(size):
            nx = (x + 0.5) / size
            px_col = (0, 0, 0, 0)

            # Signed distance to rounded rectangle
            cx = abs(x + 0.5 - size / 2.0) - (size / 2.0 - radius - 0.5)
            cy = abs(y + 0.5 - size / 2.0) - (size / 2.0 - radius - 0.5)
            sdf = math.hypot(max(cx, 0.0), max(cy, 0.0)) + min(max(cx, cy), 0.0) - radius

            if sdf <= 0.5:
                cov = max(0.0, min(1.0, 0.5 - sdf))
                fill = (bg_fill[0], bg_fill[1], bg_fill[2], int(255 * cov))
                px_col = _blend(px_col, fill)
                if sdf >= -border_w:
                    bcov = max(0.0, min(1.0, min(0.5 - sdf, sdf + border_w + 0.5)))
                    px_col = _blend(px_col, (border_col[0], border_col[1], border_col[2], int(255 * bcov)))

                # Shield outline distance
                min_d = 999.0
                for i in range(len(shield_pts) - 1):
                    ax, ay = shield_pts[i]
                    bx, by = shield_pts[i + 1]
                    d = _dist_segment(nx * size, ny * size, ax * size, ay * size, bx * size, by * size)
                    if d < min_d:
                        min_d = d
                if min_d <= stroke_w * 0.65:
                    ac = max(0.0, min(1.0, (stroke_w * 0.65 - min_d) / max(0.7, stroke_w * 0.28)))
                    px_col = _blend(px_col, (glyph_col[0], glyph_col[1], glyph_col[2], int(255 * ac)))

                # Inner check glyph
                min_c = 999.0
                for i in range(len(check_pts) - 1):
                    ax, ay = check_pts[i]
                    bx, by = check_pts[i + 1]
                    d = _dist_segment(nx * size, ny * size, ax * size, ay * size, bx * size, by * size)
                    if d < min_c:
                        min_c = d
                if min_c <= stroke_w * 0.62:
                    ac = max(0.0, min(1.0, (stroke_w * 0.62 - min_c) / max(0.7, stroke_w * 0.28)))
                    px_col = _blend(px_col, (accent_dot[0], accent_dot[1], accent_dot[2], int(255 * ac)))

            rows.extend(px_col)

    ihdr = struct.pack("!IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(rows), level=9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


import sys


def generate_icons(force_default: bool = False) -> None:
    ICONS_DIR.mkdir(parents=True, exist_ok=True)
    for sz in (16, 32, 48, 128):
        target = ICONS_DIR / f"icon-{sz}.png"
        if force_default or not target.exists():
            target.write_bytes(render_icon_png(sz))


def build_target(dest: Path, manifest: dict) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    for sub in ("shared", "popup", "icons"):
        shutil.copytree(SRC / sub, dest / sub)
    (dest / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    generate_icons(force_default="--default-icons" in sys.argv)

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

    chromium_manifest = {
        "manifest_version": 3,
        "name": "PryWarp — WARP for Browser",
        "version": APP_VERSION,
        "description": "Точечный обход YouTube и выбранных сайтов через локальный Cloudflare WARP SOCKS5 без влияния на остальной трафик.",
        "icons": icons_green,
        "action": {
            "default_title": "PryWarp — WARP for Browser",
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
            "https://api.github.com/*",
        ],
    }

    firefox_manifest = {
        "manifest_version": 3,
        "name": "PryWarp — WARP for Browser",
        "version": APP_VERSION,
        "description": "Точечный обход YouTube и выбранных сайтов через локальный Cloudflare WARP SOCKS5 без влияния на остальной трафик.",
        "browser_specific_settings": {
            "gecko": {
                "id": "prywarp@pryanick.dev",
                "strict_min_version": "115.0",
            }
        },
        "icons": icons_green,
        "action": {
            "default_title": "PryWarp — WARP for Browser",
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

    build_target(DIST_CHROMIUM, chromium_manifest)
    build_target(DIST_FIREFOX, firefox_manifest)
    print(f"Built: {DIST_CHROMIUM}")
    print(f"Built: {DIST_FIREFOX}")


if __name__ == "__main__":
    main()
