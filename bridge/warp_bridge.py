"""
PryWarp Bridge Supervisor v2.0 — high-speed, fail-safe user-space Cloudflare WARP manager.

Primary engine: MetaCubeX/mihomo running AmneziaWG 1.5 (+i1 QUIC-like handshake obfuscation)
over a multi-endpoint Cloudflare WARP pool with automatic url-test failover and keepalive.
Backup engine:  Diniboy1123/usque over MASQUE HTTP/2 (TCP:443) or QUIC if UDP is blocked.

Runs strictly in user-space (SOCKS5 on 127.0.0.1:10880, Control API on 127.0.0.1:10881).
Does NOT create VPN/TUN adapters, does NOT require admin rights, does NOT touch OS routes, DNS, or hosts.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _resolve_bridge_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


BRIDGE_DIR = _resolve_bridge_dir()
MIHOMO_EXE = BRIDGE_DIR / "mihomo.exe"
USQUE_EXE = BRIDGE_DIR / "usque.exe"
AWG_CONFIG = BRIDGE_DIR / "warp_awg.json"
MIHOMO_RUNTIME_YAML = BRIDGE_DIR / "mihomo_runtime.yaml"
WARP_CONFIG = BRIDGE_DIR / "config.json"
SETTINGS_FILE = BRIDGE_DIR / "bridge_settings.json"
LOG_FILE = BRIDGE_DIR / "bridge.log"

BRIDGE_VERSION = "2.0.1"

# Verified high-speed Cloudflare WARP AmneziaWG (+i1) endpoints across diverse subnets & ports
AWG_ENDPOINTS: Tuple[Tuple[str, int], ...] = (
    ("162.159.192.1", 2408),
    ("188.114.96.1", 2408),
    ("188.114.97.1", 894),
    ("162.159.192.8", 500),
    ("188.114.96.3", 4500),
    ("188.114.99.224", 1002),
)

# Official Cloudflare WARP MASQUE endpoints for usque fallback
PREFERRED_MASQUE_ENDPOINTS = ("162.159.198.2", "162.159.198.1")
HTTP2_ENDPOINT = "162.159.198.2"

VALID_MODES = ("auto", "awg", "http2", "quic")
VALID_TRANSPORTS = ("awg", "http2", "quic")

DEFAULT_SETTINGS: Dict[str, Any] = {
    "socks_host": "127.0.0.1",
    "socks_port": 10880,
    "api_host": "127.0.0.1",
    "api_port": 10881,
    "transport_mode": "auto",  # "auto" (strict AmneziaWG priority -> HTTP/2 only on full outage) | "awg" | "http2" | "quic"
    "probe_interval_sec": 45,
    "failover_threshold": 5,
    "recovery_retry_sec": 180,
    "mtu": 1280,
    "dns_servers": ["1.1.1.1", "1.0.0.1"],
}

_LOG_LOCK = threading.Lock()
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def log_line(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        print(line, flush=True)
    except Exception:
        pass
    with _LOG_LOCK:
        try:
            if LOG_FILE.exists() and LOG_FILE.stat().st_size > 262_144:
                tail = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-300:]
                LOG_FILE.write_text("\n".join(tail) + "\n", encoding="utf-8")
            with LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


def load_settings() -> Dict[str, Any]:
    data = dict(DEFAULT_SETTINGS)
    if SETTINGS_FILE.exists():
        try:
            loaded = json.loads(SETTINGS_FILE.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                data.update(loaded)
        except Exception as exc:
            log_line(f"Settings load warning: {exc}")
    data["socks_host"] = "127.0.0.1"
    data["api_host"] = "127.0.0.1"
    if data.get("transport_mode") not in VALID_MODES:
        data["transport_mode"] = "auto"
    if not isinstance(data.get("dns_servers"), list) or not data["dns_servers"]:
        data["dns_servers"] = list(DEFAULT_SETTINGS["dns_servers"])
    try:
        mtu = int(data.get("mtu", 1280))
        if mtu == 1360 and not data.get("mtu_custom"):
            mtu = 1280
        data["mtu"] = max(1280, min(1420, mtu))
    except Exception:
        data["mtu"] = 1280
    # Ensure legacy v1.0.x configs (failover_threshold=2) don't prematurely drop AmneziaWG
    try:
        if int(data.get("failover_threshold", 5)) < 5:
            data["failover_threshold"] = 5
    except Exception:
        data["failover_threshold"] = 5
    try:
        if int(data.get("recovery_retry_sec", 180)) > 300:
            data["recovery_retry_sec"] = 180
    except Exception:
        data["recovery_retry_sec"] = 180
    return data


def save_settings(settings: Dict[str, Any]) -> None:
    tmp = SETTINGS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(SETTINGS_FILE)


# ---------------------------------------------------------------------------
# Pure-Python RFC 7748 X25519 keygen + anonymous Cloudflare WARP registration
# ---------------------------------------------------------------------------
_X25519_P = (1 << 255) - 19
_X25519_A24 = 121665


def _x25519_scalarmult(k_bytes: bytes, u_bytes: bytes) -> bytes:
    k = bytearray(k_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    u_int = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x_1 = u_int
    x_2, z_2 = 1, 0
    x_3, z_3 = u_int, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        A = (x_2 + z_2) % _X25519_P
        AA = (A * A) % _X25519_P
        B = (x_2 - z_2) % _X25519_P
        BB = (B * B) % _X25519_P
        E = (AA - BB) % _X25519_P
        C = (x_3 + z_3) % _X25519_P
        D = (x_3 - z_3) % _X25519_P
        DA = (D * A) % _X25519_P
        CB = (C * B) % _X25519_P
        x_3 = pow((DA + CB) % _X25519_P, 2, _X25519_P)
        z_3 = (x_1 * pow((DA - CB) % _X25519_P, 2, _X25519_P)) % _X25519_P
        x_2 = (AA * BB) % _X25519_P
        z_2 = (E * (AA + _X25519_A24 * E)) % _X25519_P
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    res = (x_2 * pow(z_2, _X25519_P - 2, _X25519_P)) % _X25519_P
    return res.to_bytes(32, "little")


def _generate_wg_keypair() -> Tuple[str, str]:
    priv = bytearray(os.urandom(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    priv_b = bytes(priv)
    pub_b = _x25519_scalarmult(priv_b, bytes([9] + [0] * 31))
    return base64.b64encode(priv_b).decode("ascii"), base64.b64encode(pub_b).decode("ascii")


def _socks5_https_post_json(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_path: str,
    body_bytes: bytes,
    extra_headers: Dict[str, str],
    timeout: float = 12.0,
) -> Optional[Dict[str, Any]]:
    raw_sock: Optional[socket.socket] = None
    tls_sock: Optional[ssl.SSLSocket] = None
    try:
        raw_sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
        raw_sock.settimeout(timeout)
        raw_sock.sendall(b"\x05\x01\x00")
        if raw_sock.recv(2) != b"\x05\x00":
            return None
        hb = target_host.encode("ascii")
        raw_sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", 443))
        hdr = raw_sock.recv(4)
        if len(hdr) != 4 or hdr[1] != 0:
            return None
        atyp = hdr[3]
        if atyp == 1:
            raw_sock.recv(6)
        elif atyp == 3:
            raw_sock.recv(raw_sock.recv(1)[0] + 2)
        elif atyp == 4:
            raw_sock.recv(18)

        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=target_host)
        tls_sock.settimeout(timeout)

        hdr_lines = [
            f"POST {target_path} HTTP/1.1",
            f"Host: {target_host}",
            f"Content-Length: {len(body_bytes)}",
            "Connection: close",
        ]
        for k, v in extra_headers.items():
            hdr_lines.append(f"{k}: {v}")
        req_bytes = ("\r\n".join(hdr_lines) + "\r\n\r\n").encode("ascii") + body_bytes
        tls_sock.sendall(req_bytes)

        chunks = []
        while True:
            c = tls_sock.recv(4096)
            if not c:
                break
            chunks.append(c)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        head, _, body = text.partition("\r\n\r\n")
        if " 200 " not in head.splitlines()[0]:
            return None
        # Handle chunked transfer encoding if present
        if "transfer-encoding: chunked" in head.lower():
            decoded = []
            idx = 0
            while idx < len(body):
                nl = body.find("\r\n", idx)
                if nl == -1:
                    break
                sz = int(body[idx:nl].split(";")[0].strip(), 16)
                if sz == 0:
                    break
                decoded.append(body[nl + 2 : nl + 2 + sz])
                idx = nl + 2 + sz + 2
            body = "".join(decoded)
        return json.loads(body)
    except Exception as exc:
        log_line(f"SOCKS5 WARP reg attempt failed: {exc}")
        return None
    finally:
        for s in (tls_sock, raw_sock):
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass


def _register_awg_via_temp_usque(
    payload: bytes,
    headers: Dict[str, str],
    base_socks_port: int,
) -> Optional[Dict[str, Any]]:
    """Bootstrap fallback: if ISP/zapret blocks api.cloudflareclient.com directly, register through temp usque HTTP/2."""
    if not USQUE_EXE.exists():
        return None
    log_line("Direct WARP API blocked — bootstrapping AmneziaWG key via temporary usque HTTP/2...")
    if not (WARP_CONFIG.exists() and WARP_CONFIG.stat().st_size > 100):
        try:
            subprocess.run(
                [str(USQUE_EXE), "-c", str(WARP_CONFIG), "register", "-a"],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            return None
    if not WARP_CONFIG.exists():
        return None
    _set_usque_config_endpoint(HTTP2_ENDPOINT)
    temp_port = min(65000, base_socks_port + 99)
    proc = subprocess.Popen(
        [
            str(USQUE_EXE),
            "-c",
            str(WARP_CONFIG),
            "socks",
            "--http2",
            "-b",
            "127.0.0.1",
            "-p",
            str(temp_port),
            "-m",
            "1280",
            "-d",
            "1.1.1.1",
        ],
        cwd=str(BRIDGE_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        if not _wait_socks_port("127.0.0.1", temp_port, timeout=4.0):
            return None
        time.sleep(0.5)
        return _socks5_https_post_json(
            "127.0.0.1", temp_port, "api.cloudflareclient.com", "/v0a2158/reg", payload, headers, timeout=12.0
        )
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def register_warp_awg_account(base_socks_port: int = 10880) -> Optional[Dict[str, Any]]:
    """Registers a free anonymous Cloudflare WARP WireGuard device via official API (direct or via temp HTTP/2)."""
    priv_b64, pub_b64 = _generate_wg_keypair()
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    payload = json.dumps(
        {
            "key": pub_b64,
            "install_id": "",
            "fcm_token": "",
            "tos": now_iso,
            "model": "PC",
            "serial_number": "",
            "locale": "en_US",
        }
    ).encode("utf-8")

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/3.12.1",
        "CF-Client-Version": "a-6.10-2158",
    }

    data: Optional[Dict[str, Any]] = None
    last_err = ""
    for _attempt in range(2):
        try:
            req = urllib.request.Request(
                "https://api.cloudflareclient.com/v0a2158/reg",
                data=payload,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            break
        except Exception as exc:
            last_err = str(exc)
            time.sleep(0.6)

    if data is None:
        data = _register_awg_via_temp_usque(payload, headers, base_socks_port)

    if not data or "config" not in data:
        log_line(f"WARP AmneziaWG registration failed: {last_err or 'no response'}")
        return None

    try:
        cfg = data["config"]
        client_id = str(cfg.get("client_id", ""))
        reserved = list(base64.b64decode(client_id)[:3]) if client_id else [0, 0, 0]
        account = {
            "device_id": data.get("id", ""),
            "private_key": priv_b64,
            "public_key": pub_b64,
            "peer_public_key": cfg["peers"][0]["public_key"],
            "ip4": cfg["interface"]["addresses"]["v4"],
            "ip6": cfg["interface"]["addresses"]["v6"],
            "reserved": reserved,
            "created_at": now_iso,
        }
        tmp = AWG_CONFIG.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(account, indent=2), encoding="utf-8")
        tmp.replace(AWG_CONFIG)
        log_line("Free Cloudflare WARP (AmneziaWG) key registered cleanly.")
        return account
    except Exception as exc:
        log_line(f"WARP AmneziaWG registration parse failed: {exc}")
        return None


def load_or_create_awg_account(base_socks_port: int = 10880) -> Optional[Dict[str, Any]]:
    if AWG_CONFIG.exists():
        try:
            data = json.loads(AWG_CONFIG.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict) and data.get("private_key") and data.get("peer_public_key") and data.get("ip4"):
                return data
        except Exception as exc:
            log_line(f"warp_awg.json read warning: {exc}")
    return register_warp_awg_account(base_socks_port=base_socks_port)


def write_mihomo_runtime_yaml(
    account: Dict[str, Any],
    socks_host: str,
    socks_port: int,
    mtu: int,
    dns_servers: List[str],
    endpoint_offset: int = 0,
) -> Path:
    n = len(AWG_ENDPOINTS)
    ordered = [AWG_ENDPOINTS[(endpoint_offset + i) % n] for i in range(n)]
    reserved = account.get("reserved") or [0, 0, 0]
    dns_yaml = ", ".join(str(d) for d in dns_servers)
    ip4 = str(account["ip4"]).split("/")[0]
    ip6 = str(account.get("ip6") or "").split("/")[0]
    ipv6_line = f"    ipv6: {ip6}\n" if ip6 else ""

    proxies_blocks: List[str] = []
    proxy_names: List[str] = []
    for idx, (srv, port) in enumerate(ordered):
        pname = f"WARP-{idx + 1}"
        proxy_names.append(pname)
        proxies_blocks.append(
            f'  - name: "{pname}"\n'
            f"    type: wireguard\n"
            f"    server: {srv}\n"
            f"    port: {port}\n"
            f"    ip: {ip4}\n"
            f"{ipv6_line}"
            f'    private-key: "{account["private_key"]}"\n'
            f'    public-key: "{account["peer_public_key"]}"\n'
            f"    reserved: {json.dumps(reserved)}\n"
            f"    udp: true\n"
            f"    mtu: {mtu}\n"
            f"    persistent-keepalive: 25\n"
            f"    remote-dns-resolve: true\n"
            f"    dns: [{dns_yaml}]\n"
            f"    amnezia-wg-option:\n"
            f"      jc: 4\n"
            f"      jmin: 40\n"
            f"      jmax: 70\n"
            f"      s1: 0\n"
            f"      s2: 0\n"
            f"      h1: 1\n"
            f"      h2: 2\n"
            f"      h3: 3\n"
            f"      h4: 4\n"
            f'      i1: "<b 0xc700000001><r 8><b 0x00000000>"\n'
        )

    names_block = "\n".join(f"      - {p}" for p in proxy_names)
    yaml_text = (
        f"mixed-port: {socks_port}\n"
        f"bind-address: {socks_host}\n"
        f"allow-lan: false\n"
        f"mode: global\n"
        f"log-level: warning\n"
        f"ipv6: true\n"
        f"\n"
        f"proxies:\n"
        + "".join(proxies_blocks)
        + "\n"
        f"proxy-groups:\n"
        f"  - name: GLOBAL\n"
        f"    type: url-test\n"
        f'    url: "https://www.cloudflare.com/cdn-cgi/trace"\n'
        f"    interval: 90\n"
        f"    timeout: 3000\n"
        f"    max-failed-times: 1\n"
        f"    tolerance: 80\n"
        f"    lazy: false\n"
        f"    proxies:\n"
        f"{names_block}\n"
    )

    tmp = MIHOMO_RUNTIME_YAML.with_suffix(".yaml.tmp")
    tmp.write_text(yaml_text, encoding="utf-8")
    tmp.replace(MIHOMO_RUNTIME_YAML)
    return MIHOMO_RUNTIME_YAML


# ---------------------------------------------------------------------------
# SOCKS5 health & latency probes
# ---------------------------------------------------------------------------
def _socks5_https_get(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_path: str,
    timeout: float = 6.0,
) -> Tuple[bool, int, str, int, str]:
    started = time.perf_counter()
    raw_sock: Optional[socket.socket] = None
    tls_sock: Optional[ssl.SSLSocket] = None
    try:
        raw_sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
        raw_sock.settimeout(timeout)

        raw_sock.sendall(b"\x05\x01\x00")
        resp = raw_sock.recv(2)
        if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
            return False, 0, "", 0, f"SOCKS5 auth failed: {resp!r}"

        host_bytes = target_host.encode("ascii")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", 443)
        raw_sock.sendall(req)

        hdr = raw_sock.recv(4)
        if len(hdr) != 4 or hdr[0] != 5 or hdr[1] != 0:
            rep = hdr[1] if len(hdr) >= 2 else -1
            return False, 0, "", 0, f"SOCKS5 connect rejected (code {rep})"

        atyp = hdr[3]
        if atyp == 1:
            raw_sock.recv(4 + 2)
        elif atyp == 3:
            alen = raw_sock.recv(1)[0]
            raw_sock.recv(alen + 2)
        elif atyp == 4:
            raw_sock.recv(16 + 2)

        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=target_host)
        tls_sock.settimeout(timeout)

        http_req = (
            f"GET {target_path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: PryWarp-Bridge/{BRIDGE_VERSION}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        tls_sock.sendall(http_req)

        chunks = []
        total_len = 0
        while total_len < 8192:
            chunk = tls_sock.recv(2048)
            if not chunk:
                break
            chunks.append(chunk)
            total_len += len(chunk)

        latency_ms = int((time.perf_counter() - started) * 1000)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        head, _, body = text.partition("\r\n\r\n")
        status_code = 0
        first_line = head.splitlines()[0] if head else ""
        parts = first_line.split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
        return True, status_code, body, latency_ms, ""
    except Exception as exc:
        return False, 0, "", 0, str(exc)
    finally:
        for s in (tls_sock, raw_sock):
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass


def _wait_socks_port(socks_host: str, socks_port: int, timeout: float = 4.0) -> bool:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection((socks_host, socks_port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.08)
    return False


def socks5_cloudflare_and_youtube_probe(
    socks_host: str,
    socks_port: int,
    timeout: float = 6.0,
) -> Tuple[bool, Dict[str, Any]]:
    cf_res: Dict[str, Any] = {}
    yt_res: Dict[str, Any] = {}

    def _run_cf() -> None:
        cf_res["val"] = _socks5_https_get(
            socks_host, socks_port, "www.cloudflare.com", "/cdn-cgi/trace", timeout=timeout
        )

    def _run_yt() -> None:
        yt_res["val"] = _socks5_https_get(
            socks_host, socks_port, "www.youtube.com", "/generate_204", timeout=timeout
        )

    t1 = threading.Thread(target=_run_cf, daemon=True)
    t2 = threading.Thread(target=_run_yt, daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout + 1.5)
    t2.join(timeout + 1.5)

    ok, status, body, latency_ms, err = cf_res.get("val", (False, 0, "", 0, "Cloudflare probe timeout"))
    if not ok or status != 200:
        return False, {"error": err or f"Cloudflare trace HTTP {status}"}

    fields: Dict[str, str] = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()

    warp_state = fields.get("warp", "off")
    colo = fields.get("colo", "")
    loc = fields.get("loc", "")
    if warp_state not in ("on", "plus"):
        return False, {
            "warp": warp_state,
            "colo": colo,
            "loc": loc,
            "latency_ms": latency_ms,
            "error": f"Unexpected warp state: {warp_state}",
        }

    yt_ok, yt_status, _, yt_ms, yt_err = yt_res.get("val", (False, 0, "", 0, "YouTube probe timeout"))
    if not yt_ok or yt_status not in (200, 204):
        return False, {
            "warp": warp_state,
            "colo": colo,
            "loc": loc,
            "latency_ms": latency_ms,
            "youtube_ok": False,
            "error": yt_err or f"YouTube check failed (HTTP {yt_status})",
        }

    return True, {
        "warp": warp_state,
        "colo": colo,
        "loc": loc,
        "latency_ms": latency_ms,
        "youtube_ok": True,
        "youtube_ms": yt_ms,
    }


def _set_usque_config_endpoint(endpoint_ip: str) -> None:
    if not WARP_CONFIG.exists():
        return
    try:
        data = json.loads(WARP_CONFIG.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            return
        changed = False
        if data.get("endpoint_v4") != endpoint_ip:
            data["endpoint_v4"] = endpoint_ip
            changed = True
        # Always keep cert-pinned HTTP/2 endpoint on 162.159.198.2
        if data.get("endpoint_h2_v4") != HTTP2_ENDPOINT:
            data["endpoint_h2_v4"] = HTTP2_ENDPOINT
            changed = True
        if changed:
            tmp = WARP_CONFIG.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(WARP_CONFIG)
            log_line(f"Updated usque endpoints (quic={endpoint_ip}, h2={HTTP2_ENDPOINT})")
    except Exception as exc:
        log_line(f"Endpoint update warning: {exc}")


# ---------------------------------------------------------------------------
# Hybrid Fail-Safe Supervisor (AmneziaWG via mihomo + MASQUE via usque)
# ---------------------------------------------------------------------------
class WarpSupervisor:
    def __init__(self, settings: Dict[str, Any]) -> None:
        self.settings = settings
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.proc: Optional[subprocess.Popen] = None

        self.has_mihomo: bool = MIHOMO_EXE.exists()
        self.has_usque: bool = USQUE_EXE.exists()
        self.mihomo_version: str = self._detect_mihomo_version()
        self.usque_version: str = self._detect_usque_version()

        mode = settings.get("transport_mode", "auto")
        self.active_transport: str = self._resolve_initial_transport(mode)
        self.active_engine: str = "mihomo" if self.active_transport == "awg" else "usque"
        self.awg_endpoint_idx: int = 0
        self.masque_endpoint_idx: int = 0

        self.state: str = "starting"
        self.warp_status: str = "off"
        self.colo: str = ""
        self.loc: str = ""
        self.latency_ms: Optional[int] = None
        self.youtube_ms: Optional[int] = None
        self.youtube_ok: bool = False
        self.last_error: str = ""
        self.started_at: float = time.time()
        self.last_probe_at: float = 0.0
        self.consecutive_failures: int = 0
        self.restarts: int = 0
        self.proc_gen: int = 0
        self.proc_started_at: float = 0.0
        self.cold_start_pending: bool = False
        self.cold_warmup_misses: int = 0
        self.fallback_since: Optional[float] = None
        self.recovery_backoff_mult: int = 1
        self.masque_connected_event = threading.Event()
        self.socks_listening_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _resolve_initial_transport(self, mode: str) -> str:
        if mode == "awg":
            return "awg" if self.has_mihomo else ("http2" if self.has_usque else "awg")
        if mode in ("http2", "quic"):
            return mode if self.has_usque else ("awg" if self.has_mihomo else mode)
        # "auto": AmneziaWG (mihomo) primary -> HTTP/2 (usque) backup
        return "awg" if self.has_mihomo else "http2"

    def _detect_mihomo_version(self) -> str:
        if not MIHOMO_EXE.exists():
            return "missing"
        try:
            res = subprocess.run(
                [str(MIHOMO_EXE), "-v"],
                capture_output=True,
                text=True,
                timeout=4,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            out = (res.stdout or res.stderr or "").strip()
            m = re.search(r"v\d+\.\d+\.\d+", out)
            return m.group(0) if m else "installed"
        except Exception:
            return "installed"

    def _detect_usque_version(self) -> str:
        if not USQUE_EXE.exists():
            return "missing"
        try:
            res = subprocess.run(
                [str(USQUE_EXE), "version"],
                capture_output=True,
                text=True,
                timeout=4,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            out = (res.stdout or res.stderr or "").strip()
            m = re.search(r"v?\d+\.\d+\.\d+", out)
            return m.group(0) if m else "installed"
        except Exception:
            return "installed"

    def _ensure_usque_registered(self) -> bool:
        if not USQUE_EXE.exists():
            self.state = "error"
            self.last_error = f"Не найден бинарник usque.exe в {BRIDGE_DIR}"
            log_line(self.last_error)
            return False
        if WARP_CONFIG.exists() and WARP_CONFIG.stat().st_size > 100:
            return True
        log_line("WARP config.json missing — registering free Cloudflare WARP (usque)...")
        try:
            res = subprocess.run(
                [str(USQUE_EXE), "-c", str(WARP_CONFIG), "register", "-a"],
                capture_output=True,
                text=True,
                timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if res.returncode == 0 and WARP_CONFIG.exists():
                log_line("Free WARP (usque) registration succeeded.")
                return True
            self.last_error = f"Ошибка регистрации WARP (код {res.returncode})"
            log_line(self.last_error)
            return False
        except Exception as exc:
            self.last_error = f"Ошибка запуска регистрации WARP: {exc}"
            log_line(self.last_error)
            return False

    def _pump_proc_output(self, proc: subprocess.Popen, tag: str) -> None:
        stream = proc.stdout
        if stream is None:
            return
        try:
            for raw_line in iter(stream.readline, ""):
                if not raw_line:
                    break
                clean = _ANSI_RE.sub("", raw_line).strip()
                if not clean:
                    continue
                if "SOCKS proxy listening" in clean or "Mixed(http+socks) proxy listening" in clean:
                    self.socks_listening_event.set()
                if "Connected to MASQUE server" in clean:
                    self.masque_connected_event.set()
                log_line(f"[{tag}] {clean[:300]}")
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def _stop_proc_locked(self) -> None:
        if self.proc is not None:
            proc = self.proc
            self.proc = None
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2)
            except Exception:
                pass

    def _start_proc_locked(self, transport: str) -> bool:
        self._stop_proc_locked()
        self.masque_connected_event.clear()
        self.socks_listening_event.clear()

        mtu = int(self.settings.get("mtu", 1280))
        dns_list = list(self.settings.get("dns_servers") or ["1.1.1.1", "1.0.0.1"])
        socks_host = str(self.settings["socks_host"])
        socks_port = int(self.settings["socks_port"])

        if transport == "awg":
            if not MIHOMO_EXE.exists():
                if USQUE_EXE.exists():
                    log_line("mihomo.exe missing — falling back to usque HTTP/2")
                    return self._start_proc_locked("http2")
                self.state = "error"
                self.last_error = f"Не найден mihomo.exe в {BRIDGE_DIR}"
                log_line(self.last_error)
                return False

            account = load_or_create_awg_account(base_socks_port=socks_port)
            if not account:
                if self.settings.get("transport_mode", "auto") == "auto" and USQUE_EXE.exists():
                    log_line("AmneziaWG registration unavailable — falling back to usque HTTP/2")
                    self.fallback_since = time.time()
                    return self._start_proc_locked("http2")
                self.state = "error"
                self.last_error = "Не удалось получить анонимный ключ WARP"
                return False

            cfg_path = write_mihomo_runtime_yaml(
                account=account,
                socks_host=socks_host,
                socks_port=socks_port,
                mtu=mtu,
                dns_servers=dns_list,
                endpoint_offset=self.awg_endpoint_idx,
            )
            primary_ep = AWG_ENDPOINTS[self.awg_endpoint_idx % len(AWG_ENDPOINTS)]
            cmd = [str(MIHOMO_EXE), "-d", str(BRIDGE_DIR), "-f", str(cfg_path)]
            tag = "mihomo"
            engine = "mihomo"
            log_line(
                f"Starting mihomo AmneziaWG (+i1, primary={primary_ep[0]}:{primary_ep[1]}, pool={len(AWG_ENDPOINTS)}, mtu={mtu}) "
                f"on {socks_host}:{socks_port}"
            )
        else:
            if not self._ensure_usque_registered():
                return False
            endpoint_ip = PREFERRED_MASQUE_ENDPOINTS[self.masque_endpoint_idx % len(PREFERRED_MASQUE_ENDPOINTS)]
            _set_usque_config_endpoint(endpoint_ip)
            cmd = [
                str(USQUE_EXE),
                "-c",
                str(WARP_CONFIG),
                "socks",
                "-b",
                socks_host,
                "-p",
                str(socks_port),
                "--always-reconnect",
                "-m",
                str(mtu),
                "-k",
                "15s",
                "-t",
                "2s",
                "-r",
                "1s",
            ]
            for dns_ip in dns_list:
                cmd.extend(["-d", str(dns_ip)])
            if transport == "http2":
                cmd.append("--http2")
            tag = "usque"
            engine = "usque"
            shown_ep = HTTP2_ENDPOINT if transport == "http2" else endpoint_ip
            log_line(
                f"Starting usque ({transport}, ep={shown_ep}, mtu={mtu}, dns={','.join(dns_list)}) "
                f"on {socks_host}:{socks_port}"
            )

        try:
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            proc = subprocess.Popen(
                cmd,
                cwd=str(BRIDGE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creation_flags,
            )
            self.proc = proc
            self.proc_gen += 1
            threading.Thread(
                target=self._pump_proc_output,
                args=(proc, tag),
                name=f"{tag}-log-pump",
                daemon=True,
            ).start()
            self.active_transport = transport
            self.active_engine = engine
            self.proc_started_at = time.time()
            self.cold_start_pending = True
            self.cold_warmup_misses = 0
            self.state = "connecting"
            self.warp_status = "off"
            self.colo = ""
            self.latency_ms = None
            self.youtube_ms = None
            self.youtube_ok = False
            self.last_error = ""
            return True
        except Exception as exc:
            self.state = "error"
            self.last_error = f"Не удалось запустить {engine}: {exc}"
            log_line(self.last_error)
            return False

    def start(self) -> None:
        with self.lock:
            self._start_proc_locked(self.active_transport)
        self._thread = threading.Thread(target=self._watchdog_loop, name="warp-watchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        with self.lock:
            self._stop_proc_locked()
            self.state = "offline"
            self.warp_status = "off"
            self.youtube_ok = False
        log_line("WARP Bridge stopped cleanly.")

    def _wait_ready_before_probe(self) -> None:
        with self.lock:
            socks_host = str(self.settings["socks_host"])
            socks_port = int(self.settings["socks_port"])
            engine = self.active_engine
        if engine == "mihomo":
            _wait_socks_port(socks_host, socks_port, timeout=4.0)
            # Give mihomo url-test a short head start to pick the best live endpoint
            time.sleep(0.85)
        else:
            if not self.socks_listening_event.wait(timeout=2.5):
                _wait_socks_port(socks_host, socks_port, timeout=1.5)
            self.masque_connected_event.wait(timeout=2.0)

    def _probe_after_switch(self) -> None:
        self._wait_ready_before_probe()
        if not self.stop_event.is_set():
            self.run_probe()

    def reconnect(self, force_transport: Optional[str] = None, wait: bool = False) -> Dict[str, Any]:
        with self.lock:
            if force_transport in VALID_TRANSPORTS:
                target = force_transport
            else:
                mode = self.settings.get("transport_mode", "auto")
                target = self._resolve_initial_transport(mode)
                # Manual Reset rotates primary endpoint in the pool for a fresh route
                if target == "awg":
                    self.awg_endpoint_idx = (self.awg_endpoint_idx + 1) % len(AWG_ENDPOINTS)
                elif target == "quic":
                    self.masque_endpoint_idx = (self.masque_endpoint_idx + 1) % len(PREFERRED_MASQUE_ENDPOINTS)
            self.restarts += 1
            self.consecutive_failures = 0
            self.fallback_since = None
            self.recovery_backoff_mult = 1
            log_line(f"Reconnect requested (target={target}, restart #{self.restarts})")
            self._start_proc_locked(target)
        if wait:
            self._probe_after_switch()
        else:
            threading.Thread(target=self._probe_after_switch, name="warp-switch-probe", daemon=True).start()
        return self.get_status()

    def set_transport_mode(self, mode: str) -> Dict[str, Any]:
        if mode not in VALID_MODES:
            raise ValueError("Invalid transport mode")
        restart_needed = False
        target = self.active_transport
        with self.lock:
            prev_mode = self.settings.get("transport_mode", "auto")
            self.settings["transport_mode"] = mode
            save_settings(self.settings)
            target = self._resolve_initial_transport(mode)
            if self.active_transport != target or prev_mode != mode or self.state != "online":
                restart_needed = True
        if restart_needed:
            return self.reconnect(force_transport=target, wait=False)
        return self.get_status()

    def run_probe(self) -> bool:
        with self.lock:
            socks_host = str(self.settings["socks_host"])
            socks_port = int(self.settings["socks_port"])
            proc_alive = self.proc is not None and self.proc.poll() is None
            cold = self.cold_start_pending
            gen = self.proc_gen

        if not proc_alive:
            with self.lock:
                if self.proc_gen != gen:
                    return False
                self.state = "reconnecting"
                self.warp_status = "off"
                self.youtube_ok = False
                self.last_error = f"Процесс {self.active_engine} остановился, перезапуск..."
            return False

        probe_timeout = 10.0 if cold else 6.5
        ok, info = socks5_cloudflare_and_youtube_probe(socks_host, socks_port, timeout=probe_timeout)
        now = time.time()
        with self.lock:
            if self.proc_gen != gen or self.stop_event.is_set():
                return False
            self.last_probe_at = now
            if ok:
                self.state = "online"
                self.warp_status = info.get("warp", "on")
                self.colo = info.get("colo", "")
                self.loc = info.get("loc", "")
                self.latency_ms = info.get("latency_ms")
                self.youtube_ok = bool(info.get("youtube_ok", True))
                self.youtube_ms = info.get("youtube_ms")
                self.last_error = ""
                self.consecutive_failures = 0
                self.cold_start_pending = False
                self.cold_warmup_misses = 0
                if self.active_transport == "awg":
                    self.fallback_since = None
                    self.recovery_backoff_mult = 1
                return True
            else:
                # Give AmneziaWG url-test up to 2 warm-up passes (~25s) before ever counting failures
                max_warmups = 2 if self.active_transport == "awg" else 1
                if self.cold_start_pending and self.cold_warmup_misses < max_warmups and (now - self.proc_started_at) < 25.0:
                    self.cold_warmup_misses += 1
                    self.state = "connecting"
                    self.last_error = info.get("error", "Прогрев туннеля...")
                    log_line(
                        f"Cold-start warm-up probe {self.cold_warmup_misses}/{max_warmups} on {self.active_transport}: {self.last_error}"
                    )
                    return False

                self.cold_start_pending = False
                self.consecutive_failures += 1
                self.warp_status = info.get("warp", "off")
                self.youtube_ok = False
                self.last_error = info.get("error", "Таймаут проверки туннеля")
                self.state = "reconnecting"
                log_line(
                    f"Probe failed ({self.consecutive_failures}) on {self.active_transport}: {self.last_error}"
                )
                return False

    def _watchdog_loop(self) -> None:
        self._wait_ready_before_probe()
        prev_tick = time.time()
        while not self.stop_event.is_set():
            try:
                now = time.time()
                woke_from_sleep = (now - prev_tick) > 30.0
                prev_tick = now
                if woke_from_sleep:
                    log_line("System resume detected — re-verifying WARP tunnel immediately.")

                with self.lock:
                    proc_dead = self.proc is None or self.proc.poll() is not None
                    probe_interval = max(10, int(self.settings.get("probe_interval_sec", 45)))
                    failover_threshold = max(3, int(self.settings.get("failover_threshold", 5)))
                    recovery_retry = max(60, int(self.settings.get("recovery_retry_sec", 180)))
                    mode = self.settings.get("transport_mode", "auto")

                if proc_dead:
                    log_line(f"Watchdog detected {self.active_engine} exit — restarting...")
                    with self.lock:
                        self.restarts += 1
                        self._start_proc_locked(self.active_transport)
                    self._wait_ready_before_probe()
                    continue

                # In auto mode, periodically recover from backup HTTP/2 back to high-speed AmneziaWG
                should_recover = False
                with self.lock:
                    if (
                        mode == "auto"
                        and self.has_mihomo
                        and self.active_transport != "awg"
                        and self.fallback_since is not None
                        and (now - self.fallback_since) >= recovery_retry * self.recovery_backoff_mult
                    ):
                        should_recover = True
                        self.restarts += 1
                        self.consecutive_failures = 0
                        self.fallback_since = now
                        self.recovery_backoff_mult = min(3, self.recovery_backoff_mult + 1)
                        log_line(f"Auto-recovery: retrying primary transport {self.active_transport} -> awg")
                        self._start_proc_locked("awg")
                if should_recover:
                    self._wait_ready_before_probe()
                    continue

                need_probe = woke_from_sleep or (now - self.last_probe_at >= probe_interval) or (self.state != "online")
                if need_probe:
                    ok = self.run_probe()
                    if not ok:
                        need_wait_ready = False
                        with self.lock:
                            failures = self.consecutive_failures
                            # Strict priority to AmneziaWG: rotate & restart AmneziaWG on failure #2 and #4;
                            # only fall back to HTTP/2 on full sustained outage (>= failover_threshold, default 5).
                            if (
                                mode == "auto"
                                and self.active_transport == "awg"
                                and failures in (2, 4)
                                and failures < failover_threshold
                            ):
                                self.awg_endpoint_idx = (self.awg_endpoint_idx + 1) % len(AWG_ENDPOINTS)
                                self.restarts += 1
                                log_line(
                                    f"AmneziaWG soft-retry ({failures}/{failover_threshold}): rotating endpoint before any HTTP/2 fallback"
                                )
                                self._start_proc_locked("awg")
                                need_wait_ready = True
                            elif failures >= failover_threshold:
                                if mode == "auto":
                                    if self.active_transport == "awg" and self.has_usque:
                                        next_t = "http2"
                                        self.fallback_since = time.time()
                                    elif self.active_transport == "http2" and self.has_mihomo:
                                        next_t = "awg"
                                        self.awg_endpoint_idx = (self.awg_endpoint_idx + 1) % len(AWG_ENDPOINTS)
                                        self.fallback_since = None
                                    else:
                                        next_t = self.active_transport
                                        self.awg_endpoint_idx = (self.awg_endpoint_idx + 1) % len(AWG_ENDPOINTS)
                                    log_line(
                                        f"Auto-failover: switching transport {self.active_transport} -> {next_t}"
                                    )
                                else:
                                    next_t = self.active_transport
                                    if next_t == "awg":
                                        self.awg_endpoint_idx = (self.awg_endpoint_idx + 1) % len(AWG_ENDPOINTS)
                                    elif next_t == "quic":
                                        self.masque_endpoint_idx = (self.masque_endpoint_idx + 1) % len(
                                            PREFERRED_MASQUE_ENDPOINTS
                                        )
                                    log_line(f"Watchdog restarting {next_t} on rotated endpoint")
                                self.restarts += 1
                                self.consecutive_failures = 0
                                self._start_proc_locked(next_t)
                                need_wait_ready = True
                        if need_wait_ready:
                            self._wait_ready_before_probe()
                            continue
            except Exception as exc:
                log_line(f"Watchdog loop recovered from error: {exc}")

            self.stop_event.wait(2.5)

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            if self.active_transport == "awg":
                ep_host, ep_port = AWG_ENDPOINTS[self.awg_endpoint_idx % len(AWG_ENDPOINTS)]
                ep_str = f"{ep_host}:{ep_port}"
            elif self.active_transport == "http2":
                ep_str = f"{HTTP2_ENDPOINT}:443"
            else:
                ep_str = f"{PREFERRED_MASQUE_ENDPOINTS[self.masque_endpoint_idx % len(PREFERRED_MASQUE_ENDPOINTS)]}:443"

            pid = self.proc.pid if (self.proc is not None and self.proc.poll() is None) else None
            return {
                "ok": self.state == "online",
                "bridge_version": BRIDGE_VERSION,
                "engine": self.active_engine,
                "mihomo_version": self.mihomo_version,
                "usque_version": self.usque_version,
                "state": self.state,
                "warp": self.warp_status,
                "colo": self.colo,
                "loc": self.loc,
                "latency_ms": self.latency_ms,
                "youtube_ok": self.youtube_ok,
                "youtube_ms": self.youtube_ms,
                "transport": self.active_transport,
                "transport_mode": self.settings.get("transport_mode", "auto"),
                "mtu": int(self.settings.get("mtu", 1280)),
                "endpoint": ep_str,
                "socks_host": self.settings["socks_host"],
                "socks_port": int(self.settings["socks_port"]),
                "api_port": int(self.settings["api_port"]),
                "uptime_sec": int(time.time() - self.started_at),
                "restarts": self.restarts,
                "engine_pid": pid,
                "usque_pid": pid,
                "last_error": self.last_error,
                "install_dir": str(BRIDGE_DIR),
            }


def check_engine_github_release() -> Dict[str, Any]:
    url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"PryWarp-Bridge/{BRIDGE_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return {
            "ok": True,
            "latest_tag": data.get("tag_name", ""),
            "html_url": data.get("html_url", "https://github.com/MetaCubeX/mihomo/releases"),
            "published_at": data.get("published_at", ""),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def make_handler(supervisor: WarpSupervisor, shutdown_cb):
    class ApiHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _is_allowed_origin(self) -> Tuple[bool, str]:
            origin = self.headers.get("Origin", "")
            if not origin:
                return True, "*"
            allowed_prefixes = (
                "chrome-extension://",
                "moz-extension://",
                "http://127.0.0.1",
                "http://localhost",
            )
            if origin.startswith(allowed_prefixes):
                return True, origin
            return False, ""

        def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
            ok_origin, allow_origin = self._is_allowed_origin()
            if not ok_origin:
                self.send_response(403)
                self.end_headers()
                return
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", allow_origin)
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:
            ok_origin, allow_origin = self._is_allowed_origin()
            if not ok_origin:
                self.send_response(403)
                self.end_headers()
                return
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", allow_origin)
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_GET(self) -> None:
            if self.path == "/api/status":
                self._send_json(200, supervisor.get_status())
            elif self.path == "/api/health":
                st = supervisor.get_status()
                self._send_json(200 if st["ok"] else 503, st)
            else:
                self._send_json(404, {"ok": False, "error": "Not found"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(min(length, 16384)) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                body = {}

            if self.path == "/api/reconnect":
                transport = body.get("transport") if isinstance(body, dict) else None
                st = supervisor.reconnect(force_transport=transport)
                self._send_json(200, st)
            elif self.path == "/api/transport":
                mode = body.get("mode", "") if isinstance(body, dict) else ""
                if mode not in VALID_MODES:
                    self._send_json(400, {"ok": False, "error": "Invalid mode"})
                    return
                st = supervisor.set_transport_mode(mode)
                self._send_json(200, st)
            elif self.path == "/api/probe":
                supervisor.run_probe()
                self._send_json(200, supervisor.get_status())
            elif self.path == "/api/check-usque-update":
                res = check_engine_github_release()
                res["current_version"] = supervisor.mihomo_version
                self._send_json(200, res)
            elif self.path == "/api/stop":
                self._send_json(200, {"ok": True, "stopping": True})
                threading.Thread(target=shutdown_cb, daemon=True).start()
            else:
                self._send_json(404, {"ok": False, "error": "Not found"})

    return ApiHandler


def main() -> int:
    settings = load_settings()
    save_settings(settings)

    api_host = settings["api_host"]
    api_port = int(settings["api_port"])

    # Single-instance guard
    try:
        with urllib.request.urlopen(f"http://{api_host}:{api_port}/api/status", timeout=1.5) as resp:
            if resp.status == 200:
                log_line(f"WARP Bridge is already running on {api_host}:{api_port}; skipping duplicate start.")
                return 0
    except Exception:
        pass

    supervisor = WarpSupervisor(settings)
    server_holder: Dict[str, Optional[ThreadingHTTPServer]] = {"server": None}

    def shutdown_all(*_args: Any) -> None:
        supervisor.stop()
        srv = server_holder.get("server")
        if srv is not None:
            try:
                srv.shutdown()
            except Exception:
                pass

    signal.signal(signal.SIGINT, shutdown_all)
    signal.signal(signal.SIGTERM, shutdown_all)

    supervisor.start()

    try:
        server = ThreadingHTTPServer((api_host, api_port), make_handler(supervisor, shutdown_all))
    except OSError as exc:
        log_line(f"Failed to bind API on {api_host}:{api_port}: {exc}")
        supervisor.stop()
        return 1

    server_holder["server"] = server
    log_line(
        f"PryWarp Bridge v{BRIDGE_VERSION} listening: SOCKS5 {settings['socks_host']}:{settings['socks_port']} | API http://{api_host}:{api_port}"
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        supervisor.stop()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
