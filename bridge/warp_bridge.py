"""
WARP Bridge Supervisor — fail-safe local Cloudflare WARP (usque) manager
with automatic health checks (Cloudflare trace + YouTube generate_204),
QUIC <-> HTTP/2 failover, optimal Cloudflare DNS & MTU, and localhost control API.

Runs strictly in user-space (SOCKS5 on 127.0.0.1:10880, API on 127.0.0.1:10881).
Does NOT create VPN/TUN adapters, does NOT touch system routes, DNS, or hosts.
"""

from __future__ import annotations

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
from typing import Any, Dict, Optional, Tuple


def _resolve_bridge_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


BRIDGE_DIR = _resolve_bridge_dir()
USQUE_EXE = BRIDGE_DIR / "usque.exe"
WARP_CONFIG = BRIDGE_DIR / "config.json"
SETTINGS_FILE = BRIDGE_DIR / "bridge_settings.json"
LOG_FILE = BRIDGE_DIR / "bridge.log"

BRIDGE_VERSION = "1.1.1"

# Verified fastest Cloudflare WARP MASQUE endpoints on Rostelecom / RU networks
PREFERRED_ENDPOINTS = ("162.159.198.1", "162.159.198.2")

DEFAULT_SETTINGS: Dict[str, Any] = {
    "socks_host": "127.0.0.1",
    "socks_port": 10880,
    "api_host": "127.0.0.1",
    "api_port": 10881,
    "transport_mode": "auto",  # "auto" (QUIC first -> HTTP/2 failover) | "quic" | "http2"
    "probe_interval_sec": 20,
    "failover_threshold": 2,
    "quic_retry_interval_sec": 600,
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
            loaded = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data.update(loaded)
        except Exception as exc:
            log_line(f"Settings load warning: {exc}")
    data["socks_host"] = "127.0.0.1"
    data["api_host"] = "127.0.0.1"
    if data.get("transport_mode") not in ("auto", "http2", "quic"):
        data["transport_mode"] = "auto"
    if not isinstance(data.get("dns_servers"), list) or not data["dns_servers"]:
        data["dns_servers"] = list(DEFAULT_SETTINGS["dns_servers"])
    try:
        mtu = int(data.get("mtu", 1280))
        # Migrate legacy default 1360 -> official usque-supported 1280 unless marked custom
        if mtu == 1360 and not data.get("mtu_custom"):
            mtu = 1280
        data["mtu"] = max(1280, min(1420, mtu))
    except Exception:
        data["mtu"] = 1280
    return data


def save_settings(settings: Dict[str, Any]) -> None:
    tmp = SETTINGS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(SETTINGS_FILE)


def _socks5_https_get(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_path: str,
    timeout: float = 8.0,
) -> Tuple[bool, int, str, int, str]:
    """
    Lightweight HTTPS GET over SOCKS5 (ATYP=domain) using Python stdlib sockets + TLS.
    Returns (ok, http_status, body_text, latency_ms, error_msg).
    """
    started = time.perf_counter()
    raw_sock: Optional[socket.socket] = None
    tls_sock: Optional[ssl.SSLSocket] = None
    try:
        raw_sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
        raw_sock.settimeout(timeout)

        # SOCKS5 greeting: VER=5, NMETHODS=1, NO AUTH(0x00)
        raw_sock.sendall(b"\x05\x01\x00")
        resp = raw_sock.recv(2)
        if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
            return False, 0, "", 0, f"SOCKS5 auth failed: {resp!r}"

        # SOCKS5 CONNECT with domain name (ATYP=0x03) so DNS runs inside WARP tunnel
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
            f"User-Agent: WARP-Bridge/{BRIDGE_VERSION}\r\n"
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


def socks5_cloudflare_and_youtube_probe(
    socks_host: str,
    socks_port: int,
    timeout: float = 8.0,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verifies both Cloudflare WARP tunnel (warp=on) and real YouTube reachability (HTTP 204).
    """
    ok, status, body, latency_ms, err = _socks5_https_get(
        socks_host, socks_port, "www.cloudflare.com", "/cdn-cgi/trace", timeout=timeout
    )
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

    # Verify real YouTube reachability over the same tunnel
    yt_ok, yt_status, _, yt_ms, yt_err = _socks5_https_get(
        socks_host, socks_port, "www.youtube.com", "/generate_204", timeout=timeout
    )
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


def _set_config_endpoint(endpoint_ip: str) -> None:
    """Safely updates endpoint_v4/endpoint_h2_v4 in config.json without touching keys."""
    if not WARP_CONFIG.exists():
        return
    try:
        data = json.loads(WARP_CONFIG.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return
        changed = False
        if data.get("endpoint_v4") != endpoint_ip:
            data["endpoint_v4"] = endpoint_ip
            changed = True
        if data.get("endpoint_h2_v4") != endpoint_ip:
            data["endpoint_h2_v4"] = endpoint_ip
            changed = True
        if changed:
            tmp = WARP_CONFIG.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(WARP_CONFIG)
            log_line(f"Updated WARP MASQUE endpoint to {endpoint_ip}")
    except Exception as exc:
        log_line(f"Endpoint update warning: {exc}")


class WarpSupervisor:
    def __init__(self, settings: Dict[str, Any]) -> None:
        self.settings = settings
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.proc: Optional[subprocess.Popen] = None

        # In auto mode, start with QUIC (HTTP/3 UDP) — 3-5x faster for YouTube videoplayback;
        # auto-fails over to HTTP/2 TCP if QUIC fails 2 probes in a row.
        mode = settings.get("transport_mode", "auto")
        self.active_transport: str = "http2" if mode == "http2" else "quic"
        self.endpoint_idx: int = 0
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
        self.proc_started_at: float = 0.0
        self.cold_start_pending: bool = False
        self.cold_warmup_missed: bool = False
        self.http2_fallback_at: Optional[float] = None
        self.quic_retry_backoff_mult: int = 1
        self.usque_version: str = self._detect_usque_version()
        self._thread: Optional[threading.Thread] = None

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
            return m.group(0) if m else (out[:32] or "installed")
        except Exception:
            return "installed"

    def _ensure_registered(self) -> bool:
        if not USQUE_EXE.exists():
            self.state = "error"
            self.last_error = f"Не найден бинарник usque.exe в {BRIDGE_DIR}"
            log_line(self.last_error)
            return False
        if WARP_CONFIG.exists() and WARP_CONFIG.stat().st_size > 100:
            return True
        log_line("WARP config.json missing — registering free Cloudflare WARP account...")
        try:
            res = subprocess.run(
                [str(USQUE_EXE), "-c", str(WARP_CONFIG), "register", "-a"],
                capture_output=True,
                text=True,
                timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if res.returncode == 0 and WARP_CONFIG.exists():
                log_line("Free WARP registration succeeded.")
                return True
            self.last_error = f"Ошибка регистрации WARP (код {res.returncode})"
            log_line(self.last_error)
            return False
        except Exception as exc:
            self.last_error = f"Ошибка запуска регистрации WARP: {exc}"
            log_line(self.last_error)
            return False

    def _pump_proc_output(self, proc: subprocess.Popen) -> None:
        stream = proc.stdout
        if stream is None:
            return
        try:
            for raw_line in iter(stream.readline, ""):
                if not raw_line:
                    break
                clean = _ANSI_RE.sub("", raw_line).strip()
                if clean:
                    log_line(f"[usque] {clean[:300]}")
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def _stop_proc_locked(self) -> None:
        if self.proc is not None:
            try:
                if self.proc.stdout is not None:
                    try:
                        self.proc.stdout.close()
                    except Exception:
                        pass
                if self.proc.poll() is None:
                    self.proc.terminate()
                    try:
                        self.proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.proc.kill()
                        self.proc.wait(timeout=2)
            except Exception:
                pass
            self.proc = None

    def _start_proc_locked(self, transport: str) -> bool:
        self._stop_proc_locked()
        if not self._ensure_registered():
            return False

        endpoint_ip = PREFERRED_ENDPOINTS[self.endpoint_idx % len(PREFERRED_ENDPOINTS)]
        _set_config_endpoint(endpoint_ip)

        mtu = int(self.settings.get("mtu", 1280))
        dns_list = self.settings.get("dns_servers") or ["1.1.1.1", "1.0.0.1"]

        cmd = [
            str(USQUE_EXE),
            "-c",
            str(WARP_CONFIG),
            "socks",
            "-b",
            str(self.settings["socks_host"]),
            "-p",
            str(self.settings["socks_port"]),
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

        log_line(
            f"Starting usque ({transport}, ep={endpoint_ip}, mtu={mtu}, dns={','.join(dns_list)}) "
            f"on {self.settings['socks_host']}:{self.settings['socks_port']}"
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
            threading.Thread(
                target=self._pump_proc_output,
                args=(proc,),
                name="usque-log-pump",
                daemon=True,
            ).start()
            self.active_transport = transport
            self.proc_started_at = time.time()
            self.cold_start_pending = True
            self.cold_warmup_missed = False
            self.state = "connecting"
            self.last_error = ""
            return True
        except Exception as exc:
            self.state = "error"
            self.last_error = f"Не удалось запустить usque.exe: {exc}"
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

    def reconnect(self, force_transport: Optional[str] = None) -> Dict[str, Any]:
        with self.lock:
            if force_transport in ("http2", "quic"):
                target = force_transport
            elif self.settings["transport_mode"] in ("http2", "quic"):
                target = self.settings["transport_mode"]
            else:
                target = self.active_transport
                # On manual reconnect in auto mode, also rotate endpoint if previous had errors
                if self.last_error:
                    self.endpoint_idx = (self.endpoint_idx + 1) % len(PREFERRED_ENDPOINTS)
            self.restarts += 1
            self.consecutive_failures = 0
            self._start_proc_locked(target)
        time.sleep(1.5)
        self.run_probe()
        return self.get_status()

    def set_transport_mode(self, mode: str) -> Dict[str, Any]:
        if mode not in ("auto", "http2", "quic"):
            raise ValueError("Invalid transport mode")
        restart_needed = False
        with self.lock:
            self.settings["transport_mode"] = mode
            save_settings(self.settings)
            if mode in ("http2", "quic") and self.active_transport != mode:
                self.active_transport = mode
                restart_needed = True
            elif mode == "auto" and self.active_transport != "quic":
                self.active_transport = "quic"
                restart_needed = True
        if restart_needed:
            return self.reconnect(force_transport=self.active_transport)
        return self.get_status()

    def run_probe(self) -> bool:
        with self.lock:
            socks_host = str(self.settings["socks_host"])
            socks_port = int(self.settings["socks_port"])
            proc_alive = self.proc is not None and self.proc.poll() is None
            cold = self.cold_start_pending

        if not proc_alive:
            with self.lock:
                self.state = "reconnecting"
                self.warp_status = "off"
                self.youtube_ok = False
                self.last_error = "Процесс usque остановился, перезапуск..."
            return False

        probe_timeout = 14.0 if cold else 8.0
        ok, info = socks5_cloudflare_and_youtube_probe(socks_host, socks_port, timeout=probe_timeout)
        now = time.time()
        with self.lock:
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
                self.cold_warmup_missed = False
                if self.active_transport == "quic":
                    self.http2_fallback_at = None
                    self.quic_retry_backoff_mult = 1
                return True
            else:
                # Give QUIC/MASQUE one generous cold-start warm-up pass before counting towards failover
                if self.cold_start_pending and not self.cold_warmup_missed and (now - self.proc_started_at) < 20.0:
                    self.cold_warmup_missed = True
                    self.state = "connecting"
                    self.last_error = info.get("error", "Прогрев туннеля...")
                    log_line(f"Cold-start warm-up probe on {self.active_transport}: {self.last_error}")
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
        self.stop_event.wait(2.2)
        while not self.stop_event.is_set():
            with self.lock:
                proc_dead = self.proc is None or self.proc.poll() is not None
                probe_interval = max(10, int(self.settings.get("probe_interval_sec", 20)))
                failover_threshold = max(1, int(self.settings.get("failover_threshold", 2)))
                quic_retry_interval = max(60, int(self.settings.get("quic_retry_interval_sec", 600)))
                mode = self.settings.get("transport_mode", "auto")

            if proc_dead:
                log_line("Watchdog detected usque exit — restarting...")
                with self.lock:
                    self.restarts += 1
                    self._start_proc_locked(self.active_transport)
                self.stop_event.wait(2.2)
                continue

            now = time.time()

            # Periodically retry QUIC when running in HTTP/2 fallback in auto mode
            should_retry_quic = False
            with self.lock:
                if (
                    mode == "auto"
                    and self.active_transport == "http2"
                    and self.http2_fallback_at is not None
                    and (now - self.http2_fallback_at) >= quic_retry_interval * self.quic_retry_backoff_mult
                ):
                    should_retry_quic = True
                    self.endpoint_idx = (self.endpoint_idx + 1) % len(PREFERRED_ENDPOINTS)
                    self.restarts += 1
                    self.consecutive_failures = 0
                    self.http2_fallback_at = now
                    self.quic_retry_backoff_mult = min(3, self.quic_retry_backoff_mult + 1)
                    log_line("Auto-recovery: retrying transport http2 -> quic")
                    self._start_proc_locked("quic")
            if should_retry_quic:
                self.stop_event.wait(2.2)
                continue

            need_probe = (now - self.last_probe_at >= probe_interval) or (self.state != "online")
            if need_probe:
                ok = self.run_probe()
                if not ok:
                    with self.lock:
                        failures = self.consecutive_failures
                        if failures >= failover_threshold:
                            if mode == "auto":
                                next_t = "http2" if self.active_transport == "quic" else "quic"
                                if next_t == "quic":
                                    self.endpoint_idx = (self.endpoint_idx + 1) % len(PREFERRED_ENDPOINTS)
                                    self.http2_fallback_at = None
                                else:
                                    self.http2_fallback_at = time.time()
                                log_line(
                                    f"Auto-failover: switching transport {self.active_transport} -> {next_t}"
                                )
                            else:
                                next_t = self.active_transport
                                self.endpoint_idx = (self.endpoint_idx + 1) % len(PREFERRED_ENDPOINTS)
                                log_line(f"Watchdog restarting transport {next_t} on next endpoint")
                            self.restarts += 1
                            self.consecutive_failures = 0
                            self._start_proc_locked(next_t)
                    self.stop_event.wait(2.5)
                    continue

            self.stop_event.wait(2.5)

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "ok": self.state == "online",
                "bridge_version": BRIDGE_VERSION,
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
                "endpoint": PREFERRED_ENDPOINTS[self.endpoint_idx % len(PREFERRED_ENDPOINTS)],
                "socks_host": self.settings["socks_host"],
                "socks_port": int(self.settings["socks_port"]),
                "api_port": int(self.settings["api_port"]),
                "uptime_sec": int(time.time() - self.started_at),
                "restarts": self.restarts,
                "last_error": self.last_error,
                "install_dir": str(BRIDGE_DIR),
            }


def check_usque_github_release() -> Dict[str, Any]:
    url = "https://api.github.com/repos/Diniboy1123/usque/releases/latest"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"WARP-Bridge/{BRIDGE_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return {
            "ok": True,
            "latest_tag": data.get("tag_name", ""),
            "html_url": data.get("html_url", "https://github.com/Diniboy1123/usque/releases"),
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
                if mode not in ("auto", "http2", "quic"):
                    self._send_json(400, {"ok": False, "error": "Invalid mode"})
                    return
                st = supervisor.set_transport_mode(mode)
                self._send_json(200, st)
            elif self.path == "/api/probe":
                supervisor.run_probe()
                self._send_json(200, supervisor.get_status())
            elif self.path == "/api/check-usque-update":
                res = check_usque_github_release()
                res["current_version"] = supervisor.usque_version
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

    # Single-instance check
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
        f"WARP Bridge v{BRIDGE_VERSION} listening: SOCKS5 {settings['socks_host']}:{settings['socks_port']} | API http://{api_host}:{api_port}"
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        supervisor.stop()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
