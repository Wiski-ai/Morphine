#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Morphine - Stealth Recon Tool
Single-file Python tool intended to run on Kali / BlackArch.
Features:
 - Ultra-slow TCP stealth (SYN) scan (falls back to TCP connect if required)
 - Randomized delays between probes (low & slow)
 - User-Agent rotation for HTTP fingerprinting
 - Passive DNS enumeration via crt.sh
 - HTTP fingerprint (headers, title, status)
 - Terminal "GUI" (curses) inspired by tools like wifite/airgeddon
 - Export results to JSON
Notes:
 - This is an active scanner: you MUST have explicit authorization to test targets.
 - SYN scan requires root (raw sockets) and scapy.
 - The tool deliberately scans slowly; tune delays responsibly.
"""
from __future__ import annotations
import argparse
import threading
import concurrent.futures
import random
import time
import json
import socket
import sys
import os
import datetime
import traceback
import logging
from typing import List, Dict, Any, Optional, Set

import ipaddress

# Optional dependencies
try:
    from scapy.all import IP, TCP, sr1, send, conf  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    import requests  # type: ignore
    from bs4 import BeautifulSoup  # type: ignore
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

# curses UI
try:
    import curses  # type: ignore
    CURSES_AVAILABLE = True
except Exception:
    CURSES_AVAILABLE = False

# Setup logger
logger = logging.getLogger("Morphine")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
logger.addHandler(ch)

# Default configuration
DEFAULT_MIN_DELAY = 1.5   # seconds
DEFAULT_MAX_DELAY = 8.0   # seconds
DEFAULT_TIMEOUT = 5.0     # seconds for socket/connect/HTTP
DEFAULT_WORKERS = 8

USER_AGENTS = [
    # A small rotation list; can be expanded
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/116.0.5845.96 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
    " Version/16.1 Safari/605.1.15",
    "curl/7.86.0",
    "Wget/1.21.3 (linux-gnu)",
]

CRT_SH_URL = "https://crt.sh/"
DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5900,8080"

# ASCII art splash (will be printed in red)
ASCII_ART = r"""

 ███▄ ▄███▓ ▒█████   ██▀███   ██▓███   ██░ ██  ██▓ ███▄    █ ▓█████ 
▓██▒▀█▀ ██▒▒██▒  ██▒▓██ ▒ ██▒▓██░  ██▒▓██░ ██▒▓██▒ ██ ▀█   █ ▓█   ▀ 
▓██    ▓██░▒██░  ██▒▓██ ░▄█ ▒▓██░ ██▓▒▒██▀▀██░▒██▒▓██  ▀█ ██▒▒███   
▒██    ▒██ ▒██   ██░▒██▀▀█▄  ▒██▄█▓▒ ▒░▓█ ░██ ░██░▓██▒  ▐▌██▒▒▓█  ▄ 
▒██▒   ░██▒░ ████▓▒░░██▓ ▒██▒▒██▒ ░  ░░▓█▒░██▓░██░▒██░   ▓██░░▒████▒
░ ▒░   ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░▒▓▒░ ░  ░ ▒ ░░▒░▒░▓  ░ ▒░   ▒ ▒ ░░ ▒░ ░
░  ░      ░  ░ ▒ ▒░   ░▒ ░ ▒░░▒ ░      ▒ ░▒░ ░ ▒ ░░ ░░   ░ ▒░ ░ ░  ░
░      ░   ░ ░ ░ ▒    ░░   ░ ░░        ░  ░░ ░ ▒ ░   ░   ░ ░    ░   
       ░       ░ ░     ░               ░  ░  ░ ░           ░    ░  ░
                                                                    
                         dev by H8Laws
"""

# Results storage
LOCK = threading.Lock()

class ScanResult:
    def __init__(self, host: str):
        self.host = host
        self.port_status: Dict[int, str] = {}  # port -> "open"/"closed"/"filtered"/"unknown"
        self.http: Optional[Dict[str, Any]] = None
        self.notes: List[str] = []
        self.started_at = datetime.datetime.utcnow().isoformat() + "Z"

    def to_dict(self):
        return {
            "host": self.host,
            "started_at": self.started_at,
            "port_status": self.port_status,
            "http": self.http,
            "notes": self.notes,
        }

def passive_dns_crtsh(domain: str, timeout: float = 8.0) -> Set[str]:
    """Passive enumeration using crt.sh JSON output. Uses requests with params to avoid manual encoding."""
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("requests not installed; passive DNS unavailable.")
    subs: Set[str] = set()
    try:
        # use params to build the proper query string safely
        params = {"q": f"%{domain}", "output": "json"}
        resp = requests.get(CRT_SH_URL, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        for entry in data:
            name = entry.get("name_value")
            if not name:
                continue
            for line in name.splitlines():
                line = line.strip()
                if line.startswith("*."):
                    line = line[2:]
                if line.endswith(domain):
                    subs.add(line)
    except Exception as e:
        logger.warning(f"crt.sh lookup failed for {domain}: {e}")
    return subs

def rotate_user_agent() -> str:
    return random.choice(USER_AGENTS)

def http_fingerprint(host: str, port: int = 80, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Basic HTTP fingerprint: status code, server header, title, content-type."""
    result = {
        "host": host,
        "port": port,
        "url": None,
        "status": None,
        "server": None,
        "content_type": None,
        "title": None,
        "error": None,
        "redirects": [],
    }
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not installed"
        return result

    # choose scheme order based on port: if 443 prefer https, if 80 prefer http
    schemes = []
    if port == 443:
        schemes = [("https", 443), ("http", 80)]
    elif port == 80:
        schemes = [("http", 80), ("https", 443)]
    else:
        schemes = [("https", 443), ("http", 80)]

    for scheme, default_port in schemes:
        try:
            # include port only when non-standard for scheme
            if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
                url = f"{scheme}://{host}:{port}"
            else:
                url = f"{scheme}://{host}"
            headers = {"User-Agent": rotate_user_agent(), "Accept": "*/*"}
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            result["url"] = url
            result["status"] = r.status_code
            result["server"] = r.headers.get("Server")
            result["content_type"] = r.headers.get("Content-Type")
            if r.history:
                # r.history contains Response objects for redirects; use their Location if present
                redirects = []
                for h in r.history:
                    loc = h.headers.get("Location") or h.headers.get("location") or ""
                    redirects.append(loc)
                result["redirects"] = redirects
            # try to parse title
            ct = r.headers.get("Content-Type", "")
            if r.text and ("html" in ct.lower() or "<html" in r.text[:200].lower()):
                try:
                    soup = BeautifulSoup(r.text, "html.parser")
                    if soup.title and soup.title.string:
                        result["title"] = soup.title.string.strip()
                except Exception:
                    pass
            return result
        except requests.exceptions.SSLError:
            # try next scheme
            continue
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            # if https failed, try http; otherwise return error
            if scheme == "https":
                continue
            return result
        except Exception as e:
            result["error"] = str(e)
            return result
    # if we get here, nothing worked
    if result["status"] is None and result["error"] is None:
        result["error"] = "No HTTP response obtained"
    return result

def tcp_connect_scan(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """A simple TCP connect scan (no raw sockets). Uses socket.create_connection for better behavior."""
    try:
        # socket.create_connection accepts hostnames and handles IPv4/IPv6 resolution
        s = socket.create_connection((host, port), timeout=timeout)
        try:
            s.close()
        except Exception:
            pass
        return "open"
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError as e:
        # name resolution failures, network unreachable, etc.
        logger.debug(f"tcp_connect_scan error for {host}:{port} -> {e}")
        return "filtered"
    except Exception as e:
        logger.debug(f"tcp_connect_scan unexpected error for {host}:{port} -> {e}")
        return "filtered"

def syn_scan_scapy(host: str, port: int, timeout: float = 3.0) -> str:
    """SYN scan using scapy. Requires root and scapy."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy not available")
    # send SYN and wait for response
    conf.verb = 0
    ip = IP(dst=host)
    tcp = TCP(dport=port, flags="S")
    pkt = ip/tcp
    try:
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            return "open|filtered"
        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            # SYN+ACK => open
            # flags may be an int-like value
            if int(flags) & 0x12:  # SYN+ACK
                # send RST to gracefully close (use send to avoid waiting)
                try:
                    send(IP(dst=host)/TCP(dport=port, flags="R"), verbose=False)
                except Exception:
                    pass
                return "open"
            # RST => closed
            if int(flags) & 0x14:  # RST+ACK
                return "closed"
        return "filtered"
    except PermissionError:
        # re-raise so caller can fallback to connect scan
        raise
    except Exception as e:
        logger.debug(f"scapy syn scan error for {host}:{port}: {e}")
        return "filtered"

def parse_ports(ports_str: str) -> List[int]:
    """Parse a string like '22,80,1000-1010' into list of ints."""
    ports = set()
    if not ports_str:
        return []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                a_i = int(a); b_i = int(b)
                for p in range(min(a_i, b_i), max(a_i, b_i) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except Exception:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception:
                continue
    return sorted(ports)

def is_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except Exception:
        return False

# Splash / ASCII art helpers
def show_splash_curses(stdscr, delay: float = 2.0):
    """Show ASCII art splash in curses with red color (if supported)."""
    try:
        curses.curs_set(0)
    except Exception:
        pass
    stdscr.clear()
    stdscr.refresh()
    try:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        color = curses.color_pair(1) | curses.A_BOLD
    except Exception:
        color = curses.A_BOLD
    lines = ASCII_ART.strip("\n").splitlines()
    h, w = stdscr.getmaxyx()
    start_y = max((h - len(lines)) // 2, 0)
    for i, line in enumerate(lines):
        # center
        x = max((w - len(line)) // 2, 0)
        try:
            stdscr.addstr(start_y + i, x, line, color)
        except Exception:
            try:
                stdscr.addstr(start_y + i, x, line)
            except Exception:
                pass
    stdscr.refresh()
    time.sleep(delay)
    try:
        curses.curs_set(1)
    except Exception:
        pass
    stdscr.clear()
    stdscr.refresh()

def print_splash_cli():
    """Print ASCII art in red using ANSI codes for CLI/no-ui mode."""
    RED = "\033[31m"
    RESET = "\033[0m"
    try:
        print(RED + ASCII_ART + RESET)
    except Exception:
        print(ASCII_ART)

# Curses UI helpers
class UI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        curses.use_default_colors()
        self.height, self.width = self.stdscr.getmaxyx()
        self.win_title = curses.newwin(3, self.width, 0, 0)
        self.win_main = curses.newwin(self.height-7, self.width, 3, 0)
        self.win_status = curses.newwin(4, self.width, self.height-4, 0)
        self.stdscr.nodelay(False)
        self.draw_title()

    def draw_title(self):
        self.win_title.clear()
        title = "Morphine - Stealth Recon Tool"
        subtitle = "Ultra-slow stealth scanner | Use only on authorized targets"
        try:
            self.win_title.addstr(0, 2, title, curses.A_BOLD)
            self.win_title.addstr(1, 2, subtitle)
            self.win_title.hline(2, 0, '-', self.width)
        except Exception:
            # fallback in case of small terminal
            pass
        self.win_title.refresh()

    def show_status(self, text: str):
        self.win_status.clear()
        lines = text.splitlines()
        for i, l in enumerate(lines[:3]):
            try:
                self.win_status.addstr(i, 1, l[:self.width-2])
            except Exception:
                pass
        try:
            self.win_status.hline(3, 0, '-', self.width)
        except Exception:
            pass
        self.win_status.refresh()

    def show_main(self, lines: List[str]):
        self.win_main.clear()
        h, w = self.win_main.getmaxyx()
        for i, l in enumerate(lines[:h-1]):
            try:
                self.win_main.addstr(i, 1, l[:w-2])
            except Exception:
                pass
        self.win_main.refresh()

    def input_box(self, prompt: str, default: str = "") -> str:
        self.show_status(prompt)
        curses.echo()
        self.stdscr.move(self.height-3, 0)
        self.stdscr.clrtoeol()
        try:
            self.stdscr.addstr(self.height-3, 1, f"{prompt} [{default}]: ")
            self.stdscr.refresh()
            # safe fallback: read a reasonable length
            s = self.stdscr.getstr(self.height-3, len(prompt) + 5 + len(str(default)), 2048)
            curses.noecho()
            if not s:
                return default
            return s.decode('utf-8').strip()
        except Exception:
            curses.noecho()
            return default

def scan_worker(host: str, port: int, mode: str, min_delay: float, max_delay: float,
                timeout: float, results: ScanResult, ui_update_cb=None) -> None:
    """Worker that performs a single port scan with randomized delay and records result."""
    # Sleep random delay to implement low & slow behavior
    delay = random.uniform(min_delay, max_delay)
    time.sleep(delay)
    status = "unknown"
    try:
        if mode == "syn" and SCAPY_AVAILABLE and os.geteuid() == 0:
            try:
                status = syn_scan_scapy(host, port, timeout=min(timeout, 4.0))
            except PermissionError:
                # fallback to connect scan if raw sockets are not permitted
                status = tcp_connect_scan(host, port, timeout=timeout)
        else:
            status = tcp_connect_scan(host, port, timeout=timeout)
    except Exception:
        status = "filtered"
    with LOCK:
        results.port_status[port] = status
    if ui_update_cb:
        try:
            ui_update_cb(host, port, status)
        except Exception:
            pass

def start_scan_targets(targets: List[str], ports: List[int], mode: str,
                       min_delay: float, max_delay: float, workers: int,
                       do_http: bool, timeout: float, ui_update_cb=None) -> Dict[str, ScanResult]:
    """Main orchestration of scans for multiple targets."""
    results: Dict[str, ScanResult] = {}
    # Prepare thread pool; we allow concurrency but each task delays itself
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        futures = []
        for host in targets:
            sr = ScanResult(host)
            results[host] = sr
            # Optionally do HTTP fingerprinting first (quick)
            if do_http:
                # try sensible order based on common http ports
                tried_ports = []
                if 443 in ports:
                    tried_ports.append(443)
                if 80 in ports:
                    tried_ports.append(80)
                tried_ports.extend([p for p in (443, 80) if p not in tried_ports])
                http_info = None
                for p in tried_ports:
                    try:
                        info = http_fingerprint(host, port=p, timeout=timeout)
                        if info.get("status") is not None:
                            http_info = info
                            break
                    except Exception as e:
                        logger.debug(f"http_fingerprint error for {host}:{p} -> {e}")
                        continue
                sr.http = http_info
            # schedule port scans
            for p in ports:
                f = exe.submit(scan_worker, host, p, mode, min_delay, max_delay, timeout, sr, ui_update_cb)
                futures.append(f)
        # Wait for all to finish
        try:
            for f in concurrent.futures.as_completed(futures):
                _ = f.result()
        except KeyboardInterrupt:
            exe.shutdown(wait=False)
            raise
    return results

def pretty_lines_from_results(results: Dict[str, ScanResult]) -> List[str]:
    lines: List[str] = []
    for host, sr in results.items():
        lines.append(f"Host: {host}  (HTTP: {'yes' if sr.http else 'no'})")
        if sr.http:
            lines.append(f"  HTTP -> url: {sr.http.get('url')} status: {sr.http.get('status')} server: {sr.http.get('server')}")
            if sr.http.get("title"):
                lines.append(f"    title: {sr.http.get('title')}")
        if sr.port_status:
            ports_sorted = sorted(sr.port_status.items(), key=lambda t: t[0])
            port_line = "  Ports: " + ", ".join(f"{p}/{st}" for p,st in ports_sorted)
            lines.append(port_line)
        lines.append("")
    return lines

def save_json(results: Dict[str, ScanResult], filename: str) -> None:
    out = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "tool": "Morphine",
        "results": {h: r.to_dict() for h, r in results.items()}
    }
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)

def main_curses(stdscr):
    # Show splash first
    try:
        show_splash_curses(stdscr, delay=2.0)
    except Exception:
        pass
    ui = UI(stdscr)
    ui.show_status("Bienvenue. Appuyez sur 'c' pour config, 'q' pour quitter, 's' pour démarrer scan.")
    current_config = {
        "targets": "",
        "ports": DEFAULT_PORTS,
        "mode": "syn",  # syn or connect
        "min_delay": str(DEFAULT_MIN_DELAY),
        "max_delay": str(DEFAULT_MAX_DELAY),
        "workers": str(DEFAULT_WORKERS),
        "do_http": "y",
        "export": "morphine_results.json",
        "timeout": str(DEFAULT_TIMEOUT),
    }
    results: Dict[str, ScanResult] = {}
    live_lines: List[str] = ["No scans yet."]
    ui.show_main(live_lines)
    while True:
        c = stdscr.getch()
        if c == ord('q'):
            break
        elif c == ord('c'):
            # Config inputs
            targets = ui.input_box("Targets (comma sep IP/host or domain). If domain, passive DNS can be used", current_config["targets"])
            if not targets:
                targets = current_config["targets"]
            current_config["targets"] = targets
            ports = ui.input_box("Ports (e.g. 22,80,8000-8100)", current_config["ports"])
            if ports:
                current_config["ports"] = ports
            mode = ui.input_box("Mode (syn/connect)", current_config["mode"])
            if mode in ("syn", "connect"):
                current_config["mode"] = mode
            min_d = ui.input_box("Min delay seconds", current_config["min_delay"])
            max_d = ui.input_box("Max delay seconds", current_config["max_delay"])
            workers = ui.input_box("Parallel workers (threads)", current_config["workers"])
            do_http = ui.input_box("Do HTTP fingerprint? (y/n)", current_config["do_http"])
            export = ui.input_box("Export JSON filename", current_config["export"])
            timeout = ui.input_box("Timeout seconds", current_config["timeout"])
            # sanitize
            current_config["min_delay"] = min_d
            current_config["max_delay"] = max_d
            current_config["workers"] = workers
            current_config["do_http"] = do_http.lower()[:1]
            current_config["export"] = export or current_config["export"]
            current_config["timeout"] = timeout
            ui.show_status("Configuration saved. Press 's' to start scan.")
        elif c == ord('s'):
            # Confirm authorization
            confirm = ui.input_box("Do you have written authorization to test these targets? (yes/no)", "no")
            if confirm.lower() not in ("yes", "y"):
                ui.show_status("Authorization required. Aborting start.")
                continue
            # Build target list: if a domain appears and user wants passive DNS, ask
            raw_targets = current_config["targets"]
            if not raw_targets:
                ui.show_status("No targets configured. Press 'c' to configure.")
                continue
            tokens = [t.strip() for t in raw_targets.split(",") if t.strip()]
            final_targets: Set[str] = set()
            for t in tokens:
                if "." in t and not is_ip(t):
                    # domain: ask if do passive DNS
                    pd = ui.input_box(f"Passive DNS for domain {t}? (y/n)", "y")
                    if pd.lower().startswith("y"):
                        ui.show_status(f"Enumerating subdomains for {t}...")
                        try:
                            subs = passive_dns_crtsh(t)
                            if subs:
                                for s in subs:
                                    final_targets.add(s)
                                ui.show_status(f"crt.sh returned {len(subs)} hosts; added to target list.")
                            else:
                                ui.show_status(f"No entries found on crt.sh for {t}; adding domain itself.")
                                final_targets.add(t)
                        except Exception as e:
                            ui.show_status(f"crt.sh error: {e}; adding {t} as-is")
                            final_targets.add(t)
                    else:
                        final_targets.add(t)
                else:
                    final_targets.add(t)
            # parse ports
            ports = parse_ports(current_config["ports"])
            if not ports:
                ui.show_status("No valid ports parsed.")
                continue
            # parse numeric values
            try:
                min_delay = float(current_config["min_delay"])
                max_delay = float(current_config["max_delay"])
            except Exception:
                min_delay = DEFAULT_MIN_DELAY
                max_delay = DEFAULT_MAX_DELAY
            if min_delay < 0: min_delay = DEFAULT_MIN_DELAY
            if max_delay < min_delay: max_delay = min_delay + 1.0
            try:
                workers = int(current_config["workers"])
            except Exception:
                workers = DEFAULT_WORKERS
            do_http = current_config["do_http"].lower().startswith("y")
            mode = current_config["mode"]
            timeout = float(current_config.get("timeout") or DEFAULT_TIMEOUT)
            ui.show_status(f"Starting scan on {len(final_targets)} targets, {len(ports)} ports each. Mode={mode}")
            # live update callback
            live_state_lock = threading.Lock()
            live_state: Dict[str, Dict[int, str]] = {}
            def ui_update(host, port, status):
                with live_state_lock:
                    if host not in live_state:
                        live_state[host] = {}
                    live_state[host][port] = status
                # prepare lines for UI
                display_lines = []
                for h, pst in live_state.items():
                    display_lines.append(f"{h}: " + ", ".join(f"{p}/{st}" for p,st in sorted(pst.items())))
                ui.show_main(display_lines)
            # run scan
            try:
                results = start_scan_targets(list(final_targets), ports, mode, min_delay, max_delay, workers, do_http, timeout, ui_update_cb=ui_update)
                ui.show_status("Scan completed. Preparing output...")
            except KeyboardInterrupt:
                ui.show_status("Scan interrupted by user.")
                continue
            except Exception as e:
                ui.show_status(f"Fatal error: {e}")
                continue
            # finalize UI output
            lines = pretty_lines_from_results(results)
            ui.show_main(lines)
            # save results
            filename = current_config["export"]
            try:
                save_json(results, filename)
                ui.show_status(f"Results saved to {filename}")
            except Exception as e:
                ui.show_status(f"Failed to save results: {e}")
        else:
            time.sleep(0.05)

def main_non_curses(args):
    # Non-interactive mode for automation / testing
    # Print splash/art for CLI mode
    try:
        print_splash_cli()
    except Exception:
        pass

    if not args.targets:
        print("No targets provided. Use -t (--targets).")
        return
    # Confirm authorization
    if not args.yes:
        c = input("Do you have written authorization for these targets? (yes/no) ")
        if c.lower() not in ("yes", "y"):
            print("Authorization required. Exiting.")
            return
    tokens = [t.strip() for t in args.targets.split(",") if t.strip()]
    final_targets: Set[str] = set()
    for t in tokens:
        if "." in t and not is_ip(t) and args.passive_dns:
            print(f"[+] Performing passive DNS for {t} via crt.sh...")
            subs = passive_dns_crtsh(t)
            if subs:
                final_targets.update(subs)
                print(f"[+] crt.sh: {len(subs)} hosts")
            else:
                final_targets.add(t)
        else:
            final_targets.add(t)
    ports = parse_ports(args.ports)
    if not ports:
        print("No valid ports parsed.")
        return
    mode = args.mode
    results = start_scan_targets(list(final_targets), ports, mode, args.min_delay, args.max_delay, args.workers, args.http, args.timeout,
                                 ui_update_cb=lambda h,p,s: print(f"[{h}] {p}/{s}"))
    save_json(results, args.export)
    print(f"[+] Results saved to {args.export}")

def cli_args():
    p = argparse.ArgumentParser(description="Morphine - Stealth Recon Tool")
    p.add_argument("-t", "--targets", help="Comma separated targets (IP, host, domain)", default="")
    p.add_argument("-p", "--ports", help=f"Ports list, default: {DEFAULT_PORTS}", default=DEFAULT_PORTS)
    p.add_argument("-m", "--mode", choices=("syn","connect"), default="syn", help="Scan mode")
    p.add_argument("--min-delay", type=float, default=DEFAULT_MIN_DELAY)
    p.add_argument("--max-delay", type=float, default=DEFAULT_MAX_DELAY)
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS)
    p.add_argument("--http", action="store_true", help="Do HTTP fingerprint")
    p.add_argument("--passive-dns", action="store_true", help="Use crt.sh passive dns for domains")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("-o", "--export", default="morphine_results.json")
    p.add_argument("--no-ui", action="store_true", help="Run without curses UI (CLI mode)")
    p.add_argument("--yes", action="store_true", help="Auto-confirm authorization (dangerous)")
    return p.parse_args()

if __name__ == "__main__":
    # suppress insecure-request warnings from requests
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    args = cli_args()
    if args.no_ui:
        if not REQUESTS_AVAILABLE:
            logger.warning("requests/bs4 not available; HTTP & passive DNS will be limited.")
        if args.mode == "syn" and not SCAPY_AVAILABLE:
            logger.warning("scapy not available; SYN mode will fallback to connect mode.")
        main_non_curses(args)
        sys.exit(0)

    if not CURSES_AVAILABLE:
        logger.error("curses not available; run with --no-ui for CLI mode.")
        sys.exit(1)

    try:
        curses.wrapper(main_curses)
    except Exception as e:
        logger.error("Fatal UI error: %s", e)
        traceback.print_exc()
        sys.exit(1)