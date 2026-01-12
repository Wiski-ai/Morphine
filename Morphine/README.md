# Morphine — Stealth Recon Tool

Morphine is a "low & slow" reconnaissance tool designed to test IDS/IPS and SOC detection.
It is delivered as a single Python file (`morphine.py`) and targets Kali / BlackArch environments.

IMPORTANT — Legal and Ethical Notice
- Use Morphine only on targets for which you have explicit written authorization (scope, dates, IPs/domains).
- Without authorization, any active activity (SYN scans, TCP connect, HTTP probing) is illegal.
- This software is provided for educational and authorized auditing purposes only. The author disclaims any responsibility for misuse.

Main Features
- TCP scan in "stealth" (SYN) mode if scapy and root privileges are available.
- Fallback to TCP connect scan if scapy/privileges are missing.
- Random delays between probes (configurable) to simulate a very slow scan.
- User-Agent rotation for HTTP requests.
- HTTP fingerprinting (status, headers, title).
- Passive DNS enumeration via crt.sh (JSON).
- Terminal interface (curses) inspired by wifite / airgeddon.
- JSON export of results.

Requirements
- Python 3.8+
- On Kali / BlackArch, install:
  - scapy (for SYN scans, requires root): `pip install scapy` (or use distro package)
  - requests, beautifulsoup4: `pip install requests beautifulsoup4`
- To run SYN scans: launch as root (`sudo`).

Usage (UI)
- Launch: `sudo python3 morphine.py`
- In the interface:
  - Press `c` to configure (targets, ports, delays,...)
  - Press `s` to start a scan
  - Press `q` to quit
  - During configuration, `targets` accepts domains; you can enable passive crt.sh enumeration.

Usage (CLI)
- Example:
  - `python3 morphine.py --no-ui -t example.com -p 22,80,443 -m syn --http --passive-dns --export out.json`
- Options:
  - `-t/--targets` : comma-separated targets
  - `-p/--ports` : port list or ranges (e.g. `1-1024,8080`)
  - `-m/--mode` : `syn` or `connect`
  - `--min-delay/--max-delay` : delay between probes (seconds)
  - `-w/--workers` : parallel threads (each task respects its delays)
  - `--http` : run HTTP fingerprint
  - `--passive-dns` : use crt.sh for domains
  - `-o/--export` : output JSON file
  - `--no-ui` : CLI mode
  - `--yes` : automatically confirm authorization (danger)

Technical and Security Considerations
- SYN mode uses raw sockets — requirements: scapy + root privileges.
- The scan is intentionally slow (random delays) to test "low & slow" detection.
- Do not run heavy scans from shared environments or without permission.
- Results are exported in JSON for integration/reporting.

Contributing / Improvements
- Add OS/stack fingerprinting (banner grabbing, TCP/IP stack analysis).
- Add an internal database to store scan history.
- Better thread management and long-session resume support.
- Integrate a "dry-run" option to simulate activity without sending packets.

License
- Provided as-is, responsible use only.
- This tool is create By H8Laws

