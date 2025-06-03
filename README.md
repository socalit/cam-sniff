# 📷 cam-sniff

`cam-sniff` is a fast Python-based CLI tool that scans your local network for unsecured or default-credential IP cameras. Built for ethical hackers, IT pros, and hospitality/enterprise security audits.

Created by [socalit](https://github.com/socalit) to simplify camera reconnaissance and vulnerability checks in hotel and enterprise environments.

---

## Features

- Scans a subnet (e.g. `192.168.1.0/24`) for IP cameras
- Probes common ports: `80`, `554`, `8000`, `8080`, `8554`
- Detects camera vendor from HTTP headers or page content
- Tries known default credentials (`default_creds.json`)
- Discovers RTSP stream URLs if available
- Grabs snapshots from HTTP or RTSP using `ffmpeg`
- ONVIF metadata discovery (model, firmware, stream URI)
- Optional: Enriches output using Shodan API
- Output formats: pretty-print, JSON, or CSV
- Multi-threaded (fast)

---

## 🧪 Usage

```bash
# Basic scan with pretty output
cam-sniff 192.168.1.0/24

# Output results to JSON
cam-sniff 192.168.1.0/24 --output json

# Save results to CSV
cam-sniff 192.168.1.0/24 --output csv

# Try grabbing camera snapshots
cam-sniff 192.168.1.0/24 --grab-snapshots

# Scan ONVIF metadata
cam-sniff 192.168.1.0/24 --onvif-scan

# Full scan with Shodan enrichment
cam-sniff 192.168.1.0/24 --grab-snapshots --onvif-scan --shodan YOUR_API_KEY
```

---

## ⚙️ Quick Start

```bash
# Clone the repo
git clone https://github.com/socalit/cam-sniff
cd cam-sniff

# Install dependencies and setup
chmod +x install-cam-sniff.sh
sudo ./install-cam-sniff.sh
```

---

## Output

- `snapshots/` — Camera image captures (JPEG)
- `onvif_data/` — Metadata JSON from ONVIF-enabled cameras
- `cam-sniff-output.json` or `.csv` — Full scan report

---

## Legal Use Only

This tool is intended **only for authorized network testing**. Always ensure you have explicit permission to scan and probe devices on any given network.
