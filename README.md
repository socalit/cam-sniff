# cam-sniff

`cam-sniff` is a fast Python-based CLI tool that scans your network for unsecured or default-credential IP cameras. Works great on Linux or macOS. Ideal for IT pros, pentesters, and hotel/hospitality infrastructure audits.

Built by socalit to perform security audits.

---

## Features

- Detects IP cameras on a given subnet (e.g. `192.168.1.0/24`)
- Scans common ports: `80`, `554`, `8000`, `8080`, `8554`
- Identifies camera brands via HTTP banners or HTML content
- Checks default login credentials (from `default_creds.json`)
- Discovers RTSP stream URLs if port `554` is open
- Optional: Pulls live camera metadata from Shodan API
- Output: pretty-print, JSON, or CSV

---
## Usage:

# Basic scan with pretty terminal output
cam-sniff 192.168.1.0/24

# Output results to JSON
cam-sniff 192.168.1.0/24 --output json

# Output to CSV for reporting
cam-sniff 192.168.1.0/24 --output csv

# Include Shodan enrichment (optional)
cam-sniff 192.168.1.0/24 --output json --shodan YOUR_API_KEY

---
## Quick Start

```bash
# Clone the repo
git clone https://github.com/socalit/cam-sniff
cd cam-sniff

# Install dependencies and setup
chmod +x install-cam-sniff.sh
sudo ./install-cam-sniff.sh
