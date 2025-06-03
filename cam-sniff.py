#!/usr/bin/env python3
import argparse
import ipaddress
import socket
import requests
import json
import csv
import concurrent.futures
from base64 import b64encode

# Load default credentials
with open("default_creds.json", "r") as f:
    DEFAULT_CREDS = json.load(f)

COMMON_PORTS = [80, 554, 8000, 8080, 8554]
TIMEOUT = 3
results = []

# Optional Shodan API integration
def shodan_lookup(ip, api_key):
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def check_camera(ip, shodan_key=None):
    entry = {"ip": str(ip), "ports": [], "vendor": None, "stream": None, "creds": None, "shodan": None}

    for port in COMMON_PORTS:
        try:
            sock = socket.create_connection((str(ip), port), timeout=TIMEOUT)
            entry["ports"].append(port)
            sock.close()
        except:
            continue

    # HTTP banner grabbing
    for port in entry["ports"]:
        if port in [80, 8000, 8080]:
            try:
                r = requests.get(f"http://{ip}:{port}", timeout=TIMEOUT)
                if "Server" in r.headers:
                    entry["vendor"] = r.headers["Server"]
                elif r.text:
                    for vendor in DEFAULT_CREDS:
                        if vendor.lower() in r.text.lower():
                            entry["vendor"] = vendor
                            break
                break
            except:
                continue

    # RTSP check
    if 554 in entry["ports"]:
        entry["stream"] = f"rtsp://{ip}:554/"

    # Default credential check
    if entry["vendor"] and entry["vendor"] in DEFAULT_CREDS:
        creds = DEFAULT_CREDS[entry["vendor"]]
        for cred in creds:
            auth = b64encode(f"{cred['username']}:{cred['password']}".encode()).decode()
            try:
                r = requests.get(f"http://{ip}", headers={"Authorization": f"Basic {auth}"}, timeout=TIMEOUT)
                if r.status_code != 401:
                    entry["creds"] = cred
                    break
            except:
                continue

    # Shodan enrichment
    if shodan_key:
        entry["shodan"] = shodan_lookup(ip, shodan_key)

    if entry["ports"]:
        results.append(entry)

def write_output(output_format):
    if output_format == "json":
        with open("cam-sniff-output.json", "w") as f:
            json.dump(results, f, indent=2)
    elif output_format == "csv":
        with open("cam-sniff-output.csv", "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "ports", "vendor", "stream", "creds", "shodan"])
            writer.writeheader()
            for row in results:
                writer.writerow(row)
    else:
        for r in results:
            print("\n[+] Camera Found:")
            for k, v in r.items():
                print(f"  {k}: {v}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan for unsecured IP cameras on a network.")
    parser.add_argument("subnet", help="Target subnet in CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("--output", choices=["json", "csv", "pretty"], default="pretty", help="Output format")
    parser.add_argument("--shodan", help="Optional Shodan API key to enrich results")
    args = parser.parse_args()

    net = ipaddress.ip_network(args.subnet, strict=False)
    print(f"[*] Scanning {len(list(net.hosts()))} hosts in {args.subnet}...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_camera, ip, args.shodan) for ip in net.hosts()]
        concurrent.futures.wait(futures)

    print(f"\n[+] Scan complete. {len(results)} potential camera(s) found.")
    write_output(args.output)
