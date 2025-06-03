#!/usr/bin/env python3
import argparse
import ipaddress
import socket
import requests
import json
import csv
import concurrent.futures
from base64 import b64encode
import os
import subprocess
from datetime import datetime

# Try importing ONVIF for --onvif-scan
try:
    from onvif import ONVIFCamera
    HAS_ONVIF = True
except ImportError:
    HAS_ONVIF = False

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(SCRIPT_DIR, "default_creds.json"), "r") as f:
    DEFAULT_CREDS = json.load(f)

COMMON_PORTS = [80, 554, 8000, 8080, 8554]
TIMEOUT = 3
results = []

os.makedirs("snapshots", exist_ok=True)
os.makedirs("onvif_data", exist_ok=True)

def grab_snapshot(ip, vendor, creds):
    paths = [
        "/snapshot.jpg",
        "/snapshot.cgi",
        "/image.jpg",
        "/cgi-bin/snapshot.cgi"
    ]
    for path in paths:
        url = f"http://{ip}{path}"
        try:
            r = requests.get(url, auth=(creds['username'], creds['password']), timeout=5)
            if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("image"):
                fname = f"snapshots/{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
                with open(fname, "wb") as f:
                    f.write(r.content)
                print(f"[+] Snapshot saved: {fname}")
                return
        except:
            continue
    # fallback to ffmpeg RTSP grab
    rtsp_url = f"rtsp://{ip}/"
    fname = f"snapshots/{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_rtsp.jpg"
    try:
        subprocess.run([
            "ffmpeg", "-y", "-rtsp_transport", "tcp",
            "-i", rtsp_url, "-vframes", "1", fname
        ], timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(fname):
            print(f"[+] RTSP snapshot saved: {fname}")
    except:
        pass

def run_onvif_scan(ip, creds):
    if not HAS_ONVIF:
        return
    try:
        cam = ONVIFCamera(ip, 80, creds['username'], creds['password'])
        info = cam.devicemgmt.GetDeviceInformation()
        media = cam.create_media_service()
        profiles = media.GetProfiles()
        uri = media.GetStreamUri({
            'StreamSetup': {'Stream': 'RTP-Unicast', 'Transport': {'Protocol': 'RTSP'}},
            'ProfileToken': profiles[0].token
        })

        out = {
            "ip": ip,
            "manufacturer": info.Manufacturer,
            "model": info.Model,
            "firmware": info.FirmwareVersion,
            "serial": info.SerialNumber,
            "hardware": info.HardwareId,
            "stream_uri": uri.Uri
        }
        path = f"onvif_data/{ip}.json"
        with open(path, "w") as f:
            json.dump(out, f, indent=2)
        print(f"[+] ONVIF data saved: {path}")
    except:
        pass

def shodan_lookup(ip, api_key):
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def check_camera(ip, shodan_key=None, grab_snap=False, run_onvif=False):
    entry = {"ip": str(ip), "ports": [], "vendor": None, "stream": None, "creds": None, "shodan": None}

    for port in COMMON_PORTS:
        try:
            sock = socket.create_connection((str(ip), port), timeout=TIMEOUT)
            entry["ports"].append(port)
            sock.close()
        except:
            continue

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

    if 554 in entry["ports"]:
        entry["stream"] = f"rtsp://{ip}:554/"

    if entry["vendor"] and entry["vendor"] in DEFAULT_CREDS:
        creds_list = DEFAULT_CREDS[entry["vendor"]]
        for cred in creds_list:
            auth = b64encode(f"{cred['username']}:{cred['password']}".encode()).decode()
            try:
                r = requests.get(f"http://{ip}", headers={"Authorization": f"Basic {auth}"}, timeout=TIMEOUT)
                if r.status_code != 401:
                    entry["creds"] = cred
                    if grab_snap:
                        grab_snapshot(ip, entry["vendor"], cred)
                    if run_onvif:
                        run_onvif_scan(ip, cred)
                    break
            except:
                continue

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
    parser.add_argument("--grab-snapshots", action="store_true", help="Attempt to save camera snapshots")
    parser.add_argument("--onvif-scan", action="store_true", help="Run ONVIF scan and export metadata")
    args = parser.parse_args()

    if args.onvif_scan and not HAS_ONVIF:
        print("[!] ONVIF support not installed. Run: pip3 install onvif-zeep")
        exit(1)

    net = ipaddress.ip_network(args.subnet, strict=False)
    print(f"[*] Scanning {len(list(net.hosts()))} hosts in {args.subnet}...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_camera, ip, args.shodan, args.grab_snapshots, args.onvif_scan) for ip in net.hosts()]
        concurrent.futures.wait(futures)

    print(f"\n[+] Scan complete. {len(results)} potential camera(s) found.")
    write_output(args.output)
