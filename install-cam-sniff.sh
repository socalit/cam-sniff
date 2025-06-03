#!/bin/bash

echo "[*] Installing cam-sniff dependencies..."

if ! command -v pip3 &> /dev/null; then
    echo "[!] pip3 not found. Installing..."
    sudo apt update && sudo apt install -y python3-pip
fi

if ! command -v ffmpeg &> /dev/null; then
    echo "[*] Installing ffmpeg..."
    sudo apt install -y ffmpeg
fi

pip3 install --user -r requirements-full.txt

mkdir -p snapshots onvif_data

chmod +x cam-sniff.py
sudo cp cam-sniff.py /usr/local/bin/cam-sniff

dos2unix cam-sniff.py >/dev/null 2>&1

echo "[+] cam-sniff installed and ready to use!"
echo "    Try: cam-sniff 192.168.1.0/24 --grab-snapshots --onvif-scan"
