#!/usr/bin/env python3
"""
Download 4SICS Geek Lounge ICS PCAP Datasets from Netresec
"""

import os
import sys
import urllib.request

DATASET_FILES = {
    "4SICS-GeekLounge-151020.pcap": "https://share.netresec.com/s/xYj2qCNbsLEAd6M/download/4SICS-GeekLounge-151020.pcap",
    "4SICS-GeekLounge-151021.pcap": "https://share.netresec.com/s/camL59aoxbCRyyZ/download/4SICS-GeekLounge-151021.pcap",
    "4SICS-GeekLounge-151022.pcap": "https://share.netresec.com/s/gw6Y2QzJHqDD5pr/download/4SICS-GeekLounge-151022.pcap",
}

def download_file(filename, url, target_dir):
    os.makedirs(target_dir, exist_ok=True)
    filepath = os.path.join(target_dir, filename)
    
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        print(f"[+] {filename} already exists ({os.path.getsize(filepath)} bytes). Skipping.")
        return filepath
        
    print(f"[*] Downloading {filename} from {url}...")
    def reporthook(count, block_size, total_size):
        if total_size > 0:
            percent = int(count * block_size * 100 / total_size)
            sys.stdout.write(f"\rDownloading {filename}: {percent}% ({count * block_size}/{total_size} bytes)")
            sys.stdout.flush()

    try:
        urllib.request.urlretrieve(url, filepath, reporthook)
        print(f"\n[+] Successfully downloaded {filename} ({os.path.getsize(filepath)} bytes)")
    except Exception as e:
        print(f"\n[-] Error downloading {filename}: {e}")
        if os.path.exists(filepath):
            os.remove(filepath)
        return None
    return filepath

def main():
    target_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
    print(f"=== 4SICS ICS PCAP Dataset Downloader ===")
    print(f"Target Directory: {target_dir}\n")
    
    for filename, url in DATASET_FILES.items():
        download_file(filename, url, target_dir)
        
    print("\n[+] All dataset files processed!")

if __name__ == "__main__":
    main()
