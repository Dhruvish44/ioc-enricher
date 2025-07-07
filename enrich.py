#!/usr/bin/env python3

import argparse
import requests
import sys

API_KEY = "390b86143d52458ff6fc3c3d7bde3381a783a57869940ea6c914bb3fa727c1a1"  # Replace with your own key
BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": API_KEY
}

def query_ioc(ioc):
    if "." in ioc and not ioc.count('.') == 1:
        endpoint = f"/ip_addresses/{ioc}" if ioc.replace(".", "").isdigit() else f"/domains/{ioc}"
    else:
        endpoint = f"/files/{ioc}"  # Assume it's a hash

    url = BASE_URL + endpoint
    response = requests.get(url, headers=HEADERS)

    if response.status_code != 200:
        print(f"Error querying VirusTotal: {response.status_code}")
        sys.exit(1)

    return response.json()

def parse_response(data, ioc):
    print(f"\n🔍 Results for: {ioc}")

    attr = data.get("data", {}).get("attributes", {})
    
    # General reputation info
    if "reputation" in attr:
        print(f"📊 Reputation Score: {attr['reputation']}")

    # Geo for IPs
    if "country" in attr:
        print(f"🌍 Country: {attr['country']}")

    # Detection stats
    if "last_analysis_stats" in attr:
        stats = attr["last_analysis_stats"]
        print(f"🦠 Malware Detections: {stats['malicious']} malicious, {stats['suspicious']} suspicious, {stats['harmless']} harmless")

    # Categories (domains)
    if "categories" in attr and attr["categories"]:
        print(f"🏷️ Categories: {', '.join(attr['categories'].values())}")

def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment Tool (VirusTotal)")
    parser.add_argument("-i", "--ioc", required=True, help="IOC (IP, domain, or hash) to enrich")
    args = parser.parse_args()

    ioc_data = query_ioc(args.ioc)
    parse_response(ioc_data, args.ioc)

if __name__ == "__main__":
    main()
