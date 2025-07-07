# IOC Enricher — Real-World SOC Analyst Tool 🔍

> Built by Dhruvish | Tier 1 SOC Ready

This tool enriches Indicators of Compromise (IOCs) — IPs, hashes, and domains — using the VirusTotal API. Built to simulate real-world alert triage as done in a Security Operations Center (SOC).

## 🔧 Features

- Takes a single IOC as input via CLI
- Queries VirusTotal API
- Displays:
  - Reputation score
  - Country (for IPs)
  - Malware detection count
  - Domain categories

## 📦 Usage

```bash
python enrich.py -i 8.8.8.8

🔍 Results for: 8.8.8.8
📊 Reputation Score: 549
🌍 Country: US
🦠 Malware Detections: 0 malicious, 0 suspicious, 62 harmless
