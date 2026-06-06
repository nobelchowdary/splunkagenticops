"""
BOTS Dataset Loader — Use Splunk's "Boss of the SOC" datasets for professional-grade demo data.

BOTS (Boss of the SOC) datasets contain real APT attack scenarios that are perfectly
structured for security investigation demos. This is vastly superior to custom-generated
data because:
1. Realistic attack patterns (not simplified)
2. Proper field extractions already configured
3. Multiple correlated indexes
4. Well-documented attack narratives

Available datasets:
- BOTSv1: APT attack on Wayne Enterprises (web compromise → lateral movement → exfiltration)
- BOTSv2: Two concurrent attacks (ransomware + APT)
- BOTSv3: Advanced attack with cloud infrastructure involvement

Download: https://github.com/splunk/botsv1 (or botsv2, botsv3)
"""

import os
import subprocess
from pathlib import Path


BOTS_DATASETS = {
    "v1": {
        "name": "Boss of the SOC v1",
        "url": "https://github.com/splunk/botsv1",
        "description": "APT attack on Wayne Enterprises — web compromise, lateral movement, exfiltration",
        "indexes": ["botsv1"],
        "sourcetypes": [
            "stream:http", "stream:dns", "stream:tcp",
            "WinEventLog:Security", "WinEventLog:System",
            "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "fgt_traffic", "fgt_utm", "suricata",
            "iis", "nessus:scan", "pan:traffic",
        ],
        "attack_narrative": """
            1. Attacker scans Wayne Corp's web server
            2. Exploits vulnerability in web application
            3. Establishes C2 communication
            4. Dumps credentials from memory
            5. Moves laterally to domain controller
            6. Exfiltrates sensitive data
        """,
        "size_gb": 3.2,
    },
    "v2": {
        "name": "Boss of the SOC v2",
        "url": "https://github.com/splunk/botsv2",
        "description": "Concurrent ransomware attack + APT with cryptocurrency mining",
        "indexes": ["botsv2"],
        "sourcetypes": [
            "stream:http", "stream:dns", "stream:smtp",
            "WinEventLog:Security", "WinEventLog:System",
            "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "pan:traffic", "pan:threat",
        ],
        "attack_narrative": """
            1. Phishing email delivers ransomware
            2. Simultaneous APT compromises web server
            3. Cryptominer deployed on internal servers
            4. Data exfiltration via encrypted channels
        """,
        "size_gb": 16.0,
    },
}


def get_bots_install_instructions(version: str = "v1") -> str:
    """Get instructions for installing a BOTS dataset into Splunk."""
    dataset = BOTS_DATASETS.get(version, BOTS_DATASETS["v1"])

    return f"""
## Installing {dataset['name']} Dataset

### Option 1: Splunkbase App (Recommended)
1. Go to Splunkbase: https://splunkbase.splunk.com/app/2748 (BOTSv1)
2. Download the app package
3. In Splunk Web: Apps → Install app from file → Upload
4. Restart Splunk when prompted

### Option 2: Git Clone + Manual Import
```bash
# Clone the dataset
git clone {dataset['url']}.git
cd {Path(dataset['url']).name}

# Copy to Splunk apps directory
cp -r . $SPLUNK_HOME/etc/apps/{Path(dataset['url']).name}/

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

### Option 3: Using our sample data (lighter alternative)
If you don't want to download {dataset['size_gb']}GB:
```bash
cd sentinelflow/splunk/eventgen
python attack_scenario.py
bash upload_to_splunk.sh
```
This generates a 1,666-event lightweight attack scenario that demonstrates all agent capabilities.

### After Install
The data will be available in index={dataset['indexes'][0]}
Available sourcetypes: {', '.join(dataset['sourcetypes'][:5])}...

### Schema Update
After installing BOTS, update your .env to use the BOTS index:
```
SPLUNK_DEFAULT_INDEX=botsv1
```
The schema discovery agent will auto-detect the new indexes and fields.
"""


def get_bots_schema_override(version: str = "v1") -> dict:
    """Get schema override for BOTS dataset (use when BOTS is installed)."""
    if version == "v1":
        return {
            "indexes": ["botsv1", "main"],
            "sourcetypes_by_index": {
                "botsv1": [
                    "stream:http", "stream:dns", "stream:tcp",
                    "WinEventLog:Security", "WinEventLog:System",
                    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                    "fgt_traffic", "fgt_utm", "suricata", "iis",
                ],
            },
            "fields_by_sourcetype": {
                "WinEventLog:Security": [
                    "_time", "EventCode", "Account_Name", "Source_Network_Address",
                    "Logon_Type", "Process_Name", "ComputerName", "Keywords",
                ],
                "stream:http": [
                    "_time", "src_ip", "dest_ip", "http_method", "uri_path",
                    "status", "http_user_agent", "bytes_in", "bytes_out",
                    "cookie", "form_data", "http_referrer",
                ],
                "stream:dns": [
                    "_time", "src_ip", "dest_ip", "query", "query_type",
                    "reply_code", "answer", "message_type",
                ],
                "fgt_traffic": [
                    "_time", "srcip", "dstip", "srcport", "dstport",
                    "action", "sentbyte", "rcvdbyte", "proto",
                ],
                "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational": [
                    "_time", "EventCode", "Image", "CommandLine",
                    "ParentImage", "User", "DestinationIp", "DestinationPort",
                ],
            },
        }
    return {}


if __name__ == "__main__":
    print("=" * 60)
    print("BOTS Dataset Information")
    print("=" * 60)
    for version, info in BOTS_DATASETS.items():
        print(f"\n{info['name']} ({info['size_gb']}GB)")
        print(f"  URL: {info['url']}")
        print(f"  {info['description']}")
    print("\n" + "=" * 60)
    print(get_bots_install_instructions("v1"))
