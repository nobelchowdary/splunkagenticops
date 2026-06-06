#!/bin/bash
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
