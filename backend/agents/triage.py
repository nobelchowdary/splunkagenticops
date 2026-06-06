"""Triage Agent — Initial alert classification, severity scoring, and IOC extraction."""

from typing import Dict, Any, Callable, Optional
from datetime import datetime

from tools.splunk_mcp import get_mcp_client
from tools.hosted_models import get_foundation_sec
from models import Finding, Severity, TimelineEvent


async def run_triage(
    alert_data: Dict[str, Any],
    callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Triage an alert: classify threat, extract IOCs, assign severity.

    Returns:
        Dict with severity, threat_category, iocs, mitre_techniques, investigation_path
    """
    mcp = get_mcp_client()
    foundation_sec = get_foundation_sec()

    # Step 1: Notify start
    if callback:
        await callback({
            "type": "agent_action",
            "agent": "triage",
            "action": "starting",
            "detail": "Analyzing alert for threat classification...",
        })

    # Step 2: Enrich alert with additional context from Splunk
    enriched_context = alert_data.get("description", "")
    src_ip = alert_data.get("source_ip")
    dest_ip = alert_data.get("dest_ip")
    user = alert_data.get("user")

    if src_ip:
        if callback:
            await callback({
                "type": "agent_action",
                "agent": "triage",
                "action": "querying",
                "detail": f"Pulling recent events for source IP {src_ip}",
                "spl_query": f'search index=* src_ip="{src_ip}" | stats count by index, sourcetype | sort -count',
            })

        ip_context = await mcp.get_events_by_ip(src_ip)
        if ip_context:
            enriched_context += f"\n\nRelated events for {src_ip}: {len(ip_context)} events found across indexes."

    # Step 3: Classify using Foundation-Sec-8B
    if callback:
        await callback({
            "type": "agent_action",
            "agent": "triage",
            "action": "classifying",
            "detail": "Running Foundation-Sec-8B threat classification...",
        })

    classification = await foundation_sec.classify_threat(enriched_context)

    # Step 4: Extract IOCs
    iocs = await foundation_sec.extract_iocs(enriched_context)
    if src_ip and src_ip not in iocs:
        iocs.append(src_ip)

    # Step 5: Map severity
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    severity = severity_map.get(
        classification.get("severity", "medium"), Severity.MEDIUM
    )

    # Step 6: Build triage result
    result = {
        "severity": severity,
        "threat_category": classification.get("threat_category", "Unknown"),
        "iocs": iocs,
        "mitre_techniques": classification.get("mitre_techniques", []),
        "investigation_steps": classification.get("investigation_steps", []),
        "enriched_context": enriched_context,
        "findings": [
            Finding(
                agent="triage",
                type="classification",
                title=f"Threat Classification: {classification.get('threat_category', 'Unknown')}",
                description=f"Alert classified as {classification.get('threat_category')} with severity {severity.value}",
                severity=severity,
                mitre_technique=classification.get("mitre_techniques", [None])[0] if classification.get("mitre_techniques") else None,
                confidence=0.85,
            ).model_dump(),
        ],
        "timeline_events": [
            TimelineEvent(
                timestamp=datetime.utcnow(),
                agent="triage",
                action="classified",
                detail=f"Alert classified as {classification.get('threat_category')} (severity: {severity.value}). Found {len(iocs)} IOCs.",
            ).model_dump(),
        ],
    }

    if callback:
        await callback({
            "type": "agent_result",
            "agent": "triage",
            "result": {
                "severity": severity.value,
                "threat_category": classification.get("threat_category"),
                "iocs": iocs,
                "mitre_techniques": classification.get("mitre_techniques", []),
            },
        })

    return result
