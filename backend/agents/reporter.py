"""Report Agent — Generate structured investigation reports."""

from typing import Dict, Any, Callable, Optional, List
from datetime import datetime

from models import Finding, TimelineEvent


MITRE_TACTICS = {
    "T1110": {"tactic": "Credential Access", "technique": "Brute Force"},
    "T1078": {"tactic": "Defense Evasion", "technique": "Valid Accounts"},
    "T1021": {"tactic": "Lateral Movement", "technique": "Remote Services"},
    "T1048": {"tactic": "Exfiltration", "technique": "Exfiltration Over Alternative Protocol"},
    "T1059": {"tactic": "Execution", "technique": "Command and Scripting Interpreter"},
    "T1053": {"tactic": "Persistence", "technique": "Scheduled Task/Job"},
    "T1071": {"tactic": "Command and Control", "technique": "Application Layer Protocol"},
    "T1112": {"tactic": "Defense Evasion", "technique": "Modify Registry"},
    "T1003": {"tactic": "Credential Access", "technique": "OS Credential Dumping"},
    "T1486": {"tactic": "Impact", "technique": "Data Encrypted for Impact"},
    "T1070": {"tactic": "Defense Evasion", "technique": "Indicator Removal"},
    "T1055": {"tactic": "Defense Evasion", "technique": "Process Injection"},
}


async def generate_report(
    alert_data: Dict[str, Any],
    triage_result: Dict[str, Any],
    investigation_result: Dict[str, Any],
    anomaly_result: Dict[str, Any],
    response_result: Dict[str, Any],
    callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Generate a comprehensive investigation report.

    Combines findings from all agents into a structured report with:
    - Executive summary
    - Timeline of events
    - MITRE ATT&CK mapping
    - Evidence chain
    - Recommendations
    """
    if callback:
        await callback({
            "type": "agent_action",
            "agent": "report",
            "action": "starting",
            "detail": "Compiling investigation report...",
        })

    # Collect all findings
    all_findings = (
        triage_result.get("findings", [])
        + investigation_result.get("findings", [])
        + anomaly_result.get("findings", [])
        + response_result.get("findings", [])
    )

    # Collect all timeline events
    all_timeline = (
        triage_result.get("timeline_events", [])
        + investigation_result.get("timeline_events", [])
        + anomaly_result.get("timeline_events", [])
        + response_result.get("timeline_events", [])
    )

    # Sort timeline by timestamp
    all_timeline.sort(key=lambda x: x.get("timestamp", ""))

    # Collect MITRE techniques
    mitre_techniques = list(set(
        investigation_result.get("mitre_techniques", [])
        + triage_result.get("mitre_techniques", [])
    ))

    # Build MITRE mapping
    mitre_mapping = []
    for technique_id in mitre_techniques:
        info = MITRE_TACTICS.get(technique_id, {"tactic": "Unknown", "technique": "Unknown"})
        mitre_mapping.append({
            "technique_id": technique_id,
            "tactic": info["tactic"],
            "technique": info["technique"],
        })

    # Generate executive summary
    severity = triage_result.get("severity", "medium")
    if isinstance(severity, str):
        severity_str = severity
    else:
        severity_str = severity.value if hasattr(severity, 'value') else str(severity)

    threat_category = triage_result.get("threat_category", "Unknown")
    total_anomalies = anomaly_result.get("total_anomalies", 0)
    steps_taken = investigation_result.get("steps_taken", 0)
    affected_assets = investigation_result.get("affected_assets", [])
    affected_users = investigation_result.get("affected_users", [])

    executive_summary = (
        f"SentinelFlow completed an autonomous investigation of a {severity_str}-severity "
        f"{threat_category} incident. The investigation executed {steps_taken} analytical steps, "
        f"identified {total_anomalies} behavioral anomalies, and mapped findings to "
        f"{len(mitre_techniques)} MITRE ATT&CK techniques. "
        f"{len(affected_assets)} assets and {len(affected_users)} users were affected."
    )

    if investigation_result.get("summary"):
        executive_summary += f"\n\n{investigation_result['summary']}"

    # Build report
    report = {
        "executive_summary": executive_summary,
        "severity": severity_str,
        "threat_category": threat_category,
        "alert": {
            "title": alert_data.get("title", "Unknown"),
            "description": alert_data.get("description", ""),
            "source_ip": alert_data.get("source_ip"),
            "dest_ip": alert_data.get("dest_ip"),
            "user": alert_data.get("user"),
        },
        "findings": all_findings,
        "timeline": all_timeline,
        "mitre_mapping": mitre_mapping,
        "mitre_techniques": mitre_techniques,
        "anomalies": {
            "total": total_anomalies,
            "details": anomaly_result.get("anomalies", [])[:10],
        },
        "affected_assets": affected_assets,
        "affected_users": affected_users,
        "recommendations": (
            investigation_result.get("recommendations", [])
            + [a["description"] for a in response_result.get("recommended_actions", []) if a.get("recommended")]
        ),
        "response_actions": {
            "recommended": response_result.get("recommended_actions", []),
            "executed": response_result.get("executed_actions", []),
        },
        "investigation_stats": {
            "steps_taken": steps_taken,
            "findings_count": len(all_findings),
            "anomalies_detected": total_anomalies,
            "mitre_techniques_mapped": len(mitre_techniques),
        },
        "generated_at": datetime.utcnow().isoformat(),
    }

    if callback:
        await callback({
            "type": "agent_result",
            "agent": "report",
            "result": {
                "executive_summary": executive_summary,
                "severity": severity_str,
                "findings_count": len(all_findings),
                "mitre_techniques": mitre_techniques,
                "recommendations_count": len(report["recommendations"]),
            },
        })

    return report
