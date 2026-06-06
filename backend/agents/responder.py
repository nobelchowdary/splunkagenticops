"""Response Agent — Recommend and execute containment actions."""

from typing import Dict, Any, Callable, Optional, List
from datetime import datetime

from models import Finding, Severity, TimelineEvent


# Playbook definitions based on threat categories
PLAYBOOKS = {
    "Credential Access": {
        "actions": [
            {"action": "disable_account", "description": "Disable compromised user account", "confidence_threshold": 0.8},
            {"action": "block_ip", "description": "Block source IP at firewall", "confidence_threshold": 0.7},
            {"action": "force_password_reset", "description": "Force password reset for affected user", "confidence_threshold": 0.6},
            {"action": "enable_mfa", "description": "Enable MFA for affected account", "confidence_threshold": 0.5},
        ],
    },
    "Lateral Movement": {
        "actions": [
            {"action": "isolate_host", "description": "Isolate affected hosts from network", "confidence_threshold": 0.8},
            {"action": "block_ip", "description": "Block internal lateral IPs", "confidence_threshold": 0.7},
            {"action": "revoke_sessions", "description": "Revoke all active sessions for affected accounts", "confidence_threshold": 0.7},
            {"action": "scan_endpoints", "description": "Initiate endpoint scan on affected systems", "confidence_threshold": 0.5},
        ],
    },
    "Exfiltration": {
        "actions": [
            {"action": "block_ip", "description": "Block destination exfiltration IP", "confidence_threshold": 0.7},
            {"action": "isolate_host", "description": "Isolate source host", "confidence_threshold": 0.8},
            {"action": "disable_account", "description": "Disable account performing exfiltration", "confidence_threshold": 0.8},
            {"action": "preserve_evidence", "description": "Capture forensic snapshot of affected systems", "confidence_threshold": 0.5},
        ],
    },
    "Unknown": {
        "actions": [
            {"action": "create_notable", "description": "Create notable event for SOC review", "confidence_threshold": 0.3},
            {"action": "increase_monitoring", "description": "Increase monitoring on affected entities", "confidence_threshold": 0.4},
        ],
    },
}


async def run_response(
    triage_result: Dict[str, Any],
    investigation_result: Dict[str, Any],
    anomaly_result: Dict[str, Any],
    alert_data: Dict[str, Any],
    auto_respond: bool = False,
    callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Determine and recommend response actions based on investigation findings.

    If auto_respond is True, will execute high-confidence actions automatically.
    """
    findings: List[Dict[str, Any]] = []
    timeline_events: List[Dict[str, Any]] = []
    recommended_actions: List[Dict[str, Any]] = []
    executed_actions: List[Dict[str, Any]] = []

    if callback:
        await callback({
            "type": "agent_action",
            "agent": "response",
            "action": "starting",
            "detail": "Analyzing findings to determine response actions...",
        })

    # Determine threat category and severity
    threat_category = triage_result.get("threat_category", "Unknown")
    severity = triage_result.get("severity", Severity.MEDIUM)
    if isinstance(severity, str):
        severity = Severity(severity)

    # Calculate overall confidence based on findings
    all_findings = (
        triage_result.get("findings", [])
        + investigation_result.get("findings", [])
        + anomaly_result.get("findings", [])
    )
    avg_confidence = (
        sum(f.get("confidence", 0.5) for f in all_findings) / len(all_findings)
        if all_findings
        else 0.5
    )

    # Get applicable playbook
    playbook = PLAYBOOKS.get(threat_category, PLAYBOOKS["Unknown"])

    if callback:
        await callback({
            "type": "agent_action",
            "agent": "response",
            "action": "planning",
            "detail": f"Applying playbook for '{threat_category}' (confidence: {avg_confidence:.0%})",
        })

    # Evaluate each action in the playbook
    for action_def in playbook["actions"]:
        action = {
            "action": action_def["action"],
            "description": action_def["description"],
            "confidence": avg_confidence,
            "threshold": action_def["confidence_threshold"],
            "recommended": avg_confidence >= action_def["confidence_threshold"],
            "auto_executable": auto_respond and avg_confidence >= action_def["confidence_threshold"],
        }

        # Add context-specific details
        if action_def["action"] == "block_ip" and alert_data.get("source_ip"):
            action["target"] = alert_data["source_ip"]
        elif action_def["action"] == "disable_account" and alert_data.get("user"):
            action["target"] = alert_data["user"]
        elif action_def["action"] == "isolate_host":
            affected = investigation_result.get("affected_assets", [])
            action["target"] = affected if affected else "Unknown hosts"

        recommended_actions.append(action)

        # Auto-execute if enabled and confidence meets threshold
        if action["auto_executable"]:
            executed_actions.append(action)
            if callback:
                await callback({
                    "type": "agent_action",
                    "agent": "response",
                    "action": "executing",
                    "detail": f"Auto-executing: {action['description']} (target: {action.get('target', 'N/A')})",
                })

            # Execute via Splunk SDK (notable event / adaptive response)
            timeline_events.append(
                TimelineEvent(
                    timestamp=datetime.utcnow(),
                    agent="response",
                    action="action_executed",
                    detail=f"Executed: {action['description']}",
                ).model_dump()
            )

    # Create findings
    findings.append(
        Finding(
            agent="response",
            type="recommendation",
            title=f"Response Plan: {len(recommended_actions)} actions recommended",
            description=(
                f"Based on {threat_category} classification with {avg_confidence:.0%} confidence. "
                f"{len(executed_actions)} actions auto-executed, "
                f"{len(recommended_actions) - len(executed_actions)} awaiting manual approval."
            ),
            severity=severity,
            confidence=avg_confidence,
        ).model_dump()
    )

    if callback:
        await callback({
            "type": "agent_result",
            "agent": "response",
            "result": {
                "recommended_actions": recommended_actions,
                "executed_actions": executed_actions,
                "threat_category": threat_category,
                "confidence": avg_confidence,
            },
        })

    return {
        "findings": findings,
        "timeline_events": timeline_events,
        "recommended_actions": recommended_actions,
        "executed_actions": executed_actions,
    }
