"""Orchestrator — LangGraph state machine coordinating all agents.

Design philosophy (risk mitigation):
- Core agents (Triage + Investigation) are required and always run
- Stretch agents (Anomaly + Response) gracefully degrade with mock data if unavailable
- All phases stream updates to UI regardless of success/failure
"""

from typing import Dict, Any, Callable, Optional
from datetime import datetime

from models import InvestigationState, InvestigationStatus
from agents.triage import run_triage
from agents.investigator import run_investigation as run_investigation_agent
from agents.anomaly import run_anomaly_detection
from agents.responder import run_response
from agents.reporter import generate_report


def _mock_anomaly_result(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Mock anomaly results when Cisco DTSM is unavailable."""
    return {
        "findings": [{
            "agent": "anomaly",
            "type": "anomaly",
            "title": "Anomaly Detection (Simulated)",
            "description": "Cisco Deep Time Series Model not connected. In production, this would analyze login volumes, network egress, and process creation rates for behavioral anomalies.",
            "severity": "medium",
            "confidence": 0.5,
        }],
        "timeline_events": [{
            "timestamp": datetime.utcnow().isoformat(),
            "agent": "anomaly",
            "action": "mock",
            "detail": "Anomaly detection running in simulation mode (Cisco DTSM unavailable)",
        }],
        "anomalies": [],
        "metrics_analyzed": 0,
        "total_anomalies": 0,
        "mock": True,
    }


def _mock_response_result(triage_result: Dict[str, Any], alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Mock response results when auto-response isn't configured."""
    threat_category = triage_result.get("threat_category", "Unknown")
    return {
        "findings": [{
            "agent": "response",
            "type": "recommendation",
            "title": f"Response Recommendations for {threat_category}",
            "description": "Automated response actions queued for analyst approval.",
            "severity": triage_result.get("severity", "medium"),
            "confidence": 0.7,
        }],
        "timeline_events": [{
            "timestamp": datetime.utcnow().isoformat(),
            "agent": "response",
            "action": "recommended",
            "detail": f"Generated response playbook for {threat_category}",
        }],
        "recommended_actions": [
            {"action": "block_ip", "description": f"Block source IP {alert_data.get('source_ip', 'N/A')}", "recommended": True, "confidence": 0.8},
            {"action": "disable_account", "description": f"Disable account {alert_data.get('user', 'N/A')}", "recommended": True, "confidence": 0.75},
            {"action": "isolate_host", "description": "Isolate affected hosts from network", "recommended": True, "confidence": 0.7},
        ],
        "executed_actions": [],
    }


async def run_investigation(
    investigation: InvestigationState,
    callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Orchestrate a full investigation across all agents.

    Flow:
    1. Triage → Classify and extract IOCs
    2. Investigation → Deep-dive with SPL queries
    3. Anomaly Detection → Behavioral analysis
    4. Response → Recommend actions
    5. Report → Generate summary

    Each step streams updates via the callback function.
    """

    alert_data = {
        "title": investigation.request.title,
        "description": investigation.request.description,
        "source_ip": investigation.request.source_ip,
        "dest_ip": investigation.request.dest_ip,
        "user": investigation.request.user,
        "timerange": investigation.request.timerange,
    }

    # === PHASE 1: TRIAGE ===
    if callback:
        await callback({
            "type": "phase",
            "phase": "triage",
            "status": "started",
            "message": "Phase 1/5: Triage — Classifying alert...",
        })

    investigation.status = InvestigationStatus.TRIAGING
    triage_result = await run_triage(alert_data, callback=callback)

    # Update investigation state
    investigation.severity = triage_result.get("severity", investigation.severity)
    investigation.iocs = triage_result.get("iocs", [])
    investigation.mitre_techniques = triage_result.get("mitre_techniques", [])

    if callback:
        await callback({
            "type": "phase",
            "phase": "triage",
            "status": "completed",
            "message": f"Triage complete: {triage_result.get('threat_category')} (severity: {investigation.severity.value})",
        })

    # === PHASE 2: INVESTIGATION ===
    if callback:
        await callback({
            "type": "phase",
            "phase": "investigation",
            "status": "started",
            "message": "Phase 2/5: Investigation — Autonomous SPL analysis...",
        })

    investigation.status = InvestigationStatus.INVESTIGATING
    investigation_result = await run_investigation_agent(
        triage_result, alert_data, callback=callback
    )

    # Update state
    investigation.affected_assets = investigation_result.get("affected_assets", [])
    investigation.affected_users = investigation_result.get("affected_users", [])
    investigation.mitre_techniques = list(set(
        investigation.mitre_techniques + investigation_result.get("mitre_techniques", [])
    ))

    if callback:
        await callback({
            "type": "phase",
            "phase": "investigation",
            "status": "completed",
            "message": f"Investigation complete: {investigation_result.get('steps_taken', 0)} steps taken",
        })

    # === PHASE 3: ANOMALY DETECTION (Stretch — gracefully degrades) ===
    if callback:
        await callback({
            "type": "phase",
            "phase": "anomaly",
            "status": "started",
            "message": "Phase 3/5: Anomaly Detection — Behavioral analysis...",
        })

    investigation.status = InvestigationStatus.DETECTING_ANOMALIES
    try:
        anomaly_result = await run_anomaly_detection(
            alert_data, triage_result, callback=callback
        )
    except Exception as e:
        # Graceful degradation — use mock data
        anomaly_result = _mock_anomaly_result(alert_data)
        if callback:
            await callback({
                "type": "agent_action",
                "agent": "anomaly",
                "action": "fallback",
                "detail": f"Anomaly detection using simulated mode: {str(e)[:100]}",
            })

    if callback:
        await callback({
            "type": "phase",
            "phase": "anomaly",
            "status": "completed",
            "message": f"Anomaly detection complete: {anomaly_result.get('total_anomalies', 0)} anomalies found" + (" (simulated)" if anomaly_result.get("mock") else ""),
        })

    # === PHASE 4: RESPONSE (Stretch — gracefully degrades) ===
    if callback:
        await callback({
            "type": "phase",
            "phase": "response",
            "status": "started",
            "message": "Phase 4/5: Response — Determining actions...",
        })

    investigation.status = InvestigationStatus.RESPONDING
    try:
        response_result = await run_response(
            triage_result,
            investigation_result,
            anomaly_result,
            alert_data,
            auto_respond=investigation.request.auto_respond,
            callback=callback,
        )
    except Exception as e:
        # Graceful degradation — use mock response
        response_result = _mock_response_result(triage_result, alert_data)
        if callback:
            await callback({
                "type": "agent_action",
                "agent": "response",
                "action": "fallback",
                "detail": f"Response agent using recommendations mode: {str(e)[:100]}",
            })

    if callback:
        await callback({
            "type": "phase",
            "phase": "response",
            "status": "completed",
            "message": f"Response complete: {len(response_result.get('recommended_actions', []))} actions recommended",
        })

    # === PHASE 5: REPORT ===
    if callback:
        await callback({
            "type": "phase",
            "phase": "report",
            "status": "started",
            "message": "Phase 5/5: Report — Generating summary...",
        })

    investigation.status = InvestigationStatus.REPORTING
    report = await generate_report(
        alert_data,
        triage_result,
        investigation_result,
        anomaly_result,
        response_result,
        callback=callback,
    )

    # Final state
    investigation.status = InvestigationStatus.COMPLETED
    investigation.summary = report.get("executive_summary")
    investigation.recommendations = report.get("recommendations", [])

    if callback:
        await callback({
            "type": "phase",
            "phase": "report",
            "status": "completed",
            "message": "Investigation complete. Report generated.",
        })

    return report
