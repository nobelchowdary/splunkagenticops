"""Anomaly Agent — Detect behavioral anomalies using Cisco Deep Time Series Model."""

from typing import Dict, Any, Callable, Optional, List
from datetime import datetime

from tools.splunk_mcp import get_mcp_client
from tools.hosted_models import get_cisco_dtsm
from models import Finding, Severity, TimelineEvent


async def run_anomaly_detection(
    alert_data: Dict[str, Any],
    triage_result: Dict[str, Any],
    callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Detect behavioral anomalies around the incident timeframe.

    Uses Cisco Deep Time Series Model to identify deviations from baseline
    in key metrics: login volumes, network traffic, process creation rates.
    """
    mcp = get_mcp_client()
    dtsm = get_cisco_dtsm()

    findings: List[Dict[str, Any]] = []
    timeline_events: List[Dict[str, Any]] = []
    anomalies_detected: List[Dict[str, Any]] = []

    if callback:
        await callback({
            "type": "agent_action",
            "agent": "anomaly",
            "action": "starting",
            "detail": "Collecting time-series data for anomaly detection...",
        })

    # Define metrics to analyze
    metrics_queries = [
        {
            "name": "auth_failures",
            "description": "Authentication failure rate",
            "spl": 'search index=auth_logs action=failure | timechart span=1h count as event_count',
        },
        {
            "name": "network_egress",
            "description": "Network egress volume (bytes)",
            "spl": 'search index=network_traffic direction=outbound | timechart span=1h sum(bytes_out) as event_count',
        },
        {
            "name": "process_creation",
            "description": "New process creation rate",
            "spl": 'search index=endpoint_logs event_type=process_creation | timechart span=1h count as event_count',
        },
    ]

    # Add user-specific metrics if user is known
    user = alert_data.get("user")
    if user:
        metrics_queries.append({
            "name": f"user_activity_{user}",
            "description": f"Activity volume for user {user}",
            "spl": f'search index=* user="{user}" | timechart span=1h count as event_count',
        })

    # Add IP-specific metrics if source IP is known
    src_ip = alert_data.get("source_ip")
    if src_ip:
        metrics_queries.append({
            "name": f"ip_traffic_{src_ip}",
            "description": f"Traffic volume for IP {src_ip}",
            "spl": f'search index=network_traffic src_ip="{src_ip}" | timechart span=1h sum(bytes_out) as event_count',
        })

    # Collect and analyze each metric
    for metric in metrics_queries:
        if callback:
            await callback({
                "type": "agent_action",
                "agent": "anomaly",
                "action": "collecting",
                "detail": f"Collecting: {metric['description']}",
                "spl_query": metric["spl"],
            })

        # Get time-series data from Splunk
        result = await mcp.run_custom_spl(metric["spl"])
        time_series_data = result.get("results", [])

        if not time_series_data:
            continue

        # Run anomaly detection via Cisco DTSM
        if callback:
            await callback({
                "type": "agent_action",
                "agent": "anomaly",
                "action": "detecting",
                "detail": f"Running Cisco DTSM on {metric['description']} ({len(time_series_data)} data points)",
            })

        anomaly_result = await dtsm.detect_anomalies(
            time_series_data, metric_name="event_count"
        )

        detected = anomaly_result.get("anomalies", [])
        if detected:
            anomalies_detected.extend([
                {**a, "metric": metric["name"], "description": metric["description"]}
                for a in detected
            ])

            # Create finding for this anomaly
            max_deviation = max(a.get("deviation", 0) for a in detected)
            severity = Severity.CRITICAL if max_deviation > 4 else (
                Severity.HIGH if max_deviation > 3 else Severity.MEDIUM
            )

            findings.append(
                Finding(
                    agent="anomaly",
                    type="anomaly",
                    title=f"Anomaly Detected: {metric['description']}",
                    description=(
                        f"{len(detected)} anomalous periods detected in {metric['description']}. "
                        f"Maximum deviation: {max_deviation:.1f} standard deviations above baseline. "
                        f"Baseline: {anomaly_result.get('baseline', 0):.0f}, "
                        f"Threshold: {anomaly_result.get('threshold', 0):.0f}"
                    ),
                    severity=severity,
                    evidence=metric["spl"],
                    confidence=min(0.5 + (max_deviation * 0.1), 0.95),
                ).model_dump()
            )

            timeline_events.append(
                TimelineEvent(
                    timestamp=datetime.utcnow(),
                    agent="anomaly",
                    action="anomaly_detected",
                    detail=f"{metric['description']}: {len(detected)} anomalies ({max_deviation:.1f}σ max)",
                    spl_query=metric["spl"],
                ).model_dump()
            )

    # Summary
    total_anomalies = len(anomalies_detected)
    if callback:
        await callback({
            "type": "agent_result",
            "agent": "anomaly",
            "result": {
                "total_anomalies": total_anomalies,
                "metrics_analyzed": len(metrics_queries),
                "anomaly_details": anomalies_detected[:10],  # Top 10
            },
        })

    return {
        "findings": findings,
        "timeline_events": timeline_events,
        "anomalies": anomalies_detected,
        "metrics_analyzed": len(metrics_queries),
        "total_anomalies": total_anomalies,
    }
