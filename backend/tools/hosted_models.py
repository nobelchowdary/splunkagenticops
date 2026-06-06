"""Splunk Hosted Models integration — Foundation-Sec-8B and Cisco Deep Time Series Model."""

import httpx
from typing import Dict, Any, List, Optional
from config import get_settings


class FoundationSecClient:
    """Client for the Foundation-Sec-8B hosted model (threat classification & IOC extraction)."""

    def __init__(self):
        settings = get_settings()
        self.endpoint = settings.foundation_sec_endpoint
        self.client = httpx.AsyncClient(timeout=30.0)

    async def classify_threat(self, alert_text: str) -> Dict[str, Any]:
        """Classify a security alert using Foundation-Sec-8B."""
        payload = {
            "prompt": f"""Analyze this security alert and provide:
1. Threat category (e.g., Credential Access, Lateral Movement, Exfiltration, etc.)
2. Severity (critical/high/medium/low)
3. Extracted IOCs (IPs, domains, hashes, filenames)
4. MITRE ATT&CK technique IDs
5. Recommended investigation steps

Alert:
{alert_text}""",
            "max_tokens": 1024,
            "temperature": 0.1,
        }

        try:
            response = await self.client.post(self.endpoint, json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError:
            # Fallback: return structured placeholder if model unavailable
            return self._fallback_classification(alert_text)

    def _fallback_classification(self, alert_text: str) -> Dict[str, Any]:
        """Fallback classification when hosted model is unavailable."""
        # Basic keyword-based classification as fallback
        text_lower = alert_text.lower()
        if "brute force" in text_lower or "failed login" in text_lower:
            return {
                "threat_category": "Credential Access",
                "severity": "high",
                "mitre_techniques": ["T1110"],
                "iocs": [],
                "investigation_steps": [
                    "Check auth logs for source IP",
                    "Look for successful login after failures",
                    "Check if account was compromised",
                ],
            }
        elif "lateral" in text_lower or "psexec" in text_lower:
            return {
                "threat_category": "Lateral Movement",
                "severity": "critical",
                "mitre_techniques": ["T1021"],
                "iocs": [],
                "investigation_steps": [
                    "Trace source system",
                    "Check for credential reuse",
                    "Map affected systems",
                ],
            }
        return {
            "threat_category": "Unknown",
            "severity": "medium",
            "mitre_techniques": [],
            "iocs": [],
            "investigation_steps": ["Investigate further"],
        }

    async def extract_iocs(self, text: str) -> List[str]:
        """Extract Indicators of Compromise from text."""
        payload = {
            "prompt": f"Extract all IOCs (IP addresses, domains, file hashes, filenames) from this text. Return as a JSON list:\n\n{text}",
            "max_tokens": 512,
            "temperature": 0.0,
        }

        try:
            response = await self.client.post(self.endpoint, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("iocs", [])
        except httpx.HTTPError:
            return []

    async def close(self):
        await self.client.aclose()


class CiscoDTSMClient:
    """Client for the Cisco Deep Time Series Model (anomaly detection)."""

    def __init__(self):
        settings = get_settings()
        self.endpoint = settings.cisco_dtsm_endpoint
        self.client = httpx.AsyncClient(timeout=60.0)

    async def detect_anomalies(
        self,
        time_series_data: List[Dict[str, Any]],
        metric_name: str = "event_count",
    ) -> Dict[str, Any]:
        """Detect anomalies in time-series data using Cisco DTSM."""
        payload = {
            "data": time_series_data,
            "metric": metric_name,
            "sensitivity": 0.8,
        }

        try:
            response = await self.client.post(self.endpoint, json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError:
            # Fallback: simple statistical anomaly detection
            return self._fallback_anomaly_detection(time_series_data, metric_name)

    def _fallback_anomaly_detection(
        self,
        data: List[Dict[str, Any]],
        metric_name: str,
    ) -> Dict[str, Any]:
        """Simple statistical anomaly detection as fallback."""
        if not data:
            return {"anomalies": [], "baseline": 0, "threshold": 0}

        values = [float(d.get(metric_name, 0)) for d in data]
        if not values:
            return {"anomalies": [], "baseline": 0, "threshold": 0}

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        threshold = mean + (2 * std_dev)

        anomalies = []
        for i, d in enumerate(data):
            value = float(d.get(metric_name, 0))
            if value > threshold:
                anomalies.append({
                    "index": i,
                    "timestamp": d.get("_time", ""),
                    "value": value,
                    "deviation": (value - mean) / std_dev if std_dev > 0 else 0,
                })

        return {
            "anomalies": anomalies,
            "baseline": mean,
            "threshold": threshold,
            "std_dev": std_dev,
        }

    async def forecast(
        self,
        time_series_data: List[Dict[str, Any]],
        periods: int = 24,
    ) -> Dict[str, Any]:
        """Forecast future values using the time series model."""
        payload = {
            "data": time_series_data,
            "forecast_periods": periods,
        }

        try:
            response = await self.client.post(
                f"{self.endpoint}/forecast", json=payload
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError:
            return {"forecast": [], "error": "Model unavailable"}

    async def close(self):
        await self.client.aclose()


# Singletons
_foundation_sec: Optional[FoundationSecClient] = None
_cisco_dtsm: Optional[CiscoDTSMClient] = None


def get_foundation_sec() -> FoundationSecClient:
    global _foundation_sec
    if _foundation_sec is None:
        _foundation_sec = FoundationSecClient()
    return _foundation_sec


def get_cisco_dtsm() -> CiscoDTSMClient:
    global _cisco_dtsm
    if _cisco_dtsm is None:
        _cisco_dtsm = CiscoDTSMClient()
    return _cisco_dtsm
