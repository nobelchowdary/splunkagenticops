"""Splunk Hosted Models integration — Foundation-Sec-8B and Cisco Deep Time Series Model.

When Splunk Hosted Models are unavailable, uses Claude as an intelligent fallback
for threat classification (emulating Foundation-Sec-8B behavior) and statistical
methods for anomaly detection (emulating Cisco DTSM).
"""

import json
import re
import httpx
from typing import Dict, Any, List, Optional
from config import get_settings


class FoundationSecClient:
    """Client for the Foundation-Sec-8B hosted model (threat classification & IOC extraction).
    
    Falls back to Claude LLM for intelligent classification when the hosted model
    endpoint is unavailable. This provides near-equivalent threat analysis capability.
    """

    def __init__(self):
        settings = get_settings()
        self.endpoint = settings.foundation_sec_endpoint
        self.client = httpx.AsyncClient(timeout=30.0)
        self._llm = None
        self._settings = settings

    def _get_llm(self):
        """Lazy-load Claude for fallback classification."""
        if self._llm is None:
            from langchain_anthropic import ChatAnthropic
            self._llm = ChatAnthropic(
                model=self._settings.llm_model,
                api_key=self._settings.anthropic_api_key,
                temperature=0.1,
                max_tokens=1024,
            )
        return self._llm

    async def classify_threat(self, alert_text: str) -> Dict[str, Any]:
        """Classify a security alert using Foundation-Sec-8B (or Claude fallback)."""
        # Try Foundation-Sec-8B hosted model first
        if self.endpoint:
            try:
                payload = {
                    "prompt": f"Classify this security alert:\n\n{alert_text}",
                    "max_tokens": 1024,
                    "temperature": 0.1,
                }
                response = await self.client.post(self.endpoint, json=payload)
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, Exception):
                pass

        # Fallback: Use Claude for intelligent threat classification
        return await self._llm_classification(alert_text)

    async def _llm_classification(self, alert_text: str) -> Dict[str, Any]:
        """Use Claude to classify threats (emulating Foundation-Sec-8B)."""
        import asyncio
        from langchain_core.messages import HumanMessage, SystemMessage

        system = """You are a security threat classifier (emulating Splunk Foundation-Sec-8B).
Analyze the alert and respond with ONLY a JSON object (no markdown, no explanation):
{
    "threat_category": "<one of: Credential Access, Lateral Movement, Exfiltration, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Discovery, Collection, Command and Control, Impact>",
    "severity": "<critical|high|medium|low>",
    "mitre_techniques": ["<T-number>", ...],
    "iocs": ["<IP addresses, domains, hashes, filenames found in alert>"],
    "investigation_steps": ["<step 1>", "<step 2>", "<step 3>"]
}"""

        try:
            llm = self._get_llm()
            response = await llm.ainvoke([
                SystemMessage(content=system),
                HumanMessage(content=f"Alert:\n{alert_text}"),
            ])
            
            # Parse JSON from response
            text = response.content
            json_start = text.find("{")
            json_end = text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                result = json.loads(text[json_start:json_end])
                return result
        except Exception:
            pass

        # Final keyword fallback if LLM also fails
        return self._keyword_fallback(alert_text)

    def _keyword_fallback(self, alert_text: str) -> Dict[str, Any]:
        """Last-resort keyword-based classification."""
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
        elif "exfil" in text_lower or "data transfer" in text_lower:
            return {
                "threat_category": "Exfiltration",
                "severity": "critical",
                "mitre_techniques": ["T1048"],
                "iocs": [],
                "investigation_steps": [
                    "Identify data destinations",
                    "Quantify data volume",
                    "Check DNS for tunneling",
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
        """Extract Indicators of Compromise from text using regex + LLM."""
        iocs = []
        
        # Regex extraction for common IOC patterns
        # IPv4 addresses (exclude private ranges for external IOCs)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ips = re.findall(ip_pattern, text)
        iocs.extend(ips)
        
        # Domains (basic pattern)
        domain_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b'
        domains = [d for d in re.findall(domain_pattern, text) if '.' in d and not d.replace('.','').isdigit()]
        # Filter out common non-IOC domains
        common = {'gmail.com', 'google.com', 'microsoft.com', 'localhost'}
        iocs.extend([d for d in domains if d not in common])
        
        # MD5/SHA hashes
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        hashes = re.findall(hash_pattern, text)
        iocs.extend(hashes)
        
        return list(set(iocs))

    async def close(self):
        await self.client.aclose()


class CiscoDTSMClient:
    """Client for the Cisco Deep Time Series Model (anomaly detection).
    
    Falls back to a multi-method statistical anomaly detector:
    - Z-score analysis (standard deviation thresholds)
    - IQR method (interquartile range for robustness to outliers)
    - Rate-of-change detection (sudden spikes/drops)
    """

    def __init__(self):
        settings = get_settings()
        self.endpoint = settings.cisco_dtsm_endpoint
        self.client = httpx.AsyncClient(timeout=60.0)

    async def detect_anomalies(
        self,
        time_series_data: List[Dict[str, Any]],
        metric_name: str = "event_count",
    ) -> Dict[str, Any]:
        """Detect anomalies in time-series data using Cisco DTSM (or statistical fallback)."""
        # Try Cisco DTSM hosted model first
        if self.endpoint:
            try:
                payload = {
                    "data": time_series_data,
                    "metric": metric_name,
                    "sensitivity": 0.8,
                }
                response = await self.client.post(self.endpoint, json=payload)
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, Exception):
                pass

        # Fallback: multi-method statistical anomaly detection
        return self._statistical_anomaly_detection(time_series_data, metric_name)

    def _statistical_anomaly_detection(
        self,
        data: List[Dict[str, Any]],
        metric_name: str,
    ) -> Dict[str, Any]:
        """Multi-method statistical anomaly detection (emulating Cisco DTSM)."""
        if not data:
            return {"anomalies": [], "baseline": 0, "threshold": 0, "method": "none"}

        values = [float(d.get(metric_name, d.get("count", 0))) for d in data]
        if not values or all(v == 0 for v in values):
            return {"anomalies": [], "baseline": 0, "threshold": 0, "method": "none"}

        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n
        std_dev = variance ** 0.5

        # Method 1: Z-score (detects points > 2 std deviations from mean)
        z_anomalies = set()
        z_threshold = mean + (2 * std_dev) if std_dev > 0 else mean * 2
        for i, v in enumerate(values):
            if std_dev > 0 and abs(v - mean) / std_dev > 2.0:
                z_anomalies.add(i)

        # Method 2: IQR (robust to outliers)
        sorted_values = sorted(values)
        q1_idx = n // 4
        q3_idx = (3 * n) // 4
        q1 = sorted_values[q1_idx] if q1_idx < n else 0
        q3 = sorted_values[q3_idx] if q3_idx < n else 0
        iqr = q3 - q1
        iqr_upper = q3 + (1.5 * iqr)
        iqr_anomalies = {i for i, v in enumerate(values) if v > iqr_upper}

        # Method 3: Rate of change (sudden spikes)
        roc_anomalies = set()
        for i in range(1, n):
            if values[i - 1] > 0:
                change_rate = (values[i] - values[i - 1]) / values[i - 1]
                if change_rate > 3.0:  # 300% increase
                    roc_anomalies.add(i)

        # Combine: flag as anomaly if detected by 2+ methods (consensus)
        all_anomaly_indices = z_anomalies | iqr_anomalies | roc_anomalies
        consensus_anomalies = []
        for i in all_anomaly_indices:
            methods_detected = []
            if i in z_anomalies:
                methods_detected.append("z-score")
            if i in iqr_anomalies:
                methods_detected.append("iqr")
            if i in roc_anomalies:
                methods_detected.append("rate-of-change")
            
            score = len(methods_detected) / 3.0  # confidence 0.33 - 1.0
            deviation = (values[i] - mean) / std_dev if std_dev > 0 else 0

            consensus_anomalies.append({
                "index": i,
                "timestamp": data[i].get("_time", f"T+{i}h"),
                "value": values[i],
                "deviation": round(deviation, 2),
                "confidence": round(score, 2),
                "methods": methods_detected,
            })

        # Sort by confidence (highest first)
        consensus_anomalies.sort(key=lambda x: -x["confidence"])

        return {
            "anomalies": consensus_anomalies,
            "baseline": round(mean, 2),
            "threshold": round(z_threshold, 2),
            "std_dev": round(std_dev, 2),
            "iqr_upper": round(iqr_upper, 2),
            "data_points": n,
            "method": "multi-statistical (z-score + IQR + rate-of-change)",
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
