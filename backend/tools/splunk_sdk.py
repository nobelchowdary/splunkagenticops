"""Splunk Python SDK client — for actions (notable events, risk scores, etc.)."""

import splunklib.client as client
import splunklib.results as results
from typing import Optional, Dict, Any, List
from config import get_settings


class SplunkSDKClient:
    """Client for Splunk operations via the Python SDK."""

    def __init__(self):
        settings = get_settings()
        self.service = client.connect(
            host=settings.splunk_host,
            port=settings.splunk_port,
            username=settings.splunk_username,
            password=settings.splunk_password,
            scheme=settings.splunk_scheme,
            autologin=True,
        )

    def create_notable_event(
        self,
        title: str,
        description: str,
        severity: str = "high",
        src_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        user: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a notable event in Splunk ES."""
        event_data = {
            "title": title,
            "description": description,
            "severity": severity,
            "source": "SentinelFlow",
        }
        if src_ip:
            event_data["src_ip"] = src_ip
        if dest_ip:
            event_data["dest_ip"] = dest_ip
        if user:
            event_data["user"] = user

        # Submit as an event to the notable index
        index = self.service.indexes["notable"]
        index.submit(
            event=str(event_data),
            sourcetype="sentinelflow:notable",
            source="sentinelflow",
        )
        return {"status": "created", "event": event_data}

    def update_risk_score(
        self,
        entity: str,
        entity_type: str,  # "user" or "system"
        risk_score: int,
        reason: str,
    ) -> Dict[str, Any]:
        """Update risk score for an entity."""
        # Use the risk index
        risk_event = {
            "risk_object": entity,
            "risk_object_type": entity_type,
            "risk_score": risk_score,
            "description": reason,
            "source": "SentinelFlow",
        }

        index = self.service.indexes["risk"]
        index.submit(
            event=str(risk_event),
            sourcetype="sentinelflow:risk",
            source="sentinelflow",
        )
        return {"status": "updated", "entity": entity, "risk_score": risk_score}

    def run_search(self, spl_query: str) -> List[Dict[str, Any]]:
        """Run a one-shot search and return results."""
        kwargs = {"earliest_time": "-24h", "latest_time": "now"}
        job_results = self.service.jobs.oneshot(spl_query, **kwargs)
        reader = results.JSONResultsReader(job_results)
        return [item for item in reader if isinstance(item, dict)]

    def get_saved_searches(self) -> List[str]:
        """List available saved searches."""
        return [ss.name for ss in self.service.saved_searches]


# Singleton
_sdk_client: Optional[SplunkSDKClient] = None


def get_sdk_client() -> SplunkSDKClient:
    global _sdk_client
    if _sdk_client is None:
        _sdk_client = SplunkSDKClient()
    return _sdk_client
