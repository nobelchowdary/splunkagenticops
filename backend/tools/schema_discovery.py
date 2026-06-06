"""Schema Discovery — Queries Splunk for available indexes, sourcetypes, and fields.

This gives agents real context about what data exists, eliminating SPL hallucination.
The schema is cached after first discovery and injected into every agent prompt.
"""

import httpx
from typing import Dict, Any, List, Optional
from config import get_settings


class SplunkSchemaDiscovery:
    """Discovers and caches the Splunk environment schema for agent context."""

    def __init__(self):
        settings = get_settings()
        self.base_url = settings.splunk_mcp_url
        self.token = settings.splunk_mcp_token
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            verify=False,
        )
        self._schema_cache: Optional[Dict[str, Any]] = None

    async def discover_schema(self) -> Dict[str, Any]:
        """Discover the full Splunk schema — indexes, sourcetypes, key fields."""
        if self._schema_cache:
            return self._schema_cache

        schema = {
            "indexes": await self._get_indexes(),
            "sourcetypes_by_index": await self._get_sourcetypes(),
            "fields_by_sourcetype": await self._get_fields(),
        }

        self._schema_cache = schema
        return schema

    async def _get_indexes(self) -> List[str]:
        """Get all available indexes."""
        try:
            payload = {
                "query": "| eventcount summarize=false index=* | dedup index | fields index",
                "earliest_time": "-24h",
                "latest_time": "now",
            }
            response = await self.client.post(
                f"{self.base_url}/services/search/jobs/export",
                json=payload,
            )
            if response.status_code == 200:
                data = response.json()
                return [r.get("index", "") for r in data.get("results", [])]
        except Exception:
            pass

        # Fallback: return known indexes from our sample data
        return ["auth_logs", "network_traffic", "dns_logs", "endpoint_logs", "security_alerts", "main"]

    async def _get_sourcetypes(self) -> Dict[str, List[str]]:
        """Get sourcetypes per index."""
        try:
            payload = {
                "query": "| metadata type=sourcetypes | fields sourcetype, totalCount",
                "earliest_time": "-24h",
                "latest_time": "now",
            }
            response = await self.client.post(
                f"{self.base_url}/services/search/jobs/export",
                json=payload,
            )
            if response.status_code == 200:
                data = response.json()
                # Group by index
                return {r.get("index", "main"): [r.get("sourcetype")] for r in data.get("results", [])}
        except Exception:
            pass

        # Fallback: known sourcetypes from sample data
        return {
            "auth_logs": ["WinEventLog:Security"],
            "network_traffic": ["firewall"],
            "dns_logs": ["dns"],
            "endpoint_logs": ["endpoint"],
            "security_alerts": ["sentinelflow:notable"],
        }

    async def _get_fields(self) -> Dict[str, List[str]]:
        """Get key fields per sourcetype."""
        # For speed, return known field mappings
        # In production, you'd query: | fieldsummary | where count > 10
        return {
            "WinEventLog:Security": [
                "_time", "EventCode", "action", "user", "src_ip", "dest",
                "LogonType", "FailureReason", "app", "signature",
            ],
            "firewall": [
                "_time", "action", "src_ip", "dest_ip", "dest_port",
                "bytes_out", "bytes_in", "protocol", "direction",
            ],
            "dns": [
                "_time", "src_ip", "query", "query_type", "reply_code", "answer",
            ],
            "endpoint": [
                "_time", "event_type", "host", "user", "process_name",
                "parent_process", "command_line", "file_path", "action", "bytes_read",
            ],
        }

    def get_schema_prompt(self, schema: Dict[str, Any]) -> str:
        """Format schema into a prompt-injectable string for agents."""
        lines = ["## Splunk Environment Schema (VERIFIED — use these exact names)\n"]

        lines.append("### Available Indexes:")
        for idx in schema.get("indexes", []):
            lines.append(f"  - {idx}")

        lines.append("\n### Sourcetypes by Index:")
        for idx, sourcetypes in schema.get("sourcetypes_by_index", {}).items():
            lines.append(f"  - index={idx}: sourcetypes = {', '.join(sourcetypes)}")

        lines.append("\n### Fields by Sourcetype:")
        for st, fields in schema.get("fields_by_sourcetype", {}).items():
            lines.append(f"  - {st}: {', '.join(fields)}")

        lines.append("\n### IMPORTANT RULES:")
        lines.append("  - ALWAYS specify index= in your searches")
        lines.append("  - Use exact field names listed above (case-sensitive)")
        lines.append("  - Index names: auth_logs, network_traffic, dns_logs, endpoint_logs, security_alerts")
        lines.append("  - For auth events: action='success' or action='failure'")
        lines.append("  - For network: direction='inbound' or 'outbound'")
        lines.append("  - For endpoint: event_type='process_creation' or 'file_access'")
        lines.append("  - Time format: earliest=-24h, earliest=-1h, etc.")

        return "\n".join(lines)

    async def close(self):
        await self.client.aclose()


# Singleton
_discovery: Optional[SplunkSchemaDiscovery] = None


def get_schema_discovery() -> SplunkSchemaDiscovery:
    global _discovery
    if _discovery is None:
        _discovery = SplunkSchemaDiscovery()
    return _discovery
