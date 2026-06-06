"""Splunk MCP Server client — interface for querying Splunk data via MCP.

Falls back to Splunk SDK (direct REST API) when MCP server is unavailable.
"""

import httpx
from typing import Optional, Dict, Any, List
from config import get_settings


class SplunkMCPClient:
    """Client for interacting with Splunk via the MCP Server.
    
    Falls back to Splunk Python SDK when MCP is not available.
    """

    def __init__(self):
        settings = get_settings()
        self.base_url = settings.splunk_mcp_url
        self.token = settings.splunk_mcp_token
        self._use_sdk_fallback = not self.token  # Use SDK if no MCP token
        self._sdk_client = None
        
        if not self._use_sdk_fallback:
            self.client = httpx.AsyncClient(
                timeout=60.0,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
                verify=False,
            )

    def _get_sdk(self):
        """Lazy-load SDK client for fallback."""
        if self._sdk_client is None:
            from tools.splunk_sdk import get_sdk_client
            self._sdk_client = get_sdk_client()
        return self._sdk_client

    async def search(
        self,
        spl_query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 100,
    ) -> Dict[str, Any]:
        """Execute an SPL query via MCP Server (or SDK fallback) and return results."""
        
        # SDK fallback path
        if self._use_sdk_fallback:
            return await self._sdk_search(spl_query, earliest_time, max_results)
        
        payload = {
            "query": spl_query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "max_results": max_results,
        }

        try:
            response = await self.client.post(
                f"{self.base_url}/services/search/jobs/export",
                json=payload,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            # Fall back to SDK on MCP failure
            return await self._sdk_search(spl_query, earliest_time, max_results)

    async def _sdk_search(self, spl_query: str, earliest_time: str = "-24h", max_results: int = 100) -> Dict[str, Any]:
        """Execute SPL via Splunk SDK (synchronous but wrapped for async compatibility)."""
        import asyncio
        try:
            sdk = self._get_sdk()
            # Run sync SDK call in thread pool to avoid blocking
            results = await asyncio.to_thread(
                self._run_sdk_search, spl_query, earliest_time, max_results
            )
            return {"results": results}
        except Exception as e:
            return {"error": str(e), "results": []}

    def _run_sdk_search(self, spl_query: str, earliest_time: str, max_results: int) -> List[Dict]:
        """Synchronous SDK search."""
        import splunklib.results as splunk_results
        
        sdk = self._get_sdk()
        # Ensure query starts with 'search' command
        query = spl_query.strip()
        if not query.startswith("search") and not query.startswith("|"):
            query = f"search {query}"
        
        kwargs = {
            "earliest_time": earliest_time,
            "latest_time": "now",
            "count": max_results,
            "output_mode": "json",
        }
        job_results = sdk.service.jobs.oneshot(query, **kwargs)
        reader = splunk_results.JSONResultsReader(job_results)
        return [item for item in reader if isinstance(item, dict)]

    async def get_alerts(
        self, earliest_time: str = "-1h"
    ) -> List[Dict[str, Any]]:
        """Get recent alerts/notable events from Splunk."""
        spl = f'search index=security_alerts earliest={earliest_time} | head 50'
        result = await self.search(spl, earliest_time=earliest_time)
        return result.get("results", [])

    async def get_events_by_ip(
        self,
        ip: str,
        index: str = "*",
        earliest_time: str = "-24h",
    ) -> List[Dict[str, Any]]:
        """Get all events related to a specific IP address."""
        spl = f'search index={index} (src_ip="{ip}" OR dest_ip="{ip}") earliest={earliest_time} | head 200'
        result = await self.search(spl, earliest_time=earliest_time)
        return result.get("results", [])

    async def get_auth_events(
        self,
        user: Optional[str] = None,
        src_ip: Optional[str] = None,
        earliest_time: str = "-24h",
    ) -> List[Dict[str, Any]]:
        """Get authentication events."""
        filters = []
        if user:
            filters.append(f'user="{user}"')
        if src_ip:
            filters.append(f'src_ip="{src_ip}"')

        filter_str = " ".join(filters) if filters else ""
        spl = f'search index=auth_logs {filter_str} earliest={earliest_time} | stats count by action, user, src_ip, dest | sort -count'
        result = await self.search(spl, earliest_time=earliest_time)
        return result.get("results", [])

    async def get_network_traffic(
        self,
        src_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        earliest_time: str = "-24h",
    ) -> List[Dict[str, Any]]:
        """Get network traffic data."""
        filters = []
        if src_ip:
            filters.append(f'src_ip="{src_ip}"')
        if dest_ip:
            filters.append(f'dest_ip="{dest_ip}"')

        filter_str = " ".join(filters) if filters else ""
        spl = f'search index=network_traffic {filter_str} earliest={earliest_time} | stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port | sort -total_bytes'
        result = await self.search(spl, earliest_time=earliest_time)
        return result.get("results", [])

    async def run_custom_spl(self, spl: str) -> Dict[str, Any]:
        """Run any custom SPL query — used by investigation agent."""
        return await self.search(spl)

    async def close(self):
        if hasattr(self, 'client') and self.client:
            await self.client.aclose()


# Singleton instance
_client: Optional[SplunkMCPClient] = None


def get_mcp_client() -> SplunkMCPClient:
    global _client
    if _client is None:
        _client = SplunkMCPClient()
    return _client
