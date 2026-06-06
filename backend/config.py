"""SentinelFlow Backend Configuration."""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Splunk
    splunk_host: str = "localhost"
    splunk_port: int = 8089
    splunk_username: str = "admin"
    splunk_password: str = "changeme"
    splunk_scheme: str = "https"

    # Splunk MCP Server
    splunk_mcp_url: str = "http://localhost:8088"
    splunk_mcp_token: str = ""

    # Splunk HEC
    splunk_hec_url: str = "http://localhost:8088"
    splunk_hec_token: str = ""

    # LLM
    anthropic_api_key: str = ""
    llm_model: str = "claude-sonnet-4-6"

    # Splunk Hosted Models (optional — graceful fallback)
    foundation_sec_endpoint: str = ""
    cisco_dtsm_endpoint: str = ""

    # App
    backend_port: int = 8000

    class Config:
        env_file = "../.env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
