"""Model representing parsed port scanning findings."""

from pydantic import BaseModel, Field


class PortFinding(BaseModel):
    """Structured details of an open/closed/filtered port discovered during scanning."""

    port: int = Field(..., description="Target port number")
    protocol: str = Field(..., description="Transport layer protocol (e.g. tcp, udp)")
    service: str = Field(..., description="Discovered service name (e.g. ssh, http, unknown)")
    product: str = Field(..., description="Software product name running on the port if detected")
    version: str = Field(..., description="Software version details if detected")
    state: str = Field(..., description="Network state of the port (e.g. open, closed, filtered)")
