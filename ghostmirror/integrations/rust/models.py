from pydantic import BaseModel, Field


class RustOpenPort(BaseModel):
    port: int = Field(..., description="Open port number")
    state: str = Field(default="open", description="Port state")


class RustPortResult(BaseModel):
    target: str = Field(..., description="Scanned target host")
    open_ports: list[RustOpenPort] = Field(
        default_factory=list, description="List of open ports"
    )
    duration_ms: int = Field(0, description="Scan duration in milliseconds")


class RustBannerResult(BaseModel):
    host: str = Field(..., description="Target host")
    port: int = Field(0, description="Target port")
    server: str = Field("", description="HTTP Server header")
    powered_by: str = Field("", description="X-Powered-By header")
    via: str = Field("", description="Via header")
    technologies: list[str] = Field(
        default_factory=list, description="Detected technologies from banners"
    )


class RustDetectedTechnology(BaseModel):
    name: str = Field(..., description="Technology name")
    category: str = Field(..., description="Technology category")
    confidence: int = Field(..., description="Detection confidence (0-100)")


class RustFingerprintResult(BaseModel):
    target: str = Field(..., description="Scanned URL")
    technologies: list[RustDetectedTechnology] = Field(
        default_factory=list, description="Detected technologies"
    )
    cloudflare: bool = Field(False, description="Cloudflare detected")
    waf: str = Field("", description="WAF identified")
    cms: str = Field("", description="CMS identified")
