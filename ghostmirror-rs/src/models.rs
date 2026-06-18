use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PortResult {
    pub target: String,
    pub open_ports: Vec<OpenPort>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenPort {
    pub port: u16,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct BannerResult {
    pub host: String,
    pub port: u16,
    pub server: String,
    pub powered_by: String,
    pub via: String,
    pub technologies: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FingerprintResult {
    pub target: String,
    pub technologies: Vec<DetectedTechnology>,
    pub cloudflare: bool,
    pub waf: String,
    pub cms: String,
}

#[derive(Debug, Serialize)]
pub struct DetectedTechnology {
    pub name: String,
    pub category: String,
    pub confidence: u8,
}
