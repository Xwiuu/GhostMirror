use ghostmirror_rs::models::{BannerResult, OpenPort, PortResult};

#[test]
fn test_port_result_serialization() {
    let result = PortResult {
        target: "example.com".into(),
        open_ports: vec![
            OpenPort {
                port: 80,
                state: "open".into(),
            },
            OpenPort {
                port: 443,
                state: "open".into(),
            },
        ],
        duration_ms: 1234,
    };

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("example.com"));
    assert!(json.contains("\"port\":80"));
    assert!(json.contains("\"port\":443"));
    assert!(json.contains("\"state\":\"open\""));
    assert!(json.contains("\"duration_ms\":1234"));
}

#[test]
fn test_port_result_empty_ports() {
    let result = PortResult {
        target: "test.local".into(),
        open_ports: vec![],
        duration_ms: 500,
    };

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"open_ports\":[]"));
}

#[test]
fn test_banner_result_serialization() {
    let result = BannerResult {
        host: "example.com".into(),
        port: 80,
        server: "nginx/1.24.0".into(),
        powered_by: "PHP/8.2".into(),
        via: "1.1 varnish".into(),
        technologies: vec!["nginx/1.24.0".into(), "PHP/8.2".into()],
    };

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("example.com"));
    assert!(json.contains("nginx"));
    assert!(json.contains("PHP/8.2"));
    assert!(json.contains("varnish"));
}

#[test]
fn test_banner_result_empty_fields() {
    let result = BannerResult {
        host: "test.local".into(),
        port: 443,
        server: String::new(),
        powered_by: String::new(),
        via: String::new(),
        technologies: vec![],
    };

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"server\":\"\""));
    assert!(json.contains("\"technologies\":[]"));
}
