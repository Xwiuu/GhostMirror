use ghostmirror_rs::models::{DetectedTechnology, FingerprintResult};

#[test]
fn test_fingerprint_result_serialization() {
    let result = FingerprintResult {
        target: "http://example.com".into(),
        technologies: vec![DetectedTechnology {
            name: "Nginx".into(),
            category: "webserver".into(),
            confidence: 90,
        }],
        cloudflare: false,
        waf: String::new(),
        cms: String::new(),
    };

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("example.com"));
    assert!(json.contains("Nginx"));
    assert!(json.contains("webserver"));
    assert!(json.contains("90"));
}

#[test]
fn test_fingerprint_result_empty_techs() {
    let result = FingerprintResult {
        target: "http://test.local".into(),
        technologies: vec![],
        cloudflare: false,
        waf: String::new(),
        cms: String::new(),
    };

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"technologies\":[]"));
}
