use ghostmirror_rs::port_scanner;

#[test]
fn test_scan_empty_ports() {
    let result = port_scanner::scan("127.0.0.1", "", 1);
    assert!(result.is_err());
}

#[test]
fn test_scan_invalid_host() {
    let result = port_scanner::scan("nonexistent.invalid", "80", 1);
    // Should not panic — will just have 0 open ports or error
    if let Ok(res) = result {
        assert!(res.open_ports.is_empty());
    }
}

#[test]
fn test_scan_loopback_closed() {
    // 127.0.0.1:9999 should be closed
    let result = port_scanner::scan("127.0.0.1", "9999", 1).unwrap();
    assert!(result.open_ports.is_empty());
}

#[test]
fn test_scan_range_no_open() {
    let result = port_scanner::scan("127.0.0.1", "65000-65005", 1).unwrap();
    assert!(result.open_ports.is_empty());
}
