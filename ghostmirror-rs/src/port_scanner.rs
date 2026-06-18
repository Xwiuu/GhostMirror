use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::models::{OpenPort, PortResult};

fn parse_ports(raw: &str) -> Result<Vec<u16>, String> {
    let mut ports: Vec<u16> = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start_str, end_str)) = part.split_once('-') {
            let start: u16 = start_str
                .trim()
                .parse()
                .map_err(|_| format!("invalid port range start: '{}'", start_str))?;
            let end: u16 = end_str
                .trim()
                .parse()
                .map_err(|_| format!("invalid port range end: '{}'", end_str))?;
            if start > end {
                return Err(format!("invalid range: {}-{} (start > end)", start, end));
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| format!("invalid port: '{}'", part))?;
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn try_connect(host: &str, port: u16, timeout: Duration) -> bool {
    let addr_str = format!("{}:{}", host, port);
    if let Ok(mut addrs) = addr_str.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return TcpStream::connect_timeout(&addr, timeout).is_ok();
        }
    }
    false
}

pub fn scan(host: &str, ports_raw: &str, timeout_secs: u64) -> Result<PortResult, String> {
    let ports = parse_ports(ports_raw)?;
    if ports.is_empty() {
        return Err("no valid ports specified".into());
    }

    let timeout = Duration::from_secs(timeout_secs);
    let start = Instant::now();
    let open = Arc::new(std::sync::Mutex::new(Vec::new()));

    let host_owned = host.to_string();
    let handles: Vec<_> = ports
        .chunks(50)
        .map(|chunk| {
            let host_clone = host_owned.clone();
            let chunk = chunk.to_vec();
            let open_clone = Arc::clone(&open);
            std::thread::spawn(move || {
                for port in chunk {
                    if try_connect(&host_clone, port, timeout) {
                        let mut opened = open_clone.lock().unwrap();
                        opened.push(OpenPort {
                            port,
                            state: "open".into(),
                        });
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().map_err(|_| "thread join failed".to_string())?;
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let mut open_ports = open.lock().unwrap().clone();
    open_ports.sort_by_key(|p| p.port);

    Ok(PortResult {
        target: host.to_string(),
        open_ports,
        duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port() {
        let ports = parse_ports("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_list() {
        let ports = parse_ports("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_range() {
        let ports = parse_ports("1-5").unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_mixed() {
        let ports = parse_ports("80,443,8080-8090").unwrap();
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&8080));
        assert!(ports.contains(&8090));
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("80-70").is_err());
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_ports("").unwrap().is_empty());
    }

    #[test]
    fn test_parse_dedup() {
        let ports = parse_ports("80,80,80").unwrap();
        assert_eq!(ports, vec![80]);
    }
}
