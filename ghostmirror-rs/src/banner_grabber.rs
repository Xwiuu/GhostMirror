use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::models::BannerResult;

fn tcp_banner(host: &str, port: u16, timeout: Duration) -> Result<String, String> {
    let addr_str = format!("{}:{}", host, port);
    let addr = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .next()
        .ok_or_else(|| "no address resolved".to_string())?;

    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect failed: {}", e))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("set timeout failed: {}", e))?;

    let mut buf = [0u8; 1024];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("read failed: {}", e))?;

    if n == 0 {
        // Try sending a probe
        stream
            .write_all(b"\r\n")
            .map_err(|e| format!("write probe failed: {}", e))?;
        let n = stream
            .read(&mut buf)
            .map_err(|e| format!("read after probe failed: {}", e))?;
        if n == 0 {
            return Err("no banner received".to_string());
        }
    }

    let banner = String::from_utf8_lossy(&buf[..n]).to_string();
    Ok(banner)
}

fn extract_http_banner_info(banner: &str) -> (String, String, String, Vec<String>) {
    let mut server = String::new();
    let mut powered_by = String::new();
    let mut via = String::new();
    let mut technologies = Vec::new();

    for line in banner.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") {
            server = line[7..].trim().to_string();
            if !server.is_empty() {
                technologies.push(server.clone());
            }
        } else if lower.starts_with("x-powered-by:") {
            powered_by = line[13..].trim().to_string();
            if !powered_by.is_empty() {
                technologies.push(powered_by.clone());
            }
        } else if lower.starts_with("via:") {
            via = line[4..].trim().to_string();
        } else if lower.starts_with("x-generator:") {
            let val = line[12..].trim().to_string();
            if !val.is_empty() {
                technologies.push(val);
            }
        }
    }

    (server, powered_by, via, technologies)
}

pub fn grab(host: &str, port: u16, tls: bool) -> Result<BannerResult, String> {
    let timeout = Duration::from_secs(5);

    if tls {
        return http_banner_tls(host, port, timeout);
    }

    if port == 80 || port == 8080 {
        return http_banner_plain(host, port, timeout);
    }

    let banner = tcp_banner(host, port, timeout)?;

    let (server, powered_by, via, technologies) = extract_http_banner_info(&banner);
    if server.is_empty() && powered_by.is_empty() && banner.contains("HTTP/") {
        // Try HTTP request
        return http_banner_plain(host, port, timeout);
    }

    Ok(BannerResult {
        host: host.to_string(),
        port,
        server,
        powered_by,
        via,
        technologies,
    })
}

fn http_banner_plain(host: &str, port: u16, timeout: Duration) -> Result<BannerResult, String> {
    let addr_str = format!("{}:{}", host, port);
    let addr = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .next()
        .ok_or_else(|| "no address resolved".to_string())?;

    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect failed: {}", e))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("set timeout failed: {}", e))?;

    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: GhostMirror/0.1\r\n\r\n",
        host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write request failed: {}", e))?;

    let mut buf = [0u8; 4096];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("read response failed: {}", e))?;

    let response = String::from_utf8_lossy(&buf[..n]).to_string();
    let (server, powered_by, via, technologies) = extract_http_banner_info(&response);

    Ok(BannerResult {
        host: host.to_string(),
        port,
        server,
        powered_by,
        via,
        technologies,
    })
}

fn http_banner_tls(host: &str, port: u16, timeout: Duration) -> Result<BannerResult, String> {
    let url = format!("https://{}:{}", host, port);
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("http client build failed: {}", e))?;

    let resp = client
        .head(&url)
        .header("User-Agent", "GhostMirror/0.1")
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let mut server = String::new();
    let mut powered_by = String::new();
    let mut via = String::new();
    let mut technologies = Vec::new();

    if let Some(val) = resp.headers().get("server") {
        server = val.to_str().unwrap_or("").to_string();
        if !server.is_empty() {
            technologies.push(server.clone());
        }
    }
    if let Some(val) = resp.headers().get("x-powered-by") {
        powered_by = val.to_str().unwrap_or("").to_string();
        if !powered_by.is_empty() {
            technologies.push(powered_by.clone());
        }
    }
    if let Some(val) = resp.headers().get("via") {
        via = val.to_str().unwrap_or("").to_string();
    }

    Ok(BannerResult {
        host: host.to_string(),
        port,
        server,
        powered_by,
        via,
        technologies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_http_banner_info() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Powered-By: PHP/8.2\r\nVia: 1.1 varnish\r\n\r\n";
        let (server, powered_by, via, techs) = extract_http_banner_info(&banner);
        assert_eq!(server, "nginx/1.24.0");
        assert_eq!(powered_by, "PHP/8.2");
        assert_eq!(via, "1.1 varnish");
        assert!(techs.contains(&"nginx/1.24.0".to_string()));
        assert!(techs.contains(&"PHP/8.2".to_string()));
    }

    #[test]
    fn test_extract_http_banner_info_empty() {
        let banner = "HTTP/1.1 200 OK\r\n\r\n";
        let (server, powered_by, via, techs) = extract_http_banner_info(&banner);
        assert_eq!(server, "");
        assert_eq!(powered_by, "");
        assert_eq!(via, "");
        assert!(techs.is_empty());
    }
}
