use std::time::Duration;

use crate::models::{DetectedTechnology, FingerprintResult};

struct TechDetector {
    name: &'static str,
    category: &'static str,
    check: fn(&ResponseInfo) -> bool,
}

#[allow(dead_code)]
struct ResponseInfo {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    url: String,
}

fn has_header(headers: &[(String, String)], name: &str, value_contains: &str) -> bool {
    let lower_name = name.to_lowercase();
    let lower_value = value_contains.to_lowercase();
    headers
        .iter()
        .any(|(k, v)| k.to_lowercase() == lower_name && v.to_lowercase().contains(&lower_value))
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let lower = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == lower)
        .map(|(_, v)| v.as_str())
}

fn body_contains(body: &str, pattern: &str) -> bool {
    body.to_lowercase().contains(&pattern.to_lowercase())
}

fn detect_wordpress(info: &ResponseInfo) -> bool {
    body_contains(&info.body, "/wp-content/")
        || body_contains(&info.body, "wp-json")
        || body_contains(&info.body, "wp-admin")
        || body_contains(&info.body, "<meta name=\"generator\" content=\"WordPress")
        || body_contains(&info.body, "<meta name='generator' content='WordPress")
        || has_header(&info.headers, "x-powered-by", "wordpress")
}

fn detect_drupal(info: &ResponseInfo) -> bool {
    body_contains(&info.body, "Drupal.settings")
        || body_contains(&info.body, "drupal.js")
        || body_contains(&info.body, "/sites/default/")
        || has_header(&info.headers, "x-drupal-cache", "")
        || has_header(&info.headers, "x-generator", "drupal")
}

fn detect_joomla(info: &ResponseInfo) -> bool {
    body_contains(&info.body, "/media/system/js/")
        || body_contains(&info.body, "Joomla!")
        || body_contains(&info.body, "joomla.jtext")
        || has_header(&info.headers, "x-generator", "Joomla")
        || body_contains(&info.body, "com_content")
}

fn detect_laravel(info: &ResponseInfo) -> bool {
    has_header(&info.headers, "x-powered-by", "Laravel")
        || has_header(&info.headers, "set-cookie", "laravel_session")
        || body_contains(&info.body, "csrf_token")
        || body_contains(&info.body, "laravel")
}

fn detect_django(info: &ResponseInfo) -> bool {
    body_contains(&info.body, "csrfmiddlewaretoken")
        || has_header(&info.headers, "x-frame-options", "DENY")
        || has_header(&info.headers, "set-cookie", "django_language")
        || has_header(&info.headers, "set-cookie", "csrftoken")
        || has_header(&info.headers, "x-content-type-options", "nosniff")
}

fn detect_flask(info: &ResponseInfo) -> bool {
    has_header(&info.headers, "set-cookie", "session=")
        && !has_header(&info.headers, "set-cookie", "laravel_session")
        && (body_contains(&info.body, "flask") || has_header(&info.headers, "x-flask", ""))
}

fn detect_express(info: &ResponseInfo) -> bool {
    has_header(&info.headers, "x-powered-by", "Express")
        || has_header(&info.headers, "set-cookie", "connect.sid")
}

fn detect_nextjs(info: &ResponseInfo) -> bool {
    body_contains(&info.body, "__NEXT_DATA__")
        || body_contains(&info.body, "/_next/static/")
        || has_header(&info.headers, "x-powered-by", "Next.js")
        || body_contains(&info.body, "next.js")
}

fn detect_react(info: &ResponseInfo) -> bool {
    body_contains(&info.body, "react")
        || body_contains(&info.body, "reactRoot")
        || body_contains(&info.body, "_reactListening")
        || body_contains(&info.body, "React.createElement")
}

fn detect_vue(info: &ResponseInfo) -> bool {
    body_contains(&info.body, "__vue__")
        || body_contains(&info.body, "data-v-")
        || body_contains(&info.body, "vue.js")
        || body_contains(&info.body, "vue.min.js")
}

fn detect_angular(info: &ResponseInfo) -> bool {
    body_contains(&info.body, "ng-version")
        || body_contains(&info.body, "ng-app")
        || body_contains(&info.body, "angular.js")
        || body_contains(&info.body, "angular.min.js")
}

fn detect_cloudflare(info: &ResponseInfo) -> bool {
    has_header(&info.headers, "cf-ray", "")
        || has_header(&info.headers, "cf-cache-status", "")
        || has_header(&info.headers, "server", "cloudflare")
        || has_header(&info.headers, "cf-chl-bypass", "")
}

fn detect_nginx(info: &ResponseInfo) -> bool {
    if let Some(val) = header_value(&info.headers, "server") {
        return val.to_lowercase().contains("nginx");
    }
    false
}

fn detect_apache(info: &ResponseInfo) -> bool {
    if let Some(val) = header_value(&info.headers, "server") {
        return val.to_lowercase().contains("apache");
    }
    false
}

fn detect_iis(info: &ResponseInfo) -> bool {
    if let Some(val) = header_value(&info.headers, "server") {
        return val.to_lowercase().contains("iis") || val.to_lowercase().contains("microsoft-iis");
    }
    false
}

static DETECTORS: &[TechDetector] = &[
    TechDetector {
        name: "WordPress",
        category: "cms",
        check: detect_wordpress,
    },
    TechDetector {
        name: "Drupal",
        category: "cms",
        check: detect_drupal,
    },
    TechDetector {
        name: "Joomla",
        category: "cms",
        check: detect_joomla,
    },
    TechDetector {
        name: "Laravel",
        category: "framework",
        check: detect_laravel,
    },
    TechDetector {
        name: "Django",
        category: "framework",
        check: detect_django,
    },
    TechDetector {
        name: "Flask",
        category: "framework",
        check: detect_flask,
    },
    TechDetector {
        name: "Express",
        category: "framework",
        check: detect_express,
    },
    TechDetector {
        name: "Next.js",
        category: "framework",
        check: detect_nextjs,
    },
    TechDetector {
        name: "React",
        category: "frontend",
        check: detect_react,
    },
    TechDetector {
        name: "Vue.js",
        category: "frontend",
        check: detect_vue,
    },
    TechDetector {
        name: "Angular",
        category: "frontend",
        check: detect_angular,
    },
    TechDetector {
        name: "Nginx",
        category: "webserver",
        check: detect_nginx,
    },
    TechDetector {
        name: "Apache",
        category: "webserver",
        check: detect_apache,
    },
    TechDetector {
        name: "IIS",
        category: "webserver",
        check: detect_iis,
    },
    TechDetector {
        name: "Cloudflare",
        category: "cdn",
        check: detect_cloudflare,
    },
];

fn fetch_info(url: &str) -> Result<ResponseInfo, String> {
    let timeout = Duration::from_secs(10);
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("http client build failed: {}", e))?;

    let resp = client
        .get(url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 GhostMirror/0.1",
        )
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp
        .text()
        .map_err(|e| format!("body read failed: {}", e))?;

    Ok(ResponseInfo {
        status,
        headers,
        body,
        url: url.to_string(),
    })
}

pub fn fingerprint(url: &str) -> Result<FingerprintResult, String> {
    let info = fetch_info(url)?;
    let mut detected = Vec::new();
    let mut cloudflare = false;
    let mut cms = String::new();

    for detector in DETECTORS {
        if (detector.check)(&info) {
            let confidence: u8 = match detector.name {
                "WordPress" | "Drupal" | "Joomla" => 85,
                "Laravel" | "Django" => 80,
                "Nginx" | "Apache" | "IIS" => 90,
                "Cloudflare" => 95,
                "Express" | "Flask" => 75,
                "Next.js" => 70,
                "React" | "Vue.js" | "Angular" => 65,
                _ => 70,
            };
            detected.push(DetectedTechnology {
                name: detector.name.to_string(),
                category: detector.category.to_string(),
                confidence,
            });

            if detector.name == "Cloudflare" {
                cloudflare = true;
            }
            if detector.category == "cms" && cms.is_empty() {
                cms = detector.name.to_string();
            }
        }
    }

    // Detect generic CMS if specific not found
    if cms.is_empty() && detected.iter().any(|t| t.category == "framework") {
        // framework detected but no cms
    }

    Ok(FingerprintResult {
        target: url.to_string(),
        technologies: detected,
        cloudflare,
        waf: if cloudflare {
            "Cloudflare".into()
        } else {
            String::new()
        },
        cms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(body: &str, headers: &[(&str, &str)]) -> ResponseInfo {
        ResponseInfo {
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
            url: "http://example.com".to_string(),
        }
    }

    #[test]
    fn test_detect_wordpress() {
        let info = make_info("<meta name=\"generator\" content=\"WordPress 6.0\" />", &[]);
        assert!(detect_wordpress(&info));
    }

    #[test]
    fn test_detect_wordpress_wp_content() {
        let info = make_info("<link href='/wp-content/themes/twenty/style.css'", &[]);
        assert!(detect_wordpress(&info));
    }

    #[test]
    fn test_detect_drupal() {
        let info = make_info("Drupal.settings = {}", &[]);
        assert!(detect_drupal(&info));
    }

    #[test]
    fn test_detect_joomla() {
        let info = make_info("Joomla! jtext", &[]);
        assert!(detect_joomla(&info));
    }

    #[test]
    fn test_detect_laravel() {
        let info = make_info("csrf_token", &[("X-Powered-By", "Laravel")]);
        assert!(detect_laravel(&info));
    }

    #[test]
    fn test_detect_django() {
        let info = make_info("csrfmiddlewaretoken", &[]);
        assert!(detect_django(&info));
    }

    #[test]
    fn test_detect_express() {
        let info = make_info("", &[("X-Powered-By", "Express")]);
        assert!(detect_express(&info));
    }

    #[test]
    fn test_detect_nextjs() {
        let info = make_info("__NEXT_DATA__ = {}", &[]);
        assert!(detect_nextjs(&info));
    }

    #[test]
    fn test_detect_cloudflare() {
        let info = make_info("", &[("cf-ray", "abc123")]);
        assert!(detect_cloudflare(&info));
    }

    #[test]
    fn test_detect_react() {
        let info = make_info("React.createElement", &[]);
        assert!(detect_react(&info));
    }

    #[test]
    fn test_detect_vue() {
        let info = make_info("data-v-abc123", &[]);
        assert!(detect_vue(&info));
    }

    #[test]
    fn test_detect_angular() {
        let info = make_info("ng-version=\"15.0.0\"", &[]);
        assert!(detect_angular(&info));
    }

    #[test]
    fn test_detect_nginx() {
        let info = make_info("", &[("Server", "nginx/1.24.0")]);
        assert!(detect_nginx(&info));
    }

    #[test]
    fn test_detect_apache() {
        let info = make_info("", &[("Server", "Apache/2.4.57")]);
        assert!(detect_apache(&info));
    }

    #[test]
    fn test_no_false_positive() {
        let info = make_info("<html><body>Hello</body></html>", &[]);
        assert!(!detect_wordpress(&info));
        assert!(!detect_drupal(&info));
        assert!(!detect_joomla(&info));
        assert!(!detect_laravel(&info));
        assert!(!detect_cloudflare(&info));
    }
}
