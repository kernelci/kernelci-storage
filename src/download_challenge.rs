// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use toml::Table;

use crate::logging;

const SECURE_COOKIE_NAME: &str = "__Host-kci-download";
const DEVELOPMENT_COOKIE_NAME: &str = "kci-download";
const TOKEN_ENDPOINT: &str = "/v1/download-challenge";
const DEFAULT_TTL_SECONDS: u64 = 600;
const DEFAULT_IPV4_PREFIX: u8 = 24;
const DEFAULT_IPV6_PREFIX: u8 = 64;

#[derive(Debug)]
struct ChallengeConfig {
    user_agents: Vec<String>,
    secret: String,
    cookie_ttl_seconds: u64,
    ipv4_prefix_length: u8,
    ipv6_prefix_length: u8,
    fallback_bytes_per_second: Option<u64>,
    secure_cookie: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChallengeClaims {
    exp: u64,
    network: String,
}

static CONFIG: OnceLock<Option<ChallengeConfig>> = OnceLock::new();

fn parse_config(config: &Table) -> Result<Option<ChallengeConfig>, String> {
    let Some(section) = config.get("download_challenge") else {
        return Ok(None);
    };
    let section = section
        .as_table()
        .ok_or_else(|| "download_challenge must be a TOML table".to_string())?;

    let user_agents = section
        .get("user_agents")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "download_challenge.user_agents must be an array of strings".to_string())?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
                .ok_or_else(|| {
                    format!("download_challenge.user_agents[{index}] must be a non-empty string")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if user_agents.is_empty() {
        return Ok(None);
    }

    let secret = section
        .get("secret")
        .and_then(|value| value.as_str())
        .filter(|secret| secret.len() >= 32)
        .ok_or_else(|| "download_challenge.secret must contain at least 32 characters".to_string())?
        .to_string();
    let cookie_ttl_seconds =
        integer_setting(section, "cookie_ttl_seconds")?.unwrap_or(DEFAULT_TTL_SECONDS);
    if !(30..=86_400).contains(&cookie_ttl_seconds) {
        return Err("download_challenge.cookie_ttl_seconds must be between 30 and 86400".into());
    }

    let ipv4_prefix_length =
        integer_setting(section, "ipv4_prefix_length")?.unwrap_or(DEFAULT_IPV4_PREFIX.into());
    let ipv4_prefix_length = u8::try_from(ipv4_prefix_length)
        .map_err(|_| "download_challenge.ipv4_prefix_length must be between 0 and 32")?;
    if ipv4_prefix_length > 32 {
        return Err("download_challenge.ipv4_prefix_length must be between 0 and 32".into());
    }

    let ipv6_prefix_length =
        integer_setting(section, "ipv6_prefix_length")?.unwrap_or(DEFAULT_IPV6_PREFIX.into());
    let ipv6_prefix_length = u8::try_from(ipv6_prefix_length)
        .map_err(|_| "download_challenge.ipv6_prefix_length must be between 0 and 128")?;
    if ipv6_prefix_length > 128 {
        return Err("download_challenge.ipv6_prefix_length must be between 0 and 128".into());
    }

    let fallback_bytes_per_second = integer_setting(section, "fallback_bytes_per_second")?;
    let fallback_bytes_per_second = match fallback_bytes_per_second {
        Some(0) | None => None,
        Some(value) => Some(value),
    };
    let secure_cookie = section
        .get("secure_cookie")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);

    Ok(Some(ChallengeConfig {
        user_agents,
        secret,
        cookie_ttl_seconds,
        ipv4_prefix_length,
        ipv6_prefix_length,
        fallback_bytes_per_second,
        secure_cookie,
    }))
}

fn integer_setting(section: &Table, name: &str) -> Result<Option<u64>, String> {
    let Some(value) = section.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_integer()
        .ok_or_else(|| format!("download_challenge.{name} must be a non-negative integer"))?;
    u64::try_from(value)
        .map(Some)
        .map_err(|_| format!("download_challenge.{name} must be a non-negative integer"))
}

pub fn init() -> Result<(), String> {
    let config: Table = toml::from_str(&crate::get_config_content())
        .map_err(|error| format!("failed to parse config: {error}"))?;
    CONFIG
        .set(parse_config(&config)?)
        .map_err(|_| "download challenge was already initialized".to_string())
}

fn config() -> Option<&'static ChallengeConfig> {
    CONFIG.get().and_then(Option::as_ref)
}

fn cookie_name(config: &ChallengeConfig) -> &'static str {
    if config.secure_cookie {
        SECURE_COOKIE_NAME
    } else {
        DEVELOPMENT_COOKIE_NAME
    }
}

fn matches_user_agent(config: &ChallengeConfig, user_agent: &str) -> bool {
    let user_agent = user_agent.to_ascii_lowercase();
    config
        .user_agents
        .iter()
        .any(|pattern| user_agent.contains(pattern))
}

fn client_network(config: &ChallengeConfig, ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(ip) => IpNet::V4(
            Ipv4Net::new(ip, config.ipv4_prefix_length)
                .expect("validated IPv4 prefix length")
                .trunc(),
        ),
        IpAddr::V6(ip) => IpNet::V6(
            Ipv6Net::new(ip, config.ipv6_prefix_length)
                .expect("validated IPv6 prefix length")
                .trunc(),
        ),
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn create_token(
    config: &ChallengeConfig,
    ip: IpAddr,
    now: u64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = ChallengeClaims {
        exp: now.saturating_add(config.cookie_ttl_seconds),
        network: client_network(config, ip).to_string(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.secret.as_bytes()),
    )
}

fn verify_token(config: &ChallengeConfig, token: &str, ip: IpAddr) -> bool {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    let Ok(token) = decode::<ChallengeClaims>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation,
    ) else {
        return false;
    };
    token.claims.network == client_network(config, ip).to_string()
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(cookie_name, value)| (cookie_name == name).then_some(value))
}

fn wants_fallback(uri: &Uri) -> bool {
    uri.query().is_some_and(|query| {
        query
            .split('&')
            .any(|parameter| parameter == "challenge_fallback=1")
    })
}

fn client_ip(headers: &HeaderMap, fallback: SocketAddr) -> IpAddr {
    crate::client_ip_from_headers(headers, fallback)
        .parse()
        .unwrap_or_else(|_| fallback.ip())
}

pub fn authorize_request(
    headers: &HeaderMap,
    fallback: SocketAddr,
    uri: &Uri,
) -> Result<Option<u64>, Response> {
    let Some(config) = config() else {
        return Ok(None);
    };
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !matches_user_agent(config, user_agent) {
        return Ok(None);
    }

    let ip = client_ip(headers, fallback);
    if cookie_value(headers, cookie_name(config))
        .is_some_and(|token| verify_token(config, token, ip))
    {
        return Ok(None);
    }
    if wants_fallback(uri) {
        if let Some(rate) = config.fallback_bytes_per_second {
            return Ok(Some(rate));
        }
    }

    eprintln!(
        "ts={} level=info event=download_challenge ip={} target={} ua={}",
        logging::format_log_timestamp(SystemTime::now()),
        logging::logfmt_string(&ip.to_string()),
        logging::logfmt_string(&uri.to_string()),
        logging::logfmt_string(user_agent),
    );
    Err(challenge_page(config.fallback_bytes_per_second.is_some()))
}

pub async fn issue_cookie(
    ConnectInfo(fallback): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(config) = config() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !matches_user_agent(config, user_agent) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let ip = client_ip(&headers, fallback);
    let token = match create_token(config, ip, now_seconds()) {
        Ok(token) => token,
        Err(error) => {
            eprintln!(
                "ts={} level=error event=download_challenge_token_error error={}",
                logging::format_log_timestamp(SystemTime::now()),
                logging::logfmt_string(&error.to_string()),
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let secure = if config.secure_cookie { "; Secure" } else { "" };
    let cookie_name = cookie_name(config);
    let cookie = format!(
        "{cookie_name}={token}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{secure}",
        config.cookie_ttl_seconds
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("JWT cookie must be a valid header value"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    response
}

fn challenge_page(has_fallback: bool) -> Response {
    let fallback = if has_fallback {
        r#"<a id="fallback" href="?challenge_fallback=1">Download without JavaScript</a>"#
    } else {
        ""
    };
    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Preparing download</title>
<style>
:root{{color-scheme:light dark}}body{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px system-ui,sans-serif;background:#f4f6f8;color:#17202a}}main{{width:min(30rem,calc(100% - 3rem));padding:2rem;border-radius:1rem;background:white;box-shadow:0 1rem 3rem #0002;text-align:center}}.spinner{{width:2.5rem;height:2.5rem;margin:0 auto 1.25rem;border:.3rem solid #d8dee4;border-top-color:#2563eb;border-radius:50%;animation:spin .8s linear infinite}}a{{display:block;margin-top:1.5rem;color:#2563eb}}@keyframes spin{{to{{transform:rotate(360deg)}}}}@media(prefers-color-scheme:dark){{body{{background:#111827;color:#e5e7eb}}main{{background:#1f2937}}}}
</style>
</head>
<body><main><div class="spinner" aria-hidden="true"></div><h1>Please wait</h1><p id="status">Your download is being prepared&hellip;</p>{fallback}</main>
<script>
fetch('{TOKEN_ENDPOINT}',{{method:'POST',credentials:'same-origin'}}).then(function(response){{if(!response.ok)throw new Error();window.location.reload();}}).catch(function(){{document.getElementById('status').textContent='The download could not be prepared. Please try again.';}});
</script></body></html>"#
    );
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
        ),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use axum::http::{HeaderMap, HeaderValue, Uri};
    use toml::Table;

    use super::{
        cookie_value, create_token, matches_user_agent, parse_config, verify_token, wants_fallback,
        ChallengeConfig,
    };

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn config() -> ChallengeConfig {
        ChallengeConfig {
            user_agents: vec!["android".into()],
            secret: SECRET.into(),
            cookie_ttl_seconds: 600,
            ipv4_prefix_length: 24,
            ipv6_prefix_length: 64,
            fallback_bytes_per_second: Some(262_144),
            secure_cookie: true,
        }
    }

    #[test]
    fn absent_section_disables_feature() {
        let table: Table = toml::from_str("driver = \"local\"").unwrap();
        assert!(parse_config(&table).unwrap().is_none());
    }

    #[test]
    fn empty_user_agent_list_disables_feature() {
        let table: Table = toml::from_str(
            r#"[download_challenge]
user_agents = []"#,
        )
        .unwrap();
        assert!(parse_config(&table).unwrap().is_none());
    }

    #[test]
    fn validates_required_secret_and_prefixes() {
        let missing_secret: Table = toml::from_str(
            r#"[download_challenge]
user_agents = ["android"]"#,
        )
        .unwrap();
        assert!(parse_config(&missing_secret)
            .unwrap_err()
            .contains("secret"));

        let invalid_prefix: Table = toml::from_str(&format!(
            r#"[download_challenge]
user_agents = ["android"]
secret = "{SECRET}"
ipv4_prefix_length = 33"#
        ))
        .unwrap();
        assert!(parse_config(&invalid_prefix).unwrap_err().contains("ipv4"));
    }

    #[test]
    fn user_agent_matching_is_case_insensitive() {
        assert!(matches_user_agent(
            &config(),
            "Mozilla/5.0 (Linux; ANDROID 14)"
        ));
        assert!(!matches_user_agent(&config(), "python-requests/2.32"));
    }

    #[test]
    fn token_is_valid_only_inside_its_subnet() {
        let config = config();
        let first: IpAddr = "192.0.2.10".parse().unwrap();
        let same_subnet: IpAddr = "192.0.2.200".parse().unwrap();
        let other_subnet: IpAddr = "198.51.100.10".parse().unwrap();
        let token = create_token(&config, first, super::now_seconds()).unwrap();

        assert!(verify_token(&config, &token, same_subnet));
        assert!(!verify_token(&config, &token, other_subnet));
    }

    #[test]
    fn parses_cookie_and_fallback_query() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("first=one; __Host-kci-download=token-value; last=three"),
        );
        assert_eq!(
            cookie_value(&headers, "__Host-kci-download"),
            Some("token-value")
        );
        assert!(wants_fallback(
            &"/artifact?challenge_fallback=1".parse::<Uri>().unwrap()
        ));
        assert!(!wants_fallback(
            &"/artifact?challenge_fallback=0".parse::<Uri>().unwrap()
        ));
    }
}
