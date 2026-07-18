// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::SystemTime;

use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;
use toml::Table;

use crate::logging;

static BLOCKED_SUBNETS: OnceLock<Vec<IpNet>> = OnceLock::new();

fn parse_blocked_subnets(config: &Table) -> Result<Vec<IpNet>, String> {
    let Some(value) = config.get("block_subnets") else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| "block_subnets must be an array of CIDR strings".to_string())?;

    entries
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let subnet = value
                .as_str()
                .ok_or_else(|| format!("block_subnets[{index}] must be a CIDR string"))?;
            subnet
                .parse::<IpNet>()
                .map_err(|error| format!("invalid subnet {subnet:?}: {error}"))
        })
        .collect()
}

pub fn init() -> Result<(), String> {
    let config: Table = toml::from_str(&crate::get_config_content())
        .map_err(|error| format!("failed to parse config: {error}"))?;
    let subnets = parse_blocked_subnets(&config)?;
    BLOCKED_SUBNETS
        .set(subnets)
        .map_err(|_| "blocked subnets were already initialized".to_string())
}

fn matching_subnet(ip: IpAddr) -> Option<IpNet> {
    BLOCKED_SUBNETS
        .get()
        .and_then(|subnets| subnets.iter().copied().find(|subnet| subnet.contains(&ip)))
}

pub async fn block_middleware(req: Request, next: Next) -> Response {
    let fallback = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let client_ip = crate::client_ip_from_headers(req.headers(), fallback);
    let parsed_ip = client_ip
        .parse::<IpAddr>()
        .unwrap_or_else(|_| fallback.ip());

    if let Some(subnet) = matching_subnet(parsed_ip) {
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        eprintln!(
            "ts={} level=warn event=subnet_ban ip={} subnet={} method={} target={} ua={}",
            logging::format_log_timestamp(SystemTime::now()),
            logging::logfmt_string(&parsed_ip.to_string()),
            logging::logfmt_string(&subnet.to_string()),
            req.method().as_str(),
            logging::logfmt_string(&req.uri().to_string()),
            logging::logfmt_string(user_agent),
        );
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ipnet::IpNet;
    use toml::Table;

    use super::parse_blocked_subnets;

    fn parse_config(input: &str) -> Table {
        toml::from_str(input).expect("test config should parse")
    }

    fn matches(subnets: &[IpNet], ip: &str) -> bool {
        let ip: IpAddr = ip.parse().expect("test IP should parse");
        subnets.iter().any(|subnet| subnet.contains(&ip))
    }

    #[test]
    fn absent_setting_allows_everything() {
        let subnets = parse_blocked_subnets(&parse_config("driver = \"local\""))
            .expect("absent setting should be valid");
        assert!(subnets.is_empty());
    }

    #[test]
    fn parses_multiple_ipv4_and_ipv6_subnets() {
        let config =
            parse_config(r#"block_subnets = ["192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"]"#);
        let subnets = parse_blocked_subnets(&config).expect("subnets should parse");

        assert!(matches(&subnets, "192.0.2.10"));
        assert!(matches(&subnets, "198.51.100.20"));
        assert!(matches(&subnets, "2001:db8::1234"));
        assert!(!matches(&subnets, "203.0.113.1"));
        assert!(!matches(&subnets, "2001:db9::1"));
    }

    #[test]
    fn supports_single_address_prefixes() {
        let config = parse_config(r#"block_subnets = ["192.0.2.10/32", "2001:db8::10/128"]"#);
        let subnets = parse_blocked_subnets(&config).expect("subnets should parse");

        assert!(matches(&subnets, "192.0.2.10"));
        assert!(!matches(&subnets, "192.0.2.11"));
        assert!(matches(&subnets, "2001:db8::10"));
        assert!(!matches(&subnets, "2001:db8::11"));
    }

    #[test]
    fn rejects_invalid_subnets() {
        let config = parse_config(r#"block_subnets = ["192.0.2.0/99"]"#);
        let error = parse_blocked_subnets(&config).expect_err("invalid CIDR should fail");
        assert!(error.contains("192.0.2.0/99"));
    }

    #[test]
    fn rejects_non_array_setting() {
        let config = parse_config(r#"block_subnets = "192.0.2.0/24""#);
        let error = parse_blocked_subnets(&config).expect_err("string setting should fail");
        assert!(error.contains("array"));
    }
}
