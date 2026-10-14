use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use headers::HeaderMap;
use ipnet::IpNet;

static PROXY_HEADER: OnceLock<String> = OnceLock::new();
static TRUSTED_PROXIES: OnceLock<Vec<IpNet>> = OnceLock::new();

pub fn init() -> Result<(), String> {
    let proxies = match crate::get_config_table().get("trusted_proxies") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .ok_or("trusted_proxies must be an array of CIDR strings")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| "trusted_proxies must contain strings".to_string())?
                    .parse::<IpNet>()
                    .map_err(|e| format!("invalid trusted proxy: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let header = match crate::get_config_table().get("trusted_proxy_header") {
        None => "x-forwarded-for",
        Some(value) => value
            .as_str()
            .ok_or("trusted_proxy_header must be a string")?,
    }
    .to_ascii_lowercase();
    if header != "x-forwarded-for" && header != "forwarded" {
        return Err("trusted_proxy_header must be x-forwarded-for or forwarded".to_string());
    }
    PROXY_HEADER
        .set(header)
        .map_err(|_| "proxy header already initialized".to_string())?;
    TRUSTED_PROXIES
        .set(proxies)
        .map_err(|_| "trusted proxies already initialized".to_string())
}

pub fn resolve(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    resolve_with_proxies(
        headers,
        peer.ip(),
        TRUSTED_PROXIES.get().map(Vec::as_slice).unwrap_or(&[]),
        PROXY_HEADER
            .get()
            .map(String::as_str)
            .unwrap_or("x-forwarded-for"),
    )
}

fn parse_address(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    value
        .parse()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .or_else(|| value.strip_prefix('[')?.strip_suffix(']')?.parse().ok())
}

// Split from the trusted end so malformed earlier client input cannot consume
// a proxy's appended entry. Delimiters inside quoted values are literal bytes.
fn split_quoted(bytes: &[u8], delimiter: u8) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut end = bytes.len();
    let mut quoted = false;
    for index in (0..bytes.len()).rev() {
        if bytes[index] == b'"' {
            let escapes = bytes[..index]
                .iter()
                .rev()
                .take_while(|byte| **byte == b'\\')
                .count();
            if escapes % 2 == 0 {
                quoted = !quoted;
            }
        } else if bytes[index] == delimiter && !quoted {
            parts.push(&bytes[index + 1..end]);
            end = index;
        }
    }
    parts.push(&bytes[..end]);
    parts.reverse();
    parts
}

fn resolve_with_proxies(
    headers: &HeaderMap,
    peer: IpAddr,
    proxies: &[IpNet],
    header_name: &str,
) -> IpAddr {
    let trusted = |ip| proxies.iter().any(|proxy| proxy.contains(&ip));
    if !trusted(peer) {
        return peer;
    }
    let xff = header_name.eq_ignore_ascii_case("x-forwarded-for");
    let chain: Vec<&[u8]> = headers
        .get_all(header_name)
        .iter()
        .flat_map(|value| {
            if xff {
                value.as_bytes().split(|byte| *byte == b',').collect()
            } else {
                split_quoted(value.as_bytes(), b',')
            }
        })
        .collect();
    let mut client = peer;
    for entry in chain.into_iter().rev() {
        if !trusted(client) {
            break;
        }
        let address = std::str::from_utf8(entry).ok().and_then(|entry| {
            if xff {
                return parse_address(entry);
            }
            let directives = split_quoted(entry.as_bytes(), b';');
            let mut addresses = directives.iter().filter_map(|directive| {
                let (name, value) = std::str::from_utf8(directive)
                    .ok()?
                    .trim()
                    .split_once('=')?;
                name.eq_ignore_ascii_case("for").then_some(value)
            });
            let address = parse_address(addresses.next()?)?;
            if addresses.next().is_some() {
                return None;
            }
            Some(address)
        });
        let Some(address) = address else {
            return peer;
        };
        client = address;
    }
    client
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_chain_stops_at_first_untrusted_address() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            "203.0.113.9, 198.51.100.7, 10.0.0.2".parse().unwrap(),
        );
        let peer = "10.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_with_proxies(&headers, peer, &[], "x-forwarded-for"),
            peer
        );
        let proxies = ["10.0.0.0/24".parse().unwrap()];
        assert_eq!(
            resolve_with_proxies(&headers, peer, &proxies, "x-forwarded-for").to_string(),
            "198.51.100.7"
        );
        headers.insert("X-Forwarded-For", "garbage, 198.51.100.7".parse().unwrap());
        assert_eq!(
            resolve_with_proxies(&headers, peer, &proxies, "x-forwarded-for").to_string(),
            "198.51.100.7"
        );
        headers.insert(
            "X-Forwarded-For",
            axum::http::HeaderValue::from_bytes(b"\xff, 198.51.100.7").unwrap(),
        );
        assert_eq!(
            resolve_with_proxies(&headers, peer, &proxies, "x-forwarded-for").to_string(),
            "198.51.100.7"
        );
        headers.insert("X-Forwarded-For", "198.51.100.7, garbage".parse().unwrap());
        assert_eq!(
            resolve_with_proxies(&headers, peer, &proxies, "x-forwarded-for"),
            peer
        );
    }

    #[test]
    fn forwarded_quoted_extensions_do_not_change_client_address() {
        let proxies = ["10.0.0.0/24".parse().unwrap()];
        for value in [
            r#"for=198.51.100.7;host="example.test,foo;for=203.0.113.9""#,
            r#"for=198.51.100.7;ext="foo\";bar,baz""#,
            r#"for=garbage", for=198.51.100.7;host="example.test,foo""#,
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("Forwarded", value.parse().unwrap());
            assert_eq!(
                resolve_with_proxies(&headers, "10.0.0.1".parse().unwrap(), &proxies, "forwarded")
                    .to_string(),
                "198.51.100.7",
                "{value}"
            );
        }
    }

    #[test]
    fn only_the_configured_header_family_is_used() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.9".parse().unwrap());
        headers.insert("Forwarded", "for=198.51.100.7".parse().unwrap());
        let proxies = ["10.0.0.0/24".parse().unwrap()];
        assert_eq!(
            resolve_with_proxies(&headers, "10.0.0.1".parse().unwrap(), &proxies, "forwarded")
                .to_string(),
            "198.51.100.7"
        );
    }

    #[test]
    fn forwarded_supports_ipv6_and_ports() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Forwarded",
            "for=203.0.113.9;proto=https, For=\"[2001:db8::7]:1234\""
                .parse()
                .unwrap(),
        );
        let proxies = ["10.0.0.0/24".parse().unwrap()];
        assert_eq!(
            resolve_with_proxies(&headers, "10.0.0.1".parse().unwrap(), &proxies, "forwarded")
                .to_string(),
            "2001:db8::7"
        );
    }
}
