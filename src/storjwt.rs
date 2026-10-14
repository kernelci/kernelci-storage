use crate::{
    get_config_table,
    logging::{format_log_timestamp, logfmt_string},
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    exp: Option<u64>,
}

fn verify_with_key_str(
    token_str: &str,
    key_str: &str,
) -> Result<BTreeMap<String, String>, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_secret(key_str.as_bytes());
    let mut validation = Validation::default();
    validation.required_spec_claims.clear();
    validation.validate_exp = true;
    validation.leeway = 0;
    validation.validate_aud = false;
    let token_data = decode::<Claims>(token_str, &key, &validation)?;
    let mut claims = BTreeMap::new();
    claims.insert("email".to_string(), token_data.claims.email);
    Ok(claims)
}

fn log_auth_warning(message: &str, error: Option<&jsonwebtoken::errors::Error>, client_info: &str) {
    let timestamp = format_log_timestamp(std::time::SystemTime::now());
    match error {
        Some(error) => eprintln!(
            "ts={} level=warn event=auth msg={} error={} {}",
            timestamp,
            logfmt_string(message),
            logfmt_string(&format!("{:?}", error)),
            client_info
        ),
        None => eprintln!(
            "ts={} level=warn event=auth msg={} {}",
            timestamp,
            logfmt_string(message),
            client_info
        ),
    }
}

pub fn verify_jwt_token(
    token_str: &str,
    client_info: &str,
) -> Result<BTreeMap<String, String>, jsonwebtoken::errors::Error> {
    let parsed_toml = get_config_table();

    // If only unified_secret is configured, it serves as jwt_secret as well.
    // Try jwt_secret first, then fall through to unified_secret.
    if let Some(key_str) = parsed_toml.get("jwt_secret").and_then(|v| v.as_str()) {
        match verify_with_key_str(token_str, key_str) {
            Ok(claims) => {
                debug_log!("email: {}", claims["email"]);
                return Ok(claims);
            }
            Err(e) => {
                log_auth_warning(
                    "JWT verification with jwt_secret failed",
                    Some(&e),
                    client_info,
                );
            }
        }
    } else {
        log_auth_warning("No jwt_secret configured", None, client_info);
    }

    if let Some(unified) = parsed_toml.get("unified_secret").and_then(|v| v.as_str()) {
        match verify_with_key_str(token_str, unified) {
            Ok(claims) => {
                debug_log!("email (unified_secret): {}", claims["email"]);
                return Ok(claims);
            }
            Err(e) => {
                log_auth_warning(
                    "JWT verification with unified_secret also failed",
                    Some(&e),
                    client_info,
                );
                return Err(e);
            }
        }
    } else {
        log_auth_warning("No unified_secret configured", None, client_info);
    }

    log_auth_warning(
        "JWT verification error: no matching secret found",
        None,
        client_info,
    );
    Err(jsonwebtoken::errors::ErrorKind::InvalidSignature.into())
}

pub fn generate_jwt_secret() {
    // generate a random 32 bytes alphanumeric string
    use rand::distr::{Alphanumeric, SampleString};

    let secret = Alphanumeric.sample_string(&mut rand::rng(), 32);
    debug_log!("jwt_secret=\"{}\"", secret);
}

pub fn generate_jwt_token(email: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let parsed_toml = get_config_table();
    // For token generation, prefer jwt_secret, fall back to unified_secret
    let key_str = parsed_toml
        .get("jwt_secret")
        .or_else(|| parsed_toml.get("unified_secret"))
        .and_then(|v| v.as_str())
        .expect("config must define jwt_secret or unified_secret");
    let key = EncodingKey::from_secret(key_str.as_bytes());
    let claims = Claims {
        email: email.to_string(),
        exp: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(86400),
        ),
    };
    encode(&Header::default(), &claims, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplied_expiration_is_checked_and_legacy_tokens_still_work() {
        let key = EncodingKey::from_secret(b"test-key");
        let legacy = encode(
            &Header::default(),
            &Claims {
                email: "alice".to_string(),
                exp: None,
            },
            &key,
        )
        .unwrap();
        assert!(verify_with_key_str(&legacy, "test-key").is_ok());
        let expired = encode(
            &Header::default(),
            &Claims {
                email: "alice".to_string(),
                exp: Some(1),
            },
            &key,
        )
        .unwrap();
        assert!(verify_with_key_str(&expired, "test-key").is_err());
        let future = encode(
            &Header::default(),
            &Claims {
                email: "alice".to_string(),
                exp: Some(u64::MAX),
            },
            &key,
        )
        .unwrap();
        assert!(verify_with_key_str(&future, "test-key").is_ok());
        let malformed = encode(
            &Header::default(),
            &serde_json::json!({"email":"alice", "exp":"invalid"}),
            &key,
        )
        .unwrap();
        assert!(verify_with_key_str(&malformed, "test-key").is_err());
    }
}
