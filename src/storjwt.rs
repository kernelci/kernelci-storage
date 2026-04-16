use crate::get_config_content;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use toml::value::Table;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    email: String,
}

fn verify_with_key_str(
    token_str: &str,
    key_str: &str,
) -> Result<BTreeMap<String, String>, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_secret(key_str.as_bytes());
    let mut validation = Validation::default();
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let token_data = decode::<Claims>(token_str, &key, &validation)?;
    let mut claims = BTreeMap::new();
    claims.insert("email".to_string(), token_data.claims.email);
    Ok(claims)
}

pub fn verify_jwt_token(
    token_str: &str,
) -> Result<BTreeMap<String, String>, jsonwebtoken::errors::Error> {
    let toml_cfg = get_config_content();
    let parsed_toml = toml_cfg.parse::<Table>().unwrap();

    // If only unified_secret is configured, it serves as jwt_secret as well.
    // Try jwt_secret first, then fall through to unified_secret.
    if let Some(key_str) = parsed_toml.get("jwt_secret").and_then(|v| v.as_str()) {
        match verify_with_key_str(token_str, key_str) {
            Ok(claims) => {
                debug_log!("email: {}", claims["email"]);
                return Ok(claims);
            }
            Err(e) => {
                debug_log!("JWT verification with jwt_secret failed: {:?}", e);
            }
        }
    }

    if let Some(unified) = parsed_toml.get("unified_secret").and_then(|v| v.as_str()) {
        match verify_with_key_str(token_str, unified) {
            Ok(claims) => {
                debug_log!("email (unified_secret): {}", claims["email"]);
                return Ok(claims);
            }
            Err(e) => {
                eprintln!("JWT verification with unified_secret also failed: {:?}", e);
                return Err(e);
            }
        }
    }

    Err(jsonwebtoken::errors::ErrorKind::InvalidSignature.into())
}

pub fn generate_jwt_secret() {
    // generate a random 32 bytes alphanumeric string
    use rand::{distributions::Alphanumeric, Rng};

    let secret: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    debug_log!("jwt_secret=\"{}\"", secret);
}

pub fn generate_jwt_token(email: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let toml_cfg = get_config_content();
    let parsed_toml = toml_cfg.parse::<Table>().unwrap();
    // For token generation, prefer jwt_secret, fall back to unified_secret
    let key_str = parsed_toml
        .get("jwt_secret")
        .or_else(|| parsed_toml.get("unified_secret"))
        .and_then(|v| v.as_str())
        .expect("config must define jwt_secret or unified_secret");
    let key = EncodingKey::from_secret(key_str.as_bytes());
    let claims = Claims {
        email: email.to_string(),
    };
    encode(&Header::default(), &claims, &key)
}
