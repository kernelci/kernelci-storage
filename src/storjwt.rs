use crate::{debug_log, get_config_content};
use hmac::{Hmac, Mac};
use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use sha2::Sha256;
use std::collections::BTreeMap;
use toml::value::Table;
fn verify_with_key_str(
    token_str: &str,
    key_str: &str,
) -> Result<BTreeMap<String, String>, jwt::Error> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(key_str.as_bytes())?;
    let token: Token<Header, BTreeMap<String, String>, _> = token_str.verify_with_key(&key)?;
    let claims = token.claims();
    if claims.get("email").is_none() {
        debug_log!("email not found");
        return Err(jwt::Error::InvalidSignature);
    }
    Ok(claims.clone())
}

pub fn verify_jwt_token(token_str: &str) -> Result<BTreeMap<String, String>, jwt::Error> {
    let toml_cfg = get_config_content();
    let parsed_toml = toml_cfg.parse::<Table>().unwrap();
    let key_str = parsed_toml["jwt_secret"].as_str().unwrap();

    match verify_with_key_str(token_str, key_str) {
        Ok(claims) => {
            debug_log!("email: {}", claims["email"]);
            return Ok(claims);
        }
        Err(e) => {
            debug_log!("JWT verification with jwt_secret failed: {:?}", e);
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

    Err(jwt::Error::InvalidSignature)
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

pub fn generate_jwt_token(email: &str) -> Result<String, jwt::Error> {
    let toml_cfg = get_config_content();
    let parsed_toml = toml_cfg.parse::<Table>().unwrap();
    let key_str = parsed_toml["jwt_secret"].as_str().unwrap();
    let key: Hmac<Sha256> = Hmac::new_from_slice(key_str.as_bytes())?;
    let mut claims = BTreeMap::new();
    claims.insert("email".to_string(), email.to_string());
    let token_str = claims.sign_with_key(&key)?;
    Ok(token_str)
}
