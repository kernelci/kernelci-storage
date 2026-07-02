// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>
/*
   User-Agent ban framework.

   Requests whose User-Agent header contains any banned substring
   (case-insensitive) are rejected with 403 Forbidden before they reach any
   handler. This is meant to keep out web crawlers, scrapers, and AI agents
   that hammer the storage server.

   A curated built-in list (DEFAULT_BANNED) is always applied. It blocks the
   common "lesser" search-engine crawlers and AI scrapers while deliberately
   letting Google (Googlebot) and Microsoft (bingbot/msnbot) through, so the
   artifacts stay indexable by the two major engines. Additional substrings can
   be added via config, and the built-in defaults can be turned off entirely:

   [useragent]
   # Extra case-insensitive substrings to ban, on top of the built-in list.
   ban = ["SemrushBot", "MJ12bot"]
   # Set to false to disable the built-in DEFAULT_BANNED list.
   defaults = true

   The effective list is read once and cached, so restart the server to apply
   changes.
*/

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::SystemTime;

use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use toml::Table;

use crate::logging;

/// Built-in, always-on ban list of lowercased User-Agent substrings.
///
/// Covers the common "lesser" search-engine crawlers and AI scrapers.
/// IMPORTANT: none of these substrings may appear in Google's or Microsoft's
/// crawler User-Agents (Googlebot, bingbot, msnbot, adidxbot, ...), so those
/// two are always allowed to index. Keep tokens specific (prefer "yandexbot"
/// over "yandex") to avoid matching human browsers built on the same brand.
const DEFAULT_BANNED: &[&str] = &[
    // --- Lesser search engines (Google and Microsoft intentionally excluded) ---
    "baiduspider",  // Baidu
    "yandexbot",    // Yandex
    "yandeximages", // Yandex (images)
    "duckduckbot",  // DuckDuckGo crawler (not the browser app)
    "slurp",        // Yahoo
    "sogou",        // Sogou
    "exabot",       // Exalead
    "seznambot",    // Seznam
    "naverbot",     // Naver
    "yeti",         // Naver (Yeti crawler)
    "qwant",        // Qwant
    "mojeekbot",    // Mojeek
    "petalbot",     // Petal / Huawei
    "coccocbot",    // Coc Coc
    "gigablast",    // Gigablast
    "mail.ru",      // Mail.ru
    // --- AI agents / scrapers ---
    "gptbot",         // OpenAI
    "oai-searchbot",  // OpenAI
    "chatgpt-user",   // OpenAI
    "ccbot",          // Common Crawl
    "claudebot",      // Anthropic
    "claude-web",     // Anthropic
    "anthropic-ai",   // Anthropic
    "perplexitybot",  // Perplexity
    "perplexity-user",// Perplexity
    "amazonbot",      // Amazon
    "bytespider",     // ByteDance
    "diffbot",        // Diffbot
    "omgili",         // Webz.io / Omgili
    "imagesift",      // ImageSift
    "cohere-ai",      // Cohere
    "meta-externalagent", // Meta AI
    // --- SEO / marketing crawlers ---
    "ahrefsbot",     // Ahrefs
    "semrushbot",    // Semrush
    "mj12bot",       // Majestic
    "dotbot",        // Moz
    "blexbot",       // WebMeUp
    "dataforseobot", // DataForSEO
    "megaindex",     // MegaIndex
    "serpstatbot",   // Serpstat
    "seokicks",      // SEOkicks
    "linkdexbot",    // Linkdex
    "spbot",         // OpenLinkProfiler / SEOprofiler
];

static BANNED_USER_AGENTS: OnceLock<Vec<String>> = OnceLock::new();

/// Load and cache the effective ban list: the built-in DEFAULT_BANNED
/// substrings (unless disabled via `[useragent] defaults = false`) plus any
/// extra substrings from `[useragent] ban`. All entries are stored lowercased
/// for case-insensitive matching.
fn banned_user_agents() -> &'static Vec<String> {
    BANNED_USER_AGENTS.get_or_init(|| {
        let cfg: Option<Table> = toml::from_str(&crate::get_config_content()).ok();
        let section = cfg.as_ref().and_then(|cfg| cfg.get("useragent"));

        let use_defaults = section
            .and_then(|section| section.get("defaults"))
            .and_then(|value| value.as_bool())
            .unwrap_or(true);

        let mut patterns: Vec<String> = if use_defaults {
            DEFAULT_BANNED.iter().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        };

        if let Some(extra) = section
            .and_then(|section| section.get("ban"))
            .and_then(|ban| ban.as_array())
        {
            patterns.extend(
                extra
                    .iter()
                    .filter_map(|value| value.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_ascii_lowercase()),
            );
        }

        patterns
    })
}

/// Case-insensitive substring match of `user_agent` against `patterns`.
/// `patterns` must already be lowercased.
fn matches_ban(patterns: &[String], user_agent: &str) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let ua = user_agent.to_ascii_lowercase();
    patterns.iter().any(|pattern| ua.contains(pattern))
}

/// Returns true when `user_agent` matches any configured ban substring.
pub fn is_banned(user_agent: &str) -> bool {
    matches_ban(banned_user_agents(), user_agent)
}

/// Axum middleware that rejects requests from banned User-Agents with 403
/// before they reach any handler.
pub async fn ban_middleware(req: Request, next: Next) -> Response {
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();

    if is_banned(&user_agent) {
        let fallback = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| *addr)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let client_ip = crate::client_ip_from_headers(req.headers(), fallback);
        eprintln!(
            "ts={} level=warn event=useragent_ban ip={} method={} target={} ua={}",
            logging::format_log_timestamp(SystemTime::now()),
            logging::logfmt_string(&client_ip),
            req.method().as_str(),
            logging::logfmt_string(&req.uri().to_string()),
            logging::logfmt_string(&user_agent),
        );
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::{matches_ban, DEFAULT_BANNED};

    fn patterns() -> Vec<String> {
        vec!["gptbot".to_string(), "ccbot".to_string()]
    }

    fn defaults() -> Vec<String> {
        DEFAULT_BANNED.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn defaults_block_lesser_search_engines() {
        for ua in [
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
            "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
            "Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
        ] {
            assert!(matches_ban(&defaults(), ua), "should ban: {ua}");
        }
    }

    #[test]
    fn defaults_block_seo_crawlers() {
        for ua in [
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
            "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
            "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
            "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
        ] {
            assert!(matches_ban(&defaults(), ua), "should ban: {ua}");
        }
    }

    #[test]
    fn defaults_allow_google_and_microsoft() {
        for ua in [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "msnbot/2.0b (+http://search.msn.com/msnbot.htm)",
            "Mozilla/5.0 (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Googlebot-Image/1.0",
        ] {
            assert!(!matches_ban(&defaults(), ua), "should allow: {ua}");
        }
    }

    #[test]
    fn empty_patterns_never_match() {
        assert!(!matches_ban(&[], "GPTBot/1.0"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(matches_ban(&patterns(), "Mozilla/5.0 (compatible; GPTBot/1.2)"));
        assert!(matches_ban(&patterns(), "gptbot"));
        assert!(matches_ban(&patterns(), "CCBOT"));
    }

    #[test]
    fn non_matching_agent_passes() {
        assert!(!matches_ban(&patterns(), "curl/8.0"));
        assert!(!matches_ban(&patterns(), ""));
    }
}
