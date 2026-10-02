//! `propose()`: match tokens to existing vault logins (package 1D).
//!
//! Scoring per (token, login): a service key found in the login's name or one of its hosts is +3;
//! the login's username equalling the token's username is +2. Only a service match makes a login a
//! candidate: a shared username alone (usually the user's one email address) says nothing about
//! which service a code belongs to, so it never causes an attach.

use std::collections::HashSet;

use crate::types::Token;

use super::VaultLogin;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Attach { item_id: String },
    CreateNew,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub token_id: String,
    pub decision: Decision,
    pub confidence: Confidence,
    /// Ids of every login that matched the service, best first (including ones that already have
    /// a code, which are listed but never chosen).
    pub candidates: Vec<String>,
}

const SERVICE_POINTS: u32 = 3;
const USERNAME_POINTS: u32 = 2;

/// (key as it appears in a token, extra patterns to search for as well). A pattern containing a
/// dot is a host suffix (`live.com` matches `login.live.com`, never `livenation.com`); one
/// without is a whole word of the login name or a whole label of a host. A match that rests only
/// on one of these is never better than `Low` confidence: the user confirms it.
const ALIASES: &[(&str, &[&str])] = &[
    (
        "amazon web services",
        &["aws", "amazonaws.com", "aws.amazon.com"],
    ),
    (
        "microsoft",
        &[
            "microsoft.com",
            "live.com",
            "office.com",
            "microsoftonline.com",
        ],
    ),
    ("google", &["google.com", "gmail.com"]),
    ("gmail", &["google.com", "gmail.com"]),
];

/// Lowercase, every run of non-alphanumerics becomes one space.
fn norm(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut gap = true;
    for c in s.chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
            gap = false;
        } else if !gap {
            out.push(' ');
            gap = true;
        }
    }
    out.trim_end().to_string()
}

fn has_word_run(haystack: &str, needle: &str) -> bool {
    format!(" {haystack} ").contains(&format!(" {needle} "))
}

struct Keys {
    own: Vec<String>,
    alias: Vec<String>,
}

fn search_keys(token: &Token) -> Keys {
    let mut raw: Vec<&str> = Vec::new();
    if let Some(issuer) = token.issuer.as_deref() {
        raw.push(issuer);
    }
    // "GitHub: someone@x.com" and "GitHub (someone)" both mean "GitHub"; a bare address means
    // nothing about the service.
    let name = token.name.split([':', '(']).next().unwrap_or("");
    if !name.contains('@') {
        raw.push(name);
    }
    let mut own: Vec<String> = Vec::new();
    let mut alias: Vec<String> = Vec::new();
    for r in raw {
        let k = norm(r);
        if k.chars().count() < 3 {
            continue;
        }
        for (from, to) in ALIASES {
            if has_word_run(&k, from) {
                alias.extend(to.iter().map(|s| s.to_string()));
            }
        }
        own.push(k);
    }
    own.sort();
    own.dedup();
    alias.sort();
    alias.dedup();
    alias.retain(|a| !own.contains(a));
    Keys { own, alias }
}

fn host_has_suffix(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// Second-level labels that, before a two-letter country code, form a public suffix (`co.uk`).
const SECOND_LEVEL: &[&str] = &["co", "com", "org", "net", "gov", "edu", "ac"];
/// Never matchable as a word of a login name: URL furniture and public-suffix labels.
const NOT_WORDS: &[&str] = &[
    "http", "https", "www", "com", "org", "net", "gov", "edu", "ac", "co",
];

/// A host split into its registrable label (the one just left of the public suffix) and the
/// subdomain labels in front of it. No public-suffix list: the suffix is the last label, or the
/// last two when they look like `co.uk`. IP addresses have no labels worth matching.
struct HostLabels {
    registrable: Option<String>,
    subdomains: Vec<String>,
}

fn host_labels(host: &str) -> HostLabels {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    let is_ip = host.contains(':') || host.chars().all(|c| c.is_ascii_digit() || c == '.');
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if is_ip || labels.len() < 2 {
        return HostLabels {
            registrable: None,
            subdomains: Vec::new(),
        };
    }
    let n = labels.len();
    let two_part = n >= 3
        && labels[n - 1].len() == 2
        && labels[n - 1].chars().all(|c| c.is_ascii_alphabetic())
        && SECOND_LEVEL.contains(&labels[n - 2]);
    let suffix_len = if two_part { 2 } else { 1 };
    let reg = n - suffix_len - 1;
    HostLabels {
        registrable: Some(labels[reg].to_string()),
        subdomains: labels[..reg]
            .iter()
            .filter(|l| **l != "www")
            .map(|l| l.to_string())
            .collect(),
    }
}

/// Host part of something that looks like a URL or bare host ("https://www.x.com/login",
/// "x.com"); `None` for an ordinary name.
fn name_as_host(name: &str) -> Option<String> {
    let t = name.trim();
    let has_scheme = t.contains("://");
    if !has_scheme && (t.contains(char::is_whitespace) || !t.contains('.') || t.contains('@')) {
        return None;
    }
    let rest = t.split("://").last().unwrap_or(t);
    let rest = rest.split(['/', '?', '#']).next().unwrap_or("");
    let rest = rest.rsplit('@').next().unwrap_or("");
    let host = rest.split(':').next().unwrap_or("");
    (!host.is_empty()).then(|| host.to_string())
}

/// The matchable words of a login name. A name that is a URL or host contributes only its
/// registrable label; otherwise its words minus URL furniture and public-suffix labels.
fn name_words(name: &str) -> Vec<String> {
    if let Some(host) = name_as_host(name) {
        return host_labels(&host).registrable.into_iter().collect();
    }
    norm(name)
        .split(' ')
        .filter(|w| !w.is_empty() && !NOT_WORDS.contains(w))
        .map(str::to_string)
        .collect()
}

fn squash(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).collect()
}

/// How strongly `key` matches a login: `Some(false)` strong, `Some(true)` weak (only a subdomain
/// label of a host, or a dotted alias), `None` no match.
fn key_hits(
    key: &str,
    words: &[String],
    hosts: &[HostLabels],
    raw_hosts: &[String],
) -> Option<bool> {
    if key.contains('.') {
        return raw_hosts
            .iter()
            .any(|h| host_has_suffix(&h.to_lowercase(), key))
            .then_some(true);
    }
    // A multi-word key ("stack overflow") also matches squashed ("stackoverflow") as one word or
    // label by itself.
    let words_key: Vec<&str> = key.split(' ').collect();
    let compact = squash(key);
    let multi = words_key.len() > 1;
    let name_run = words
        .windows(words_key.len())
        .any(|w| w.iter().map(String::as_str).eq(words_key.iter().copied()));
    let label_eq = |l: &String| *l == compact || (multi && squash(l) == compact);
    let name_word = multi && words.contains(&compact);
    if name_run
        || name_word
        || hosts
            .iter()
            .any(|h| h.registrable.as_ref().is_some_and(label_eq))
    {
        return Some(false);
    }
    if hosts.iter().any(|h| h.subdomains.iter().any(label_eq)) {
        return Some(true);
    }
    None
}

/// `Some(weak)` when the login matches the token's service; weak matches (a subdomain label, or
/// only an alias) are never better than `Low` confidence.
fn service_match(keys: &Keys, login: &VaultLogin) -> Option<bool> {
    let words = name_words(&login.name);
    let hosts: Vec<HostLabels> = login.hosts.iter().map(|h| host_labels(h)).collect();
    let best = |ks: &[String]| -> Option<bool> {
        ks.iter()
            .filter_map(|k| key_hits(k, &words, &hosts, &login.hosts))
            .min() // strong (false) beats weak (true)
    };
    match best(&keys.own) {
        Some(weak) => Some(weak),
        None => best(&keys.alias).map(|_| true),
    }
}

fn same_username(token: &Token, login: &VaultLogin) -> bool {
    match (token.username.as_deref(), login.username.as_deref()) {
        (Some(a), Some(b)) => {
            let (a, b) = (a.trim(), b.trim());
            !a.is_empty() && a.eq_ignore_ascii_case(b)
        }
        _ => false,
    }
}

/// (index in `vault`, score, match rests only on an alias).
type Scored = (usize, u32, bool);

/// Service-matching logins for one token, best first (own-key matches before alias-only ones,
/// vault order on ties).
fn scored(token: &Token, keys: &Keys, vault: &[VaultLogin]) -> Vec<Scored> {
    let mut v: Vec<Scored> = vault
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            let alias_only = service_match(keys, l)?;
            let mut score = SERVICE_POINTS;
            if same_username(token, l) {
                score += USERNAME_POINTS;
            }
            Some((i, score, alias_only))
        })
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)).then(a.0.cmp(&b.0)));
    v
}

/// Propose a decision for every token, in the order of `tokens`.
///
/// A login is proposed for at most one token. Tokens are settled strongest evidence first, so an
/// exact (service + username) match wins its login no matter where in the list it sits; a token
/// whose only candidates were taken becomes `CreateNew` with `Low` confidence and the taken
/// logins listed, so the user is asked.
pub fn propose(tokens: &[Token], vault: &[VaultLogin]) -> Vec<Proposal> {
    let keys: Vec<Keys> = tokens.iter().map(search_keys).collect();
    let scores: Vec<Vec<Scored>> = tokens
        .iter()
        .zip(&keys)
        .map(|(t, k)| scored(t, k, vault))
        .collect();

    // Strongest first, input order on ties.
    let mut order: Vec<usize> = (0..tokens.len()).collect();
    order.sort_by_key(|&i| {
        let best = scores[i]
            .iter()
            .filter(|(l, _, _)| !vault[*l].has_totp)
            .map(|(_, s, _)| *s)
            .max()
            .unwrap_or(0);
        (std::cmp::Reverse(best), i)
    });

    let mut claimed: HashSet<usize> = HashSet::new();
    let mut out: Vec<Option<Proposal>> = vec![None; tokens.len()];

    for i in order {
        let candidates: Vec<String> = scores[i]
            .iter()
            .map(|(l, _, _)| vault[*l].id.clone())
            .collect();
        let free: Vec<Scored> = scores[i]
            .iter()
            .copied()
            .filter(|(l, _, _)| !vault[*l].has_totp && !claimed.contains(l))
            .collect();
        let taken_by_another = scores[i]
            .iter()
            .any(|(l, _, _)| !vault[*l].has_totp && claimed.contains(l));

        let (decision, confidence) = match free.first() {
            Some(&(best, top, alias_only)) => {
                claimed.insert(best);
                let tied = free
                    .iter()
                    .filter(|(_, s, a)| *s == top && *a == alias_only)
                    .count();
                let confidence = if tied == 1 && !taken_by_another && !alias_only {
                    Confidence::High
                } else {
                    Confidence::Low
                };
                (
                    Decision::Attach {
                        item_id: vault[best].id.clone(),
                    },
                    confidence,
                )
            }
            None if taken_by_another => (Decision::CreateNew, Confidence::Low),
            None => (Decision::CreateNew, Confidence::High),
        };
        out[i] = Some(Proposal {
            token_id: tokens[i].id.clone(),
            decision,
            confidence,
            candidates,
        });
    }
    out.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_collapses_punctuation() {
        assert_eq!(norm("  Stack-Overflow.com / x "), "stack overflow com x");
    }

    #[test]
    fn short_or_address_names_make_no_keys() {
        assert!(search_keys(&token("t", "jeff@example.com", None))
            .own
            .is_empty());
        assert!(search_keys(&token("t", "ab", None)).own.is_empty());
    }

    fn token(id: &str, name: &str, issuer: Option<&str>) -> Token {
        Token {
            id: id.into(),
            title: name.into(),
            name: name.into(),
            issuer: issuer.map(Into::into),
            username: None,
            secret: crate::types::Secret::new("JBSWY3DPEHPK3PXP".into()),
            digits: 6,
            period: 30,
        }
    }
}
