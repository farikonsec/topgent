//! Naming outbound destinations, without decrypting anything.
//!
//! An agent's socket gives Topgent a peer IP and a port. That is enough to say
//! *where* traffic is going and, from reverse DNS, roughly *who* owns the far
//! end, which answers the question a person actually asks looking at a list of
//! raw IPs. It is metadata only: no payload is read and no TLS is touched, the
//! same limit Wireshark hits on an encrypted flow.
//!
//! Country-level geolocation is deliberately absent. Doing it means either an
//! offline database to ship and keep current, or a per-IP call to a third-party
//! lookup service. The second would tell that service every address every agent
//! on the machine talks to, which is exactly the kind of quiet exfiltration
//! Topgent exists to catch. Owner-from-reverse-DNS gives most of the value with
//! none of that, so it is what ships; an offline `GeoIP` database is a later
//! opt-in, never a phone-home.
//!
//! Reverse lookups are cached for the process lifetime, so a busy machine is
//! resolved once rather than once per sweep.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

/// Known owners, matched against the suffix of a reverse-DNS name or the
/// forward host an agent connected to. Deliberately a short, legible table
/// rather than an ASN database: a wrong owner is worse than none.
const OWNERS: &[(&str, &str)] = &[
    ("anthropic.com", "Anthropic"),
    ("openai.com", "OpenAI"),
    ("googleapis.com", "Google"),
    ("google.com", "Google"),
    ("dns.google", "Google"),
    ("1e100.net", "Google"),
    ("gstatic.com", "Google"),
    ("amazonaws.com", "Amazon AWS"),
    ("azure.com", "Microsoft Azure"),
    ("windows.net", "Microsoft Azure"),
    ("openai.azure.com", "Azure OpenAI"),
    ("github.com", "GitHub"),
    ("githubusercontent.com", "GitHub"),
    ("githubcopilot.com", "GitHub"),
    ("cloudflare.com", "Cloudflare"),
    ("fastly.net", "Fastly"),
    ("npmjs.org", "npm"),
    ("openrouter.ai", "OpenRouter"),
    ("mistral.ai", "Mistral"),
    ("cohere.com", "Cohere"),
];

fn cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    static C: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The owner Topgent recognises for a hostname, by suffix.
#[must_use]
pub fn owner_of(host: &str) -> Option<&'static str> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    OWNERS
        .iter()
        .find(|(suffix, _)| h == *suffix || h.ends_with(&format!(".{suffix}")))
        .map(|(_, name)| *name)
}

/// Whether a string looks like a bare IP rather than a name already.
fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// The reverse-DNS name for an address, cached, or `None` when it has none.
///
/// Uses the host resolver through `dig`/`host` with a short timeout. A lookup
/// that hangs must not stall a sweep, so the timeout is deliberately tight and a
/// failure is a cache entry of `None`, never a retry storm.
#[must_use]
pub fn reverse(ip: &str) -> Option<String> {
    if !is_ip(ip) {
        return None;
    }
    if let Ok(guard) = cache().lock()
        && let Some(hit) = guard.get(ip)
    {
        return hit.clone();
    }

    let name = dig_ptr(ip).or_else(|| host_ptr(ip));
    if let Ok(mut guard) = cache().lock() {
        guard.insert(ip.to_owned(), name.clone());
    }
    name
}

fn dig_ptr(ip: &str) -> Option<String> {
    let out = crate::tool::DIG
        .command()
        .ok()?
        .args(["+short", "+time=1", "+tries=1", "-x", ip])
        .output()
        .ok()?;
    parse_dig_short(&String::from_utf8_lossy(&out.stdout))
}

fn host_ptr(ip: &str) -> Option<String> {
    let out = crate::tool::HOST.command().ok()?.arg(ip).output().ok()?;
    parse_host_output(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `dig +short -x` output: the first non-empty line is the name.
#[must_use]
pub fn parse_dig_short(text: &str) -> Option<String> {
    text.lines()
        .next()
        .map(|l| l.trim().trim_end_matches('.').to_owned())
        .filter(|s| !s.is_empty())
}

/// Parse `host <ip>` output, whose line is
/// `<ip>.in-addr.arpa domain name pointer <name>.`
#[must_use]
pub fn parse_host_output(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.rsplit("pointer ").next().filter(|s| *s != l))
        .map(|s| s.trim().trim_end_matches('.').to_owned())
        .filter(|s| !s.is_empty())
}

/// The best label Topgent can put on a destination: its name if resolvable, its
/// owner if recognised, or just the address. Returns `(display, owner)`.
#[must_use]
pub fn label(host: &str) -> (String, Option<&'static str>) {
    // If the agent connected by name, use it directly.
    if !is_ip(host) {
        return (host.to_owned(), owner_of(host));
    }
    match reverse(host) {
        Some(name) => {
            let owner = owner_of(&name);
            (name, owner)
        }
        None => (host.to_owned(), None),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::{label, owner_of, parse_dig_short, parse_host_output};

    #[test]
    fn owners_are_matched_by_dns_suffix_not_substring() {
        assert_eq!(owner_of("lb-140-82-121-3-fra.github.com"), Some("GitHub"));
        assert_eq!(owner_of("api.anthropic.com"), Some("Anthropic"));
        assert_eq!(
            owner_of("ec2-1-2-3-4.compute-1.amazonaws.com"),
            Some("Amazon AWS")
        );
        assert_eq!(owner_of("dns.google"), Some("Google"));
        // Suffix, not substring: a lookalike host does not match.
        assert_eq!(owner_of("github.com.evil.example"), None);
        assert_eq!(owner_of("not-anthropic.com.attacker.net"), None);
        assert_eq!(owner_of("example.org"), None);
    }

    #[test]
    fn a_hostname_keeps_its_name_and_resolves_its_owner_without_a_lookup() {
        assert_eq!(
            label("api.anthropic.com"),
            ("api.anthropic.com".to_owned(), Some("Anthropic"))
        );
        assert_eq!(label("example.com"), ("example.com".to_owned(), None));
    }

    #[test]
    fn dig_output_is_read_as_the_first_name() {
        assert_eq!(
            parse_dig_short("dns.google.\n").as_deref(),
            Some("dns.google")
        );
        assert_eq!(parse_dig_short("\n").as_deref(), None);
        assert_eq!(parse_dig_short(""), None);
    }

    #[test]
    fn host_output_is_read_after_the_pointer_keyword() {
        let out = "3.121.82.140.in-addr.arpa domain name pointer lb.github.com.\n";
        assert_eq!(parse_host_output(out).as_deref(), Some("lb.github.com"));
        // No PTR record: nothing extracted, never a crash.
        assert_eq!(
            parse_host_output("Host 1.2.3.4 not found: 3(NXDOMAIN)\n"),
            None
        );
        assert_eq!(parse_host_output(""), None);
    }
}
