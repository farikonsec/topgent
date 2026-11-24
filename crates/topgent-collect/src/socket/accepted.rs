//! Telling an accepted connection from one this host opened.
//!
//! A socket table lists both ends of an established connection the same way,
//! local address then peer. The one thing that separates a connection a
//! process accepted from one it opened is that the accepted one's local end is
//! a port the process is listening on. Every established row used to be read
//! as outbound, so a local dev server with twenty browser tabs looked like an
//! agent reaching twenty hosts.

use std::net::IpAddr;

/// Whether a connection whose local end is `host:port` arrived on one of the
/// listeners, each given as its bind address and port.
///
/// A listener bound to a wildcard takes connections on every address; one
/// bound to a specific address takes them only there. An IPv4 address the
/// kernel lists in its IPv6 form is the same address.
pub(super) fn arrived_on(host: &str, port: u16, listeners: &[(String, u16)]) -> bool {
    let local = normalise(host);
    listeners.iter().any(|(bound, bound_port)| {
        *bound_port == port && (is_wildcard(bound) || normalise(bound) == local)
    })
}

fn is_wildcard(host: &str) -> bool {
    matches!(host.trim_matches(['[', ']']), "*" | "0.0.0.0" | "::")
}

fn normalise(host: &str) -> Option<IpAddr> {
    let address = host.trim_matches(['[', ']']).parse::<IpAddr>().ok()?;
    Some(match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    })
}

#[cfg(test)]
mod tests {
    use super::arrived_on;

    fn listeners(list: &[(&str, u16)]) -> Vec<(String, u16)> {
        list.iter().map(|(h, p)| ((*h).to_owned(), *p)).collect()
    }

    #[test]
    fn a_wildcard_listener_takes_every_address() {
        for wildcard in ["*", "0.0.0.0", "::", "[::]"] {
            let on = listeners(&[(wildcard, 8080)]);
            assert!(arrived_on("127.0.0.1", 8080, &on), "{wildcard}");
            assert!(arrived_on("::ffff:10.0.0.5", 8080, &on), "{wildcard}");
            assert!(!arrived_on("127.0.0.1", 8081, &on), "{wildcard}");
        }
    }

    #[test]
    fn a_bound_listener_takes_only_its_own_address() {
        let on = listeners(&[("127.0.0.1", 8080)]);
        assert!(arrived_on("127.0.0.1", 8080, &on));
        assert!(arrived_on("[::ffff:127.0.0.1]", 8080, &on));
        assert!(!arrived_on("10.0.0.5", 8080, &on));
    }

    #[test]
    fn no_listener_means_nothing_arrived() {
        assert!(!arrived_on("127.0.0.1", 8080, &[]));
        assert!(!arrived_on(
            "not-an-address",
            8080,
            &listeners(&[("127.0.0.1", 8080)])
        ));
    }
}
