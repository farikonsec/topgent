//! The kernel's socket tables, parsed without a subprocess.
//!
//! The file is kernel-owned, so this is not the hostile-input case the other
//! parsers are. It is fuzzed anyway for two reasons: the address fields are
//! hex words with per-word endianness and an easy place to index out of
//! bounds, and a kernel table is exactly the sort of thing whose format
//! changes under a distribution upgrade rather than under an attacker.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for row in topgent_collect::socket::parse_table(text) {
        // Anything admitted becomes an endpoint in a report, so the properties
        // that matter are asserted rather than assumed.
        assert!(!row.host.is_empty(), "a row with no host was admitted");
        assert!(
            row.host.parse::<std::net::IpAddr>().is_ok(),
            "host {:?} is not an address",
            row.host
        );
    }
    // The port map reads the same tables for a different column, and it reads
    // `/proc/net/raw` and `/proc/net/icmp` too, whose state and port columns
    // do not mean what the TCP ones mean.
    for row in topgent_collect::socket::parse_local_ports(text) {
        assert!(row.port != 0, "port zero holds nothing and was admitted");
    }
    let _ = topgent_collect::socket::parse_inodes(text);
    // The address decoder on its own, which is where the indexing lives.
    if let Some((host, _port)) = topgent_collect::socket::parse_address(text) {
        assert!(
            host.parse::<std::net::IpAddr>().is_ok(),
            "parse_address returned {host:?}, which is not an address"
        );
    }
});
