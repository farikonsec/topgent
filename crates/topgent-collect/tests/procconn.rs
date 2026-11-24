//! The kernel's process connector, read byte by byte.
//!
//! Every message is a netlink header, a connector header and one process
//! event. The layouts below are the kernel's own (`linux/netlink.h`,
//! `linux/connector.h`, `linux/cn_proc.h`); the parser treats every byte as
//! hostile anyway, because a parser that trusts its input is the part of a
//! privileged helper an attacker aims at.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use topgent_collect::procconn::{
    Kind, ProcEvent, SequenceTracker, parse_datagram, subscribe_message,
};

const FORK: u32 = 0x0000_0001;
const EXEC: u32 = 0x0000_0002;
const EXIT: u32 = 0x8000_0000;

/// One kernel message: netlink header, connector header, process event.
fn message(what: u32, cpu: u32, seq: u32, timestamp_ns: u64, data: &[u32]) -> Vec<u8> {
    let mut event = Vec::new();
    event.extend(what.to_ne_bytes());
    event.extend(cpu.to_ne_bytes());
    event.extend(timestamp_ns.to_ne_bytes());
    for word in data {
        event.extend(word.to_ne_bytes());
    }
    let mut connector = Vec::new();
    connector.extend(1_u32.to_ne_bytes()); // CN_IDX_PROC
    connector.extend(1_u32.to_ne_bytes()); // CN_VAL_PROC
    connector.extend(seq.to_ne_bytes());
    connector.extend(0_u32.to_ne_bytes()); // ack
    connector.extend(u16::try_from(event.len()).unwrap().to_ne_bytes());
    connector.extend(0_u16.to_ne_bytes()); // flags
    let total = 16 + connector.len() + event.len();
    let mut out = Vec::new();
    out.extend(u32::try_from(total).unwrap().to_ne_bytes());
    out.extend(3_u16.to_ne_bytes()); // NLMSG_DONE
    out.extend(0_u16.to_ne_bytes());
    out.extend(0_u32.to_ne_bytes());
    out.extend(0_u32.to_ne_bytes());
    out.extend(connector);
    out.extend(event);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

#[test]
fn a_fork_names_parent_and_child_processes() {
    let bytes = message(FORK, 2, 7, 5_000_000_000, &[100, 100, 201, 201]);
    let events = parse_datagram(&bytes);
    assert_eq!(
        events,
        vec![ProcEvent {
            kind: Kind::Fork {
                parent_tgid: 100,
                child_pid: 201,
                child_tgid: 201,
            },
            cpu: 2,
            seq: 7,
            timestamp_ns: 5_000_000_000,
        }]
    );
    assert!(events[0].is_process_level(), "a new process, not a thread");
}

/// A new thread is a fork whose child pid differs from its thread-group id.
/// It is not a new process, and counting it as one is how a threaded agent
/// used to look like a fork bomb.
#[test]
fn a_new_thread_is_not_a_new_process() {
    let events = parse_datagram(&message(FORK, 0, 1, 1, &[100, 100, 205, 100]));
    assert!(!events[0].is_process_level());
}

#[test]
fn exec_and_exit_are_read_with_their_fields() {
    let mut bytes = message(EXEC, 0, 1, 10, &[201, 201]);
    bytes.extend(message(EXIT, 1, 1, 20, &[201, 201, 0, 17, 100, 100]));
    let events = parse_datagram(&bytes);
    assert_eq!(events.len(), 2, "two messages in one datagram");
    assert_eq!(events[0].kind, Kind::Exec { tgid: 201 });
    assert!(events[0].is_process_level());
    assert_eq!(
        events[1].kind,
        Kind::Exit {
            pid: 201,
            tgid: 201,
            code: 0
        }
    );
    assert!(events[1].is_process_level());
}

/// Kinds this sensor does not use are recognised as such, not misread as one
/// it does. They are still returned: their sequence numbers count, and
/// dropping them before the loss check would report every one as a loss.
#[test]
fn other_event_kinds_are_kept_for_their_sequence_numbers() {
    let uid_change = message(0x0000_0004, 0, 9, 1, &[201, 201, 1000, 1000]);
    let events = parse_datagram(&uid_change);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, Kind::Other);
    assert_eq!(events[0].seq, 9);
    assert!(!events[0].is_process_level());
}

/// On `exec` the kernel renames the process and announces the new name, so
/// the name does not depend on reading `/proc` before a short process exits.
#[test]
fn a_rename_carries_the_new_name() {
    let mut data = vec![301_u32, 301];
    let mut name = [0_u8; 16];
    name[..3].copy_from_slice(b"cat");
    for chunk in name.chunks(4) {
        data.push(u32::from_ne_bytes(chunk.try_into().unwrap()));
    }
    let events = parse_datagram(&message(0x0000_0200, 0, 3, 1, &data));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, Kind::Comm { tgid: 301, name });
    assert_eq!(events[0].name(), Some("cat".to_owned()));
    assert!(events[0].is_process_level());
}

#[test]
fn truncated_or_lying_messages_yield_nothing_and_do_not_panic() {
    let good = message(FORK, 0, 1, 1, &[100, 100, 201, 201]);
    for cut in 0..good.len() {
        let _ = parse_datagram(&good[..cut]);
    }
    let mut lying = good.clone();
    lying[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
    assert!(parse_datagram(&lying).is_empty(), "a length past the end");
    let mut zero = good;
    zero[0..4].copy_from_slice(&0_u32.to_ne_bytes());
    assert!(
        parse_datagram(&zero).is_empty(),
        "a zero length must not loop"
    );
    assert!(parse_datagram(&[]).is_empty());
}

/// The kernel numbers messages per CPU. A gap in one CPU's numbers is
/// messages the socket dropped, and that is the loss the sensor reports.
#[test]
fn a_gap_in_one_cpus_sequence_is_counted_as_loss() {
    let mut tracker = SequenceTracker::default();
    assert_eq!(
        tracker.observe(0, 10),
        0,
        "the first number sets the baseline"
    );
    assert_eq!(tracker.observe(0, 11), 0);
    assert_eq!(tracker.observe(1, 500), 0, "each CPU has its own count");
    assert_eq!(tracker.observe(0, 15), 3, "12, 13 and 14 were lost");
    assert_eq!(tracker.observe(1, 501), 0);
    assert_eq!(tracker.lost(), 3);
    // A number going backwards is a reset, not a loss of four billion.
    assert_eq!(tracker.observe(0, 2), 0);
    assert_eq!(tracker.lost(), 3);
}

#[test]
fn the_subscription_is_the_kernels_listen_request() {
    let message = subscribe_message(4242);
    assert_eq!(message.len(), 40);
    assert_eq!(u32::from_ne_bytes(message[0..4].try_into().unwrap()), 40);
    assert_eq!(u16::from_ne_bytes(message[4..6].try_into().unwrap()), 3);
    assert_eq!(
        u32::from_ne_bytes(message[12..16].try_into().unwrap()),
        4242
    );
    assert_eq!(u32::from_ne_bytes(message[16..20].try_into().unwrap()), 1);
    assert_eq!(u32::from_ne_bytes(message[20..24].try_into().unwrap()), 1);
    assert_eq!(u16::from_ne_bytes(message[32..34].try_into().unwrap()), 4);
    assert_eq!(u32::from_ne_bytes(message[36..40].try_into().unwrap()), 1);
}
