//! Bytes from the probe's ring buffers, decoded into records. The kernel
//! writes them, but a short or odd record must still be refused, never read
//! past or guessed at.
//!
//! Covers E12's variable-length syscall records: a record is accepted only
//! when every byte its lengths claim was sent.
#![no_main]
use libfuzzer_sys::fuzz_target;
use topgent_ebpf_common::{ArgvRecord, CwdRecord, PATH_LEN, ProcessEvent, SyscallRecord};

fuzz_target!(|data: &[u8]| {
    if let Some(record) = SyscallRecord::decode(data) {
        assert!(data.len() >= SyscallRecord::MIN_SIZE && data.len() <= SyscallRecord::SIZE);
        assert!(record.used_len() <= data.len(), "decoded past what was sent");
        for path in [record.path(), record.path2()].into_iter().flatten() {
            assert!(path.len() < PATH_LEN && !path.contains(&0));
        }
        if let Some(addr) = record.addr() {
            assert!(addr.len() <= record.addr.len());
        }
        let _ = (record.capabilities(), record.login_uid(), record.namespace());
    }
    if let Some(cwd) = CwdRecord::decode(data) {
        if let Some(parts) = cwd.components() {
            for part in parts {
                assert!(!part.is_empty() && !part.contains(&b'/') && !part.contains(&0));
            }
        }
    }
    if let Some(argv) = ArgvRecord::decode(data) {
        if let Some(args) = argv.argv() {
            assert!(args.count() <= topgent_ebpf_common::ARGV_MAX);
        }
    }
    if let Some(event) = ProcessEvent::decode(data) {
        let _ = (event.kind(), event.namespace(), event.login_uid());
    }
});
