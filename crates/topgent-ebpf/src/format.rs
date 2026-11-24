//! Where a tracepoint's fields sit, read from the kernel's own description.
//!
//! `/sys/kernel/tracing/events/<category>/<event>/format` lists each field
//! of the event's record as
//! `field:<type> <name>;  offset:<n>;  size:<n>;  signed:<0|1>;`.
//! Reading it at load time, rather than assuming one kernel's layout, is what
//! lets one probe run on many kernels.

/// Where one field sits in a tracepoint's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Field {
    /// Bytes from the start of the record.
    pub(crate) offset: u32,
    /// Bytes it takes.
    pub(crate) size: u32,
}

/// Finds the field called `name` in a format description.
pub(crate) fn field(format: &str, name: &str) -> Option<Field> {
    format.lines().find_map(|line| {
        let mut parts = line.trim().split(';').map(str::trim);
        let declaration = parts.next()?.strip_prefix("field:")?;
        // The name is the declaration's last word, without any array length:
        // `char comm[16]` is `comm`, `__data_loc char[] filename` is `filename`.
        let declared = declaration.rsplit(' ').next()?.split('[').next()?;
        if declared != name {
            return None;
        }
        let (mut offset, mut size) = (None, None);
        for part in parts {
            if let Some(value) = part.strip_prefix("offset:") {
                offset = value.parse().ok();
            } else if let Some(value) = part.strip_prefix("size:") {
                size = value.parse().ok();
            }
        }
        Some(Field {
            offset: offset?,
            size: size?,
        })
    })
}

/// A syscall enter record's arguments, in order: every field after
/// `__syscall_nr`, less the `__data_loc` copies (`__filename_val`) newer
/// kernels append, whose names begin with `__`.
pub(crate) fn syscall_args(format: &str) -> Option<Vec<Field>> {
    let mut seen_number = false;
    let mut args = Vec::new();
    for line in format.lines() {
        let Some(declaration) = line
            .trim()
            .split(';')
            .next()
            .and_then(|d| d.strip_prefix("field:"))
        else {
            continue;
        };
        let name = declaration.rsplit(' ').next()?.split('[').next()?;
        if name == "__syscall_nr" {
            seen_number = true;
        } else if seen_number && !name.starts_with("__") {
            args.push(field(line, name)?);
        }
    }
    seen_number.then_some(args)
}

#[cfg(test)]
mod tests {
    use super::{Field, field, syscall_args};

    /// As Kali's 6.19 kernel describes `syscalls/sys_enter_openat`.
    const OPENAT: &str = "name: sys_enter_openat
ID: 672
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;
	field:umode_t mode;	offset:40;	size:8;	signed:0;
	field:__data_loc char[] __filename_val;	offset:48;	size:4;	signed:0;

print fmt: \"dfd: 0x%08lx\"";

    #[test]
    fn a_syscall_record_gives_its_number_and_its_arguments_in_order() {
        assert_eq!(
            field(OPENAT, "__syscall_nr"),
            Some(Field { offset: 8, size: 4 })
        );
        let args = syscall_args(OPENAT).unwrap_or_default();
        let offsets: Vec<u32> = args.iter().map(|f| f.offset).collect();
        assert_eq!(
            offsets,
            [16, 24, 32, 40],
            "the path copy is not an argument"
        );
        assert!(args.iter().all(|f| f.size == 8));
        assert_eq!(syscall_args(NEWTASK), None, "not a syscall record");
    }

    /// As Kali's 6.19 kernel describes these events.
    const NEWTASK: &str = "name: task_newtask
ID: 145
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:pid_t pid;\toffset:8;\tsize:4;\tsigned:1;
\tfield:char comm[16];\toffset:12;\tsize:16;\tsigned:0;
\tfield:u64 clone_flags;\toffset:32;\tsize:8;\tsigned:0;
\tfield:short oom_score_adj;\toffset:40;\tsize:2;\tsigned:1;

print fmt: \"pid=%d comm=%s clone_flags=%llx oom_score_adj=%hd\"";

    const EXEC: &str = "\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;
\tfield:pid_t pid;\toffset:12;\tsize:4;\tsigned:1;
\tfield:pid_t old_pid;\toffset:16;\tsize:4;\tsigned:1;";

    #[test]
    fn plain_array_and_data_loc_fields_are_found() {
        assert_eq!(field(NEWTASK, "pid"), Some(Field { offset: 8, size: 4 }));
        assert_eq!(
            field(NEWTASK, "comm"),
            Some(Field {
                offset: 12,
                size: 16
            })
        );
        assert_eq!(
            field(NEWTASK, "clone_flags"),
            Some(Field {
                offset: 32,
                size: 8
            })
        );
        assert_eq!(field(EXEC, "filename"), Some(Field { offset: 8, size: 4 }));
    }

    #[test]
    fn a_name_matches_whole_words_only() {
        // `pid` must not match `old_pid` or `common_pid`.
        assert_eq!(
            field(EXEC, "pid"),
            Some(Field {
                offset: 12,
                size: 4
            })
        );
        assert_eq!(field(NEWTASK, "common"), None);
        assert_eq!(field(NEWTASK, "group_dead"), None);
    }

    #[test]
    fn a_line_missing_its_offset_or_size_is_not_trusted() {
        assert_eq!(field("\tfield:pid_t pid;\tsize:4;", "pid"), None);
        assert_eq!(field("\tfield:pid_t pid;\toffset:x;\tsize:4;", "pid"), None);
    }
}
