//! What the container runtime says about a container: its image, whether it
//! is privileged, its Kubernetes pod, and its own accounts.
//!
//! The behaviour rules ask about the container an event ran in, and the
//! kernel names only its id (docs/ebpf/PLAN.md, E7). The rest is the
//! runtime's to say, and only while the container exists: one started with
//! `--rm` is gone within seconds. So the collector asks the moment a line
//! first names a container, on a worker thread, and keeps the answer by id.
//!
//! Nothing here is guessed. A container the runtime cannot be asked about,
//! or has already forgotten, has no context, and its fields stay unknown.

use std::collections::BTreeMap;

/// Most accounts kept from one container's `/etc/passwd`.
const MAX_ACCOUNTS: usize = 4_096;
/// Most mount destinations retained from one runtime response.
const MAX_MOUNTS: usize = 1_024;

/// One container, as its runtime described it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerContext {
    /// The image's repository, without tag or digest: `docker.io/library/nginx`.
    pub image: Option<String>,
    /// Whether it runs privileged.
    pub privileged: Option<bool>,
    /// Its Kubernetes namespace and pod, from the labels a kubelet sets.
    /// `None` for a container no kubelet started.
    pub k8s_namespace: Option<String>,
    /// See [`ContainerContext::k8s_namespace`].
    pub k8s_pod: Option<String>,
    /// Container-visible mount destinations from the runtime. `None` means
    /// the runtime did not provide a mount inventory; an empty vector means it
    /// did and the container has none.
    pub mounts: Option<Vec<String>>,
    /// Its own accounts, uid to name, from its `/etc/passwd`. `None` when
    /// that file could not be read.
    pub accounts: Option<BTreeMap<u32, String>>,
}

/// An image reference without its tag or digest. A registry port
/// (`host:5000/name`) is part of the repository, not a tag.
#[must_use]
pub fn repository(image: &str) -> String {
    let untagged = image.split('@').next().unwrap_or(image);
    match untagged.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => repo.to_owned(),
        _ => untagged.to_owned(),
    }
}

/// Uid to name from an `/etc/passwd` body. Bounded; malformed lines skipped.
#[must_use]
pub fn parse_passwd(text: &str) -> BTreeMap<u32, String> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?.trim();
            let uid = fields.nth(1)?.trim().parse().ok()?;
            (!name.is_empty() && name.len() <= 64).then(|| (uid, name.to_owned()))
        })
        .take(MAX_ACCOUNTS)
        .collect()
}

/// One element of `docker container inspect` output: the context, and the
/// container's init pid on the host (zero when it is not running).
#[must_use]
pub fn parse_inspect(item: &serde_json::Value) -> Option<(ContainerContext, u32)> {
    let text = |value: Option<&serde_json::Value>| {
        value
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 512)
            .map(str::to_owned)
    };
    let config = item.get("Config")?;
    let labels = config.get("Labels");
    let label = |name: &str| text(labels.and_then(|l| l.get(name)));
    let context = ContainerContext {
        image: text(config.get("Image")).map(|image| repository(&image)),
        privileged: item
            .get("HostConfig")
            .and_then(|h| h.get("Privileged"))
            .and_then(serde_json::Value::as_bool),
        k8s_namespace: label("io.kubernetes.pod.namespace"),
        k8s_pod: label("io.kubernetes.pod.name"),
        mounts: item
            .get("Mounts")
            .and_then(serde_json::Value::as_array)
            .map(|mounts| {
                mounts
                    .iter()
                    .filter_map(|mount| text(mount.get("Destination")))
                    .filter(|destination| destination.starts_with('/'))
                    .take(MAX_MOUNTS)
                    .collect()
            }),
        accounts: None,
    };
    let pid = item
        .get("State")
        .and_then(|s| s.get("Pid"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .unwrap_or(0);
    Some((context, pid))
}

#[cfg(target_os = "linux")]
pub use running::{context, notice};

#[cfg(not(target_os = "linux"))]
/// No runtime to ask off Linux.
#[must_use]
pub fn context(_id: &str) -> Option<std::sync::Arc<ContainerContext>> {
    None
}

#[cfg(not(target_os = "linux"))]
/// No runtime to ask off Linux.
pub const fn notice(_id: &str) {}

#[cfg(target_os = "linux")]
mod running {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};

    use super::{ContainerContext, parse_inspect, parse_passwd};
    use crate::container::valid_container_id;

    /// Most containers remembered, and most asked about at once.
    const MAX_KNOWN: usize = 1_024;
    const MAX_ASKING: usize = 4;
    /// Largest inspect output and `/etc/passwd` read.
    const MAX_BYTES: usize = 4 * 1_024 * 1_024;

    enum Slot {
        Asking,
        Known(Arc<ContainerContext>),
        /// The runtime could not say: not Docker's, already gone, or no
        /// runtime to ask.
        Unknown,
    }

    fn cache() -> &'static Mutex<HashMap<String, Slot>> {
        static CACHE: OnceLock<Mutex<HashMap<String, Slot>>> = OnceLock::new();
        CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    static ASKING: AtomicUsize = AtomicUsize::new(0);

    /// A line named container `id`: ask its runtime about it, once, now,
    /// while it still exists. Returns at once; the answer arrives later.
    pub fn notice(id: &str) {
        if !valid_container_id(id) {
            return;
        }
        {
            let mut cache = cache().lock().unwrap_or_else(PoisonError::into_inner);
            if cache.contains_key(id) {
                return;
            }
            if ASKING.load(Ordering::Relaxed) >= MAX_ASKING {
                // Busy: the next line naming it will ask again.
                return;
            }
            if cache.len() >= MAX_KNOWN {
                cache.retain(|_, slot| matches!(slot, Slot::Asking));
            }
            cache.insert(id.to_owned(), Slot::Asking);
        }
        ASKING.fetch_add(1, Ordering::Relaxed);
        let id = id.to_owned();
        let asked = std::thread::Builder::new()
            .name("topgent-container".to_owned())
            .spawn(move || {
                let slot = ask(&id).map_or(Slot::Unknown, |c| Slot::Known(Arc::new(c)));
                cache()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(id, slot);
                ASKING.fetch_sub(1, Ordering::Relaxed);
            });
        if asked.is_err() {
            ASKING.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// What the runtime said about container `id`, when it said anything.
    #[must_use]
    pub fn context(id: &str) -> Option<Arc<ContainerContext>> {
        match cache()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
        {
            Some(Slot::Known(context)) => Some(Arc::clone(context)),
            _ => None,
        }
    }

    fn ask(id: &str) -> Option<ContainerContext> {
        let output = crate::tool::DOCKER
            .command()
            .ok()?
            .args(["container", "inspect", id])
            .output()
            .ok()?;
        if !output.status.success() || output.stdout.len() > MAX_BYTES {
            return None;
        }
        let value: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).ok()?;
        let (mut context, pid) = parse_inspect(value.first()?)?;
        // The container's own accounts, through its init process's root,
        // while it runs. Needs the privilege to read another process's root.
        if pid > 0 {
            context.accounts = std::fs::read(format!("/proc/{pid}/root/etc/passwd"))
                .ok()
                .filter(|bytes| bytes.len() <= MAX_BYTES)
                .map(|bytes| parse_passwd(&String::from_utf8_lossy(&bytes)));
        }
        Some(context)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{parse_inspect, parse_passwd, repository};

    #[test]
    fn a_repository_has_no_tag_or_digest_but_keeps_a_registry_port() {
        assert_eq!(repository("forgex:latest"), "forgex");
        assert_eq!(
            repository("docker.io/library/nginx:1.27"),
            "docker.io/library/nginx"
        );
        assert_eq!(
            repository("registry:5000/team/app"),
            "registry:5000/team/app"
        );
        assert_eq!(
            repository("registry:5000/team/app:v2"),
            "registry:5000/team/app"
        );
        assert_eq!(repository("alpine@sha256:abc"), "alpine");
    }

    #[test]
    fn accounts_are_read_by_uid_and_bad_lines_are_skipped() {
        let accounts = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n# comment\nappuser:x:999:999::/home/appuser:/bin/sh\nbroken\n:x:5:5::/:/bin/sh\n",
        );
        assert_eq!(accounts.get(&0).map(String::as_str), Some("root"));
        assert_eq!(accounts.get(&999).map(String::as_str), Some("appuser"));
        assert_eq!(accounts.len(), 2);
    }

    #[test]
    fn inspect_gives_image_privilege_pod_and_pid() {
        let item: serde_json::Value = serde_json::from_str(
            r#"{"Config":{"Image":"forgex:latest","Labels":{"io.kubernetes.pod.namespace":"lab","io.kubernetes.pod.name":"agent-0"}},
                "HostConfig":{"Privileged":true},"State":{"Running":true,"Pid":4321}}"#,
        )
        .expect("json");
        let (context, pid) = parse_inspect(&item).expect("parsed");
        assert_eq!(context.image.as_deref(), Some("forgex"));
        assert_eq!(context.privileged, Some(true));
        assert_eq!(context.k8s_namespace.as_deref(), Some("lab"));
        assert_eq!(context.k8s_pod.as_deref(), Some("agent-0"));
        assert_eq!(pid, 4321);
        let plain: serde_json::Value = serde_json::from_str(
            r#"{"Config":{"Image":"alpine","Labels":null},"State":{"Pid":0}}"#,
        )
        .expect("json");
        let (context, pid) = parse_inspect(&plain).expect("parsed");
        assert_eq!((context.k8s_pod, context.privileged, pid), (None, None, 0));
    }

    #[test]
    fn inspect_keeps_only_bounded_absolute_mount_destinations() {
        let item: serde_json::Value = serde_json::from_str(
            r#"{"Config":{"Image":"alpine","Labels":null},"State":{"Pid":1},"Mounts":[{"Destination":"/proc-extra"},{"Destination":"/var/run/docker.sock"},{"Destination":"relative"}]}"#,
        )
        .expect("json");
        let (context, _) = parse_inspect(&item).expect("parsed");
        assert_eq!(
            context.mounts,
            Some(vec![
                "/proc-extra".to_owned(),
                "/var/run/docker.sock".to_owned()
            ])
        );
    }
}
