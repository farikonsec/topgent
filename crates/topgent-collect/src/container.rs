//! Container-boundary discovery for agent attribution.
//!
//! Linux cgroups provide the container identity for a running process. Docker
//! metadata then supplies the image identity, init pid, and active published
//! ports. Neither a generic runtime process name nor a user-controlled
//! container name is accepted as agent evidence.

#[cfg(any(target_os = "linux", test))]
use serde::Deserialize;
#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use topgent_facts::UnixMillis;

/// One active host-published TCP listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
    /// Host bind address, or `*` when Docker binds all interfaces.
    pub host: String,
    /// Host TCP port.
    pub port: u16,
}

/// Sanitized runtime metadata for one recognised agent container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    /// Runtime container identity from the Linux cgroup.
    pub id: String,
    /// Container init process on the host.
    pub init_pid: u32,
    /// Process start time of the init process.
    pub started_at: UnixMillis,
    /// Recognised agent family established from image provenance.
    pub family: &'static str,
    /// Active published TCP listeners.
    pub published_ports: Vec<PublishedPort>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerInspect {
    id: String,
    config: DockerConfig,
    state: DockerState,
    network_settings: DockerNetworkSettings,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerConfig {
    image: String,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerState {
    running: bool,
    pid: u32,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerNetworkSettings {
    #[serde(default)]
    ports: BTreeMap<String, Option<Vec<DockerPortBinding>>>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerPortBinding {
    host_ip: String,
    host_port: String,
}

/// Extract a Docker-style 64-hex container identity from cgroup text.
///
/// Exact token length prevents scope names, truncated IDs, and attacker-chosen
/// substrings from becoming identities.
#[must_use]
pub fn container_id_from_cgroup(text: &str) -> Option<String> {
    text.split(|character: char| !character.is_ascii_hexdigit())
        .find(|token| token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
}

/// Whether a value is one exact full-length lowercase/uppercase container ID.
#[must_use]
pub fn valid_container_id(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

#[cfg(any(target_os = "linux", test))]
fn parse_inspect(
    text: &str,
    expected_id: &str,
    starts: &BTreeMap<u32, UnixMillis>,
) -> Option<ContainerInfo> {
    let inspect: DockerInspect = serde_json::from_str(text).ok()?;
    if !inspect.state.running
        || inspect.id.to_ascii_lowercase() != expected_id
        || inspect.state.pid == 0
    {
        return None;
    }
    let family = crate::signatures::recognise_container_image(&inspect.config.image)?;
    let started_at = *starts.get(&inspect.state.pid)?;
    let mut published_ports = Vec::new();
    for (container_port, bindings) in inspect.network_settings.ports {
        if !container_port.to_ascii_lowercase().ends_with("/tcp") {
            continue;
        }
        for binding in bindings.unwrap_or_default() {
            let Ok(port) = binding.host_port.parse::<u16>() else {
                continue;
            };
            published_ports.push(PublishedPort {
                host: match binding.host_ip.as_str() {
                    "" | "0.0.0.0" | "::" => "*".to_owned(),
                    value => value.to_owned(),
                },
                port,
            });
        }
    }
    published_ports.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
    published_ports.dedup();
    Some(ContainerInfo {
        id: expected_id.to_owned(),
        init_pid: inspect.state.pid,
        started_at,
        family: family.id.as_str(),
        published_ports,
    })
}

/// Discover recognised agent containers from the supplied process snapshot.
///
/// An unavailable runtime, unreadable cgroup, or denied daemon query yields no
/// container evidence; ordinary process collection remains useful.
#[must_use]
pub fn snapshot(processes: &[crate::process::ProcInfo]) -> Vec<ContainerInfo> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = processes;
        Vec::new()
    }
    #[cfg(target_os = "linux")]
    {
        let starts = processes
            .iter()
            .map(|process| (process.pid, process.started_at))
            .collect::<BTreeMap<_, _>>();
        let ids = processes
            .iter()
            .filter_map(|process| {
                std::fs::read_to_string(format!("/proc/{}/cgroup", process.pid)).ok()
            })
            .filter_map(|text| container_id_from_cgroup(&text))
            .collect::<BTreeSet<_>>();
        ids.into_iter()
            .filter_map(|id| {
                let mut docker = crate::tool::DOCKER.command().ok()?;
                let output = docker
                    .args(["container", "inspect", id.as_str()])
                    .output()
                    .ok()?;
                if !output.status.success() || output.stdout.len() > 4 * 1_024 * 1_024 {
                    return None;
                }
                let value: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).ok()?;
                let item = value.first()?;
                parse_inspect(&item.to_string(), &id, &starts)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use super::{container_id_from_cgroup, parse_inspect};
    use std::collections::BTreeMap;
    use topgent_facts::UnixMillis;

    const ID: &str = "c39aba1b5d244ecab73a42483cd575c6ab77ad91a26571c87d1014396d055d3b";

    #[test]
    fn cgroup_identity_requires_one_exact_full_length_hex_token() {
        assert_eq!(
            container_id_from_cgroup(&format!("0::/system.slice/docker-{ID}.scope\n")),
            Some(ID.to_owned())
        );
        assert_eq!(container_id_from_cgroup("0::/docker/c39aba1b5d24\n"), None);
        assert_eq!(
            container_id_from_cgroup(&format!("0::/docker/{ID}a\n")),
            None
        );
    }

    #[test]
    fn inspect_requires_running_matching_image_provenance_and_active_init() {
        let starts = BTreeMap::from([(3931, UnixMillis(123_000))]);
        let json = format!(
            r#"{{"Id":"{ID}","Config":{{"Image":"docker.openhands.dev/openhands/openhands:latest"}},"State":{{"Running":true,"Pid":3931}},"NetworkSettings":{{"Ports":{{"3000/tcp":[{{"HostIp":"0.0.0.0","HostPort":"3000"}},{{"HostIp":"::","HostPort":"3000"}}],"3000/udp":[{{"HostIp":"","HostPort":"3000"}}]}}}}}}"#
        );
        let info = parse_inspect(&json, ID, &starts).expect("recognised fixture");
        assert_eq!(info.family, "openhands");
        assert_eq!(info.init_pid, 3931);
        assert_eq!(info.published_ports.len(), 1);
        assert_eq!(info.published_ports[0].host, "*");
        assert_eq!(info.published_ports[0].port, 3000);

        assert!(parse_inspect(&json.replace(":latest", "-decoy:latest"), ID, &starts).is_none());
        assert!(
            parse_inspect(
                &json.replace("\"Running\":true", "\"Running\":false"),
                ID,
                &starts
            )
            .is_none()
        );
    }
}
