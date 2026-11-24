//! Builds the kernel probe and hands it to this crate, when asked to.
//!
//! Runs only for a Linux target with the `probe` feature on; otherwise it does
//! nothing and the crate compiles without a probe.
//!
//! Why not `aya-build`: it runs cargo inside this workspace, so the probe would
//! have to be a workspace member, and every `cargo test --workspace` on stable
//! would then try to build a `no_std` kernel crate. Here the probe is its own
//! crate outside the workspace. Its toolchain is pinned by its own
//! `rust-toolchain.toml`, which applies because cargo runs in its directory
//! with a clean environment.

use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Where the probe crate lives, relative to this crate.
const PROBE_DIR: &str = "../topgent-ebpf-probe";
/// Every input the probe build reads, relative to this crate. The probe
/// compiles the shared layout crate too, so a change there rebuilds it.
const PROBE_INPUTS: [&str; 6] = [
    "../topgent-ebpf-probe/src",
    "../topgent-ebpf-probe/Cargo.toml",
    "../topgent-ebpf-probe/Cargo.lock",
    "../topgent-ebpf-probe/rust-toolchain.toml",
    "../topgent-ebpf-common/src",
    "../topgent-ebpf-common/Cargo.toml",
];
/// The probe's binary name, and the file name it is copied to in `OUT_DIR`.
const PROBE_BIN: &str = "topgent-probe";
/// The parent environment a nested cargo may see. Everything else (`RUSTC`,
/// `RUSTUP_TOOLCHAIN`, `RUSTFLAGS`, `CARGO_TARGET_DIR`, …) belongs to the
/// outer build and would silently override the probe's pinned toolchain.
const KEPT_ENV: [&str; 4] = ["PATH", "HOME", "RUSTUP_HOME", "CARGO_HOME"];

fn main() -> Result<(), String> {
    println!("cargo::rerun-if-changed=build.rs");
    let linux = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "linux");
    if !linux || env::var_os("CARGO_FEATURE_PROBE").is_none() {
        return Ok(());
    }

    let manifest_dir = PathBuf::from(var("CARGO_MANIFEST_DIR")?);
    let probe_dir = manifest_dir.join(PROBE_DIR);
    for input in PROBE_INPUTS {
        println!(
            "cargo::rerun-if-changed={}",
            manifest_dir.join(input).display()
        );
    }

    let out_dir = PathBuf::from(var("OUT_DIR")?);
    let target = bpf_target(&var("CARGO_CFG_TARGET_ENDIAN")?)?;
    let arch = var("CARGO_CFG_TARGET_ARCH")?;
    let target_dir = out_dir.join("probe-target");

    build(&probe_dir, target, &arch, &target_dir)?;

    let built = target_dir.join(target).join("release").join(PROBE_BIN);
    fs::copy(&built, out_dir.join(PROBE_BIN))
        .map_err(|e| format!("could not copy {}: {e}", built.display()))?;
    Ok(())
}

/// The BPF target matching the host's byte order.
fn bpf_target(endian: &str) -> Result<&'static str, String> {
    match endian {
        "little" => Ok("bpfel-unknown-none"),
        "big" => Ok("bpfeb-unknown-none"),
        other => Err(format!("no BPF target for byte order {other:?}")),
    }
}

/// Runs the probe's own cargo, on its pinned toolchain.
fn build(probe_dir: &Path, target: &str, arch: &str, target_dir: &Path) -> Result<(), String> {
    let mut cargo = Command::new("cargo");
    cargo.current_dir(probe_dir).env_clear();
    for key in KEPT_ENV {
        if let Some(value) = env::var_os(key) {
            cargo.env(key, value);
        }
    }
    cargo
        .args(["build", "--release", "--locked", "--target", target])
        .args(["-Z", "build-std=core"])
        .arg("--target-dir")
        .arg(target_dir)
        // `bpf_target_arch` tells aya-ebpf which architecture's kernel
        // structs to use; `--btf` makes bpf-linker emit BTF for CO-RE.
        // Fields are separated by 0x1f, as cargo defines for this variable.
        .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags(arch));

    let status = cargo
        .status()
        .map_err(|e| format!("could not run cargo for the probe: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "the probe did not build ({status}); cargo's reason is above. It needs the \
             toolchain named in {PROBE_DIR}/rust-toolchain.toml, `bpf-linker` on PATH, and \
             a current {PROBE_DIR}/Cargo.lock; see docs/ebpf/PLAN.md"
        ))
    }
}

fn encoded_rustflags(arch: &str) -> OsString {
    [
        format!("--cfg=bpf_target_arch=\"{arch}\""),
        "-Cdebuginfo=2".to_owned(),
        "-Clink-arg=--btf".to_owned(),
    ]
    .join("\x1f")
    .into()
}

fn var(key: &str) -> Result<String, String> {
    env::var(key).map_err(|e| format!("{key}: {e}"))
}
