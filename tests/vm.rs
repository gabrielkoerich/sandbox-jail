//! Boots real tart and lume VMs, so each test is ignored: `cargo test --test vm -- --ignored`.
//! `SANDBOX_JAIL_{TART,LUME}_{LINUX,MACOS}` pick other images

use sandbox_jail::vm::Vm;
use sandbox_jail::{Error, Policy};
use std::fs;
use std::path::{Path, PathBuf};

fn real(p: &Path) -> PathBuf {
    p.canonicalize().unwrap()
}

fn image(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.into())
}

/// Runs `script` in the guest from `dir`, its exit code and stdout
fn run(vm: &Vm, dir: &Path, script: &str) -> (Option<i32>, String) {
    let out = vm
        .command(dir, &["/bin/sh", "-c", script])
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    )
}

fn shares_reach_the_host_at_their_paths(
    start: fn(&str, &Policy) -> Result<Vm, Error>,
    image: &str,
) {
    let (w, r, secret) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let (w, r, secret) = (real(w.path()), real(r.path()), real(secret.path()));
    fs::write(r.join("f"), "host").unwrap();
    fs::write(secret.join("key"), "k").unwrap();
    let policy = Policy {
        writable: vec![w.clone()],
        readable: vec![r.clone()],
        ..Policy::default()
    };
    let vm = start(image, &policy).unwrap();

    let (code, out) = run(&vm, &w, "pwd -P >/dev/null; echo guest > from-guest; pwd");
    assert_eq!(code, Some(0));
    assert_eq!(out, w.to_string_lossy());
    assert_eq!(
        fs::read_to_string(w.join("from-guest")).unwrap().trim(),
        "guest"
    );

    let script = format!("cat {0}/f && ! echo x 2>/dev/null >{0}/nope", r.display());
    assert_eq!(run(&vm, &w, &script), (Some(0), "host".into()));
    assert!(!r.join("nope").exists());

    let script = format!("test ! -e {}/key", secret.display());
    assert_eq!(
        run(&vm, &w, &script).0,
        Some(0),
        "an unshared host dir is visible"
    );

    assert_eq!(run(&vm, &w, "exit 7").0, Some(7));
}

#[test]
#[ignore]
fn tart_linux_shares_reach_the_host_at_their_paths() {
    shares_reach_the_host_at_their_paths(
        Vm::tart,
        &image("SANDBOX_JAIL_TART_LINUX", "ghcr.io/cirruslabs/ubuntu:24.04"),
    );
}

#[test]
#[ignore]
fn tart_macos_shares_reach_the_host_at_their_paths() {
    shares_reach_the_host_at_their_paths(
        Vm::tart,
        &image(
            "SANDBOX_JAIL_TART_MACOS",
            "ghcr.io/cirruslabs/macos-tahoe-base:latest",
        ),
    );
}

#[test]
#[ignore]
fn lume_linux_shares_reach_the_host_at_their_paths() {
    shares_reach_the_host_at_their_paths(
        Vm::lume,
        &image("SANDBOX_JAIL_LUME_LINUX", "ubuntu-noble-vanilla_latest"),
    );
}

#[test]
#[ignore]
fn lume_macos_shares_reach_the_host_at_their_paths() {
    shares_reach_the_host_at_their_paths(
        Vm::lume,
        &image("SANDBOX_JAIL_LUME_MACOS", "macos-tahoe-vanilla_latest"),
    );
}

#[test]
#[ignore]
fn dropping_the_vm_deletes_the_clone() {
    let image = image("SANDBOX_JAIL_TART_LINUX", "ghcr.io/cirruslabs/ubuntu:24.04");
    let vm = Vm::tart(&image, &Policy::default()).unwrap();
    let name = vm.name().to_string();
    drop(vm);
    let list = std::process::Command::new("tart")
        .args(["list", "--quiet"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&list.stdout).contains(&name));
}
