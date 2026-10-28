//! Runs commands in the real OS sandbox and checks what the kernel lets through

use sandbox_jail::{Access, Backend, Policy, Sandbox};
use std::fs;
use std::path::{Path, PathBuf};

fn real(p: &Path) -> PathBuf {
    p.canonicalize().unwrap()
}

/// Runs `script` with `sh` under `policy`, its exit status and stderr
fn run(policy: Policy, script: &str) -> (bool, String) {
    let backend = Backend::detect().expect("an OS sandbox on this machine");
    let out = Sandbox::new(backend, policy)
        .unwrap()
        .command("/bin/sh")
        .args(["-c", script])
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn seatbelt() -> bool {
    cfg!(target_os = "macos")
}

#[test]
fn writes_only_in_writable() {
    let (w, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (w, outside) = (real(w.path()), real(outside.path()));
    let policy = Policy {
        writable: vec![w.clone()],
        ..Policy::default()
    };
    let (ok, err) = run(
        policy,
        &format!(
            "echo a > {0}/a && ! echo b > {1}/b",
            w.display(),
            outside.display()
        ),
    );
    assert!(ok, "{err}");
    assert!(w.join("a").exists());
    assert!(!outside.join("b").exists());
}

#[test]
fn read_only_wins_inside_writable() {
    let w = tempfile::tempdir().unwrap();
    let w = real(w.path());
    fs::create_dir(w.join("ro")).unwrap();
    let policy = Policy {
        writable: vec![w.clone()],
        read_only: vec![w.join("ro")],
        ..Policy::default()
    };
    let (ok, err) = run(
        policy,
        &format!("echo a > {0}/a && ! echo b > {0}/ro/b", w.display()),
    );
    assert!(ok, "{err}");
    assert!(!w.join("ro/b").exists());
}

/// A writable dir with `a/ro/f` read-only and `secret/key` hidden, and that policy
fn ruled_dir() -> (tempfile::TempDir, PathBuf, Policy) {
    let dir = tempfile::tempdir().unwrap();
    let w = real(dir.path());
    fs::create_dir_all(w.join("a/ro")).unwrap();
    fs::create_dir(w.join("secret")).unwrap();
    fs::write(w.join("a/ro/f"), "orig").unwrap();
    fs::write(w.join("secret/key"), "key").unwrap();
    let policy = Policy {
        writable: vec![w.clone()],
        read_only: vec![w.join("a/ro")],
        hidden: vec![w.join("secret")],
        ..Policy::default()
    };
    (dir, w, policy)
}

#[test]
fn renaming_a_parent_never_frees_a_read_only_path() {
    let (_dir, w, policy) = ruled_dir();
    let (ok, err) = run(
        policy,
        &format!(
            "mv {0}/a {0}/a2 2>/dev/null; ! echo x >> {0}/a/ro/f && ! echo x >> {0}/a2/ro/f",
            w.display()
        ),
    );
    assert!(ok, "{err}");
    let f = fs::read_to_string(w.join("a/ro/f")).or_else(|_| fs::read_to_string(w.join("a2/ro/f")));
    assert_eq!(f.unwrap(), "orig");
}

#[test]
fn renaming_never_frees_a_hidden_path() {
    let (_dir, w, policy) = ruled_dir();
    let (ok, err) = run(
        policy,
        &format!(
            "mv {0}/secret {0}/s2 2>/dev/null; mv {0} {0}.moved 2>/dev/null; \
             ! grep -qs key {0}/secret/key {0}/s2/key {0}.moved/secret/key",
            w.display()
        ),
    );
    assert!(ok, "{err}");
}

#[test]
fn a_hard_link_never_frees_a_ruled_file() {
    let (_dir, w, policy) = ruled_dir();
    let (ok, err) = run(
        policy,
        &format!(
            "ln {0}/a/ro/f {0}/l 2>/dev/null && echo y >> {0}/l; \
             ln {0}/secret/key {0}/k 2>/dev/null; ! grep -qs key {0}/k",
            w.display()
        ),
    );
    assert!(ok, "{err}");
    assert_eq!(fs::read_to_string(w.join("a/ro/f")).unwrap(), "orig");
}

#[test]
fn hidden_wins_inside_writable() {
    let w = tempfile::tempdir().unwrap();
    let w = real(w.path());
    fs::create_dir(w.join("secret")).unwrap();
    fs::write(w.join("secret/key"), "k").unwrap();
    fs::write(w.join("token"), "t").unwrap();
    let policy = Policy {
        writable: vec![w.clone()],
        hidden: vec![w.join("secret"), w.join("token")],
        ..Policy::default()
    };
    let (ok, err) = run(
        policy,
        &format!(
            "! cat {0}/secret/key && ! grep -q t {0}/token && cat /etc/hosts >/dev/null",
            w.display()
        ),
    );
    assert!(ok, "{err}");
}

#[test]
fn unreadable_but_for_readable() {
    let u = tempfile::tempdir().unwrap();
    let u = real(u.path());
    for d in ["ok", "no"] {
        fs::create_dir(u.join(d)).unwrap();
        fs::write(u.join(d).join("f"), d).unwrap();
    }
    let policy = Policy {
        unreadable: vec![u.clone()],
        readable: vec![u.join("ok")],
        ..Policy::default()
    };
    let (ok, err) = run(
        policy,
        &format!("cat {0}/ok/f && ! cat {0}/no/f", u.display()),
    );
    assert!(ok, "{err}");
}

#[test]
fn network_off_blocks_tcp() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connect = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
    let bash = |network| {
        let backend = Backend::detect().unwrap();
        let policy = Policy {
            network,
            ..Policy::default()
        };
        Sandbox::new(backend, policy)
            .unwrap()
            .command("/bin/bash")
            .args(["-c", &connect])
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(bash(true));
    assert!(!bash(false));
}

#[test]
fn own_signals_reach_no_other_process() {
    let me = std::process::id();
    let kill = format!("kill -0 {me}");
    assert!(
        !run(
            Policy {
                own_signals: true,
                ..Policy::default()
            },
            &kill
        )
        .0
    );

    // bwrap's pid namespace hides every other process, whatever the policy says
    if seatbelt() {
        assert!(run(Policy::default(), &kill).0);
    }
}

#[test]
fn seatbelt_denies_running_a_listed_binary() {
    if !seatbelt() {
        return;
    }

    let policy = Policy {
        no_exec: vec!["/usr/bin/true".into()],
        ..Policy::default()
    };
    let (ok, err) = run(policy, "! /usr/bin/true && /bin/echo still runs");
    assert!(ok, "{err}");
}

#[test]
fn seatbelt_keeps_a_pinned_dir_in_place_and_its_contents_writable() {
    if !seatbelt() {
        return;
    }

    let w = tempfile::tempdir().unwrap();
    let w = real(w.path());
    fs::create_dir(w.join("cache")).unwrap();
    let policy = Policy {
        writable: vec![w.clone()],
        pinned: vec![w.join("cache")],
        ..Policy::default()
    };
    let (ok, err) = run(
        policy,
        &format!(
            "echo a > {0}/cache/a && ! mv {0}/cache {0}/moved",
            w.display()
        ),
    );
    assert!(ok, "{err}");
    assert!(w.join("cache/a").exists());
}

#[test]
fn seatbelt_connects_only_to_listed_unix_sockets() {
    if !seatbelt() {
        return;
    }

    let (allowed, other) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (allowed, other) = (real(allowed.path()), real(other.path()));

    for dir in [&allowed, &other] {
        let listener = std::os::unix::net::UnixListener::bind(dir.join("s")).unwrap();
        // A connection left in the backlog makes the next one fail, so each is accepted and closed
        std::thread::spawn(move || listener.incoming().for_each(drop));
    }

    let policy = Policy {
        unix_sockets: Access::Only(vec![allowed.clone()]),
        ..Policy::default()
    };
    let (ok, err) = run(
        policy,
        &format!(
            "/usr/bin/nc -U {0}/s </dev/null && ! /usr/bin/nc -U {1}/s </dev/null",
            allowed.display(),
            other.display()
        ),
    );
    assert!(ok, "{err}");
}

#[test]
fn bwrap_scratch_starts_empty_and_leaves_the_host_dir_alone() {
    if seatbelt() {
        return;
    }

    let s = tempfile::tempdir().unwrap();
    let s = real(s.path());
    fs::write(s.join("host"), "h").unwrap();
    let policy = Policy {
        scratch: vec![s.clone()],
        ..Policy::default()
    };
    let (ok, err) = run(
        policy,
        &format!("! ls {0}/host && echo x > {0}/mine", s.display()),
    );
    assert!(ok, "{err}");
    assert!(s.join("host").exists());
    assert!(!s.join("mine").exists());
}

#[test]
fn overlay_writes_go_to_the_upper_layer() {
    let dir = tempfile::tempdir().unwrap();
    let d = real(dir.path());
    let supported = sandbox_jail::overlay_supported(&d);

    if seatbelt() {
        assert!(supported.is_err());
        return;
    }

    // overlayfs refuses layers on another overlay, such as a container's root. CI sets the variable
    if let Err(e) = supported {
        assert!(
            std::env::var("SANDBOX_JAIL_EXPECT_OVERLAY").as_deref() != Ok("1"),
            "SANDBOX_JAIL_EXPECT_OVERLAY is set but {e}"
        );
        eprintln!("skipped: {e}");
        return;
    }

    let [lower, upper, work] = ["lower", "upper", "work"].map(|n| d.join(n));
    for p in [&lower, &upper, &work] {
        fs::create_dir(p).unwrap();
    }
    fs::write(lower.join("base"), "b").unwrap();
    let policy = Policy {
        overlays: vec![sandbox_jail::Overlay {
            lower: lower.clone(),
            upper: upper.clone(),
            work,
        }],
        ..Policy::default()
    };
    let (ok, err) = run(
        policy,
        &format!("grep -q b {0}/base && echo n > {0}/new", lower.display()),
    );
    assert!(ok, "{err}");
    assert!(!lower.join("new").exists());
    assert!(upper.join("new").exists());
}

#[test]
fn seatbelt_looks_up_only_listed_mach_services() {
    if !seatbelt() {
        return;
    }

    // `id -un` asks opendirectoryd for the user's name, and prints the uid when it cannot
    let id = |cmd: &mut std::process::Command| {
        let out = cmd.arg("-un").output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let lookup = |names: Vec<String>| {
        let policy = Policy {
            mach_services: Access::Only(names),
            ..Policy::default()
        };
        id(&mut Sandbox::seatbelt(policy).unwrap().command("/usr/bin/id"))
    };
    let name = id(&mut std::process::Command::new("/usr/bin/id"));
    let basic = sandbox_jail::known::BASIC_MACH_SERVICES
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(lookup(basic), name);
    assert_ne!(lookup(vec![]), name);
}

#[cfg(target_os = "macos")]
#[test]
fn the_kernel_reports_the_sandbox_from_inside() {
    assert!(!sandbox_jail::macos::sandboxed());
    let exe = std::env::current_exe().unwrap();
    let out = Sandbox::seatbelt(Policy::default())
        .unwrap()
        .command(exe)
        .args([
            "--exact",
            "probe_sandboxed",
            "--include-ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sandboxed=true"), "{stdout}");
}

#[test]
#[ignore]
fn probe_sandboxed() {
    // Run by the test above, inside the sandbox
    #[cfg(target_os = "macos")]
    println!("sandboxed={}", sandbox_jail::macos::sandboxed());
}
