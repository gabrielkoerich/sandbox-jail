use crate::{Error, Policy, real};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The AppArmor profile that lets only bwrap create user namespaces, from apparmor's extra profiles
const BWRAP_PROFILE: &str = "/etc/apparmor.d/bwrap-userns-restrict";

pub(crate) fn detect() -> Result<(), Error> {
    let ran = Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--unshare-pid",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match ran {
        Ok(s) if s.success() => Ok(()),
        Err(_) => Err(Error::Unavailable(
            "bubblewrap is missing: `sudo apt install bubblewrap` or `sudo dnf install bubblewrap`"
                .into(),
        )),
        Ok(_) => Err(Error::Unavailable(userns_fix(
            fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
                .ok()
                .as_deref(),
            Path::new(BWRAP_PROFILE).exists(),
        ))),
    }
}

/**
 * Why bwrap could not make its user namespace, and the fix. Ubuntu 23.10 and later restrict
 * unprivileged user namespaces with AppArmor, and a profile for bwrap alone lifts that for it
 **/
fn userns_fix(restricted: Option<&str>, profile: bool) -> String {
    let load = format!("sudo apparmor_parser -r {BWRAP_PROFILE}");

    match (restricted.map(str::trim), profile) {
        (Some("1"), false) => format!(
            "AppArmor stops bwrap from creating user namespaces. Allow bwrap alone: `sudo apt install apparmor-profiles && sudo cp /usr/share/apparmor/extra-profiles/bwrap-userns-restrict /etc/apparmor.d/ && {load}`"
        ),
        (Some("1"), true) => format!(
            "AppArmor stops bwrap from creating user namespaces, and {BWRAP_PROFILE} is not loaded: `{load}`"
        ),
        _ => "bwrap cannot create a user namespace: check that `sysctl user.max_user_namespaces` is above 0 and bwrap is not setuid".into(),
    }
}

static PROBES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn overlay_supported(dir: &Path) -> Result<(), Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::Unavailable("only bwrap mounts an overlay".into()));
    }

    let n = PROBES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let probe = dir.join(format!(".sandbox-jail-probe-{}-{n}", std::process::id()));
    // Only a probe dir this call made is ever removed
    fs::create_dir(&probe).map_err(|e| Error::Unavailable(format!("{}: {e}", probe.display())))?;
    let [lower, upper, work] = ["lower", "upper", "work"].map(|d| probe.join(d));
    let ran = [&lower, &upper, &work]
        .into_iter()
        .try_for_each(fs::create_dir)
        .map_err(|e| e.to_string())
        .and_then(|_| {
            Command::new("bwrap")
                .args(["--ro-bind", "/", "/", "--dev", "/dev", "--overlay-src"])
                .arg(&lower)
                .arg("--overlay")
                .args([&upper, &work, &lower])
                .arg("true")
                .stdin(Stdio::null())
                .output()
                .map_err(|e| format!("bwrap: {e}"))
        });
    remove_tree(&probe);
    let out = ran.map_err(Error::Unavailable)?;

    if out.status.success() {
        return Ok(());
    }

    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();

    if err.contains("--overlay-src") {
        let version = Command::new("bwrap")
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .map(|l| l.trim().to_string())
            })
            .unwrap_or_else(|| "this bwrap".into());
        return Err(Error::Unavailable(format!(
            "{version} has no --overlay-src"
        )));
    }

    Err(Error::Unavailable(format!(
        "bwrap could not mount an overlay: {err}"
    )))
}

/// Removes a tree with read-only directories in it, as overlayfs leaves its work dir
fn remove_tree(dir: &Path) {
    // The system's chmod, never one earlier on PATH
    let chmod = ["/bin/chmod", "/usr/bin/chmod"]
        .into_iter()
        .find(|c| Path::new(c).exists())
        .unwrap_or("chmod");
    let _ = Command::new(chmod)
        .arg("-R")
        .arg("u+rwx")
        .arg(dir)
        .stderr(Stdio::null())
        .status();
    let _ = fs::remove_dir_all(dir);
}

fn is_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
}

fn bind(args: &mut Vec<OsString>, flag: &str, path: &PathBuf) {
    args.extend([flag.into(), path.into(), path.into()]);
}

/**
 * `bwrap` arguments. The root read-only, then an empty directory over each unreadable one, the
 * readable paths, the writable ones, the read-only ones inside those, then hidden paths, so a hidden
 * path wins over everything as it does under Seatbelt. The unreadable directories turn read-only
 * last, once every mount point in them exists
 **/
pub(crate) fn argv(p: &Policy) -> Result<Vec<OsString>, Error> {
    if !p.pinned.is_empty() {
        return Err(Error::Policy(
            "bwrap cannot keep a path in place while what is inside it stays writable".into(),
        ));
    }

    if !p.no_exec.is_empty() {
        return Err(Error::Policy(
            "bwrap cannot deny running a binary, and setuid binaries already run without privileges under it".into(),
        ));
    }

    if let Some(w) = p.writable.iter().find(|w| !w.exists()) {
        return Err(Error::Policy(format!(
            "{}: bwrap binds a writable path, so it must exist",
            w.display()
        )));
    }

    // A bind mounts after the scratch tmpfs, so one around it would show the host's files there
    let bound = p
        .writable
        .iter()
        .chain(&p.readable)
        .chain(&p.read_only)
        .chain(p.overlays.iter().map(|o| &o.lower));

    for b in bound {
        if let Some(s) = p.scratch.iter().find(|s| s.starts_with(b)) {
            return Err(Error::Policy(format!(
                "{}: a scratch dir inside the bound path {} would show its files",
                s.display(),
                b.display()
            )));
        }
    }

    let mut args: Vec<OsString> = [
        "bwrap",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--unshare-pid",
        "--die-with-parent",
        "--new-session",
    ]
    .map(Into::into)
    .to_vec();

    if !p.network {
        args.push("--unshare-net".into());
    }

    let unreadable: Vec<&PathBuf> = p.unreadable.iter().filter(|d| is_dir(d)).collect();
    let scratch: Vec<&PathBuf> = p.scratch.iter().filter(|d| is_dir(d)).collect();

    for dir in unreadable.iter().chain(&scratch) {
        args.extend(["--tmpfs".into(), (*dir).into()]);
    }

    // systemd-resolved links /etc/resolv.conf into /run
    let resolv = real(Path::new("/etc/resolv.conf"));

    if resolv.exists()
        && unreadable
            .iter()
            .chain(&scratch)
            .any(|d| resolv.starts_with(d))
    {
        bind(&mut args, "--ro-bind", &resolv);
    }

    for path in p.readable.iter().filter(|p| p.exists()) {
        bind(&mut args, "--ro-bind", path);
    }

    for path in &p.writable {
        bind(&mut args, "--bind", path);
    }

    for path in p.read_only.iter().filter(|p| p.exists()) {
        bind(&mut args, "--ro-bind", path);
    }

    for o in &p.overlays {
        args.extend([
            "--overlay-src".into(),
            o.lower.clone().into(),
            "--overlay".into(),
        ]);
        args.extend([&o.upper, &o.work, &o.lower].map(|p| p.clone().into()));
    }

    for path in &p.hidden {
        match fs::metadata(path) {
            Ok(m) if m.is_dir() => args.extend(["--tmpfs".into(), path.into()]),
            Ok(_) => args.extend(["--ro-bind".into(), "/dev/null".into(), path.into()]),
            Err(_) => {}
        }
    }

    for dir in unreadable {
        args.extend(["--remount-ro".into(), dir.into()]);
    }

    args.push("--".into());
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(args: &[OsString], flag: &str, path: &Path) -> usize {
        args.windows(2)
            .position(|w| w[0] == flag && w[1] == path.as_os_str())
            .unwrap_or_else(|| panic!("{flag} {} in {args:?}", path.display()))
    }

    #[test]
    fn hidden_paths_mount_after_the_writable_ones() {
        let dir = tempfile::tempdir().unwrap();
        let w = real(dir.path());
        let secret = w.join("secret");
        fs::create_dir(&secret).unwrap();
        let policy = Policy {
            writable: vec![w.clone()],
            hidden: vec![secret.clone()],
            ..Policy::default()
        };
        let args = argv(&policy).unwrap();
        assert!(pos(&args, "--bind", &w) < pos(&args, "--tmpfs", &secret));
    }

    #[test]
    fn scratch_dirs_are_an_empty_tmpfs_that_stays_writable() {
        let dir = tempfile::tempdir().unwrap();
        let s = real(dir.path());
        let policy = Policy {
            scratch: vec![s.clone()],
            ..Policy::default()
        };
        let args = argv(&policy).unwrap();
        pos(&args, "--tmpfs", &s);
        assert!(
            !args
                .windows(2)
                .any(|w| w[0] == "--remount-ro" && w[1] == s.as_os_str())
        );
    }

    #[test]
    fn unreadable_dirs_turn_read_only_after_every_mount() {
        let dir = tempfile::tempdir().unwrap();
        let u = real(dir.path());
        let ok = u.join("ok");
        fs::create_dir(&ok).unwrap();
        let policy = Policy {
            unreadable: vec![u.clone()],
            readable: vec![ok.clone()],
            ..Policy::default()
        };
        let args = argv(&policy).unwrap();
        assert!(pos(&args, "--tmpfs", &u) < pos(&args, "--ro-bind", &ok));
        assert!(pos(&args, "--ro-bind", &ok) < pos(&args, "--remount-ro", &u));
    }

    #[test]
    fn refuses_what_it_cannot_enforce() {
        for policy in [
            Policy {
                pinned: vec!["/p".into()],
                ..Policy::default()
            },
            Policy {
                no_exec: vec!["/usr/bin/true".into()],
                ..Policy::default()
            },
            Policy {
                writable: vec!["/does/not/exist".into()],
                ..Policy::default()
            },
        ] {
            assert!(matches!(argv(&policy), Err(Error::Policy(_))), "{policy:?}");
        }
    }

    #[test]
    fn refuses_a_scratch_dir_a_bind_would_cover() {
        let dir = tempfile::tempdir().unwrap();
        let w = real(dir.path());
        fs::create_dir(w.join("s")).unwrap();
        for scratch in [w.clone(), w.join("s")] {
            let policy = Policy {
                writable: vec![w.clone()],
                scratch: vec![scratch],
                ..Policy::default()
            };
            assert!(matches!(argv(&policy), Err(Error::Policy(_))), "{policy:?}");
        }

        // A writable dir inside a scratch dir binds over the tmpfs, such as a jail under /tmp
        let policy = Policy {
            writable: vec![w.join("s")],
            scratch: vec![w.clone()],
            ..Policy::default()
        };
        let args = argv(&policy).unwrap();
        assert!(pos(&args, "--tmpfs", &w) < pos(&args, "--bind", &w.join("s")));
    }

    #[test]
    fn names_the_apparmor_fix() {
        assert!(userns_fix(Some("1\n"), false).contains("apparmor-profiles"));
        assert!(userns_fix(Some("1"), true).contains("apparmor_parser -r"));
        assert!(userns_fix(None, false).contains("max_user_namespaces"));
    }
}
