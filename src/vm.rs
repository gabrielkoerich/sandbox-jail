//! Run commands in a throwaway VM: a clone of the image, booted headless with the policy's dirs
//! shared at their host paths, and deleted when the handle drops

use crate::{Access, Error, Policy, real};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BOOT_TIMEOUT: Duration = Duration::from_secs(300);

/// Where the Linux guest mounts the virtiofs share that holds every shared dir
const GUEST_MOUNT: &str = "/mnt/sandbox-jail";

/// The macOS guest mounts the shares itself, one dir per share name
const GUEST_VOLUME: &str = "/Volumes/My Shared Files";

static CLONES: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guest {
    Linux,
    Macos,
}

/// A running clone of an image. Dropping it stops and deletes the clone
#[derive(Debug)]
pub struct Vm {
    name: String,
    run: Option<Child>,
}

/// A host dir shared into the guest, and whether the guest may write it
struct Share {
    name: String,
    path: PathBuf,
    writable: bool,
}

impl Vm {
    /**
     * Boots a tart clone of `image` with the policy's dirs shared. The image must have the Tart
     * Guest Agent, as every non-vanilla Cirrus Labs image does, and passwordless sudo, which
     * mounting the shares at their host paths needs
     **/
    pub fn tart(image: &str, policy: &Policy) -> Result<Self, Error> {
        let shares = shares(policy)?;

        if Command::new("tart").arg("--version").output().is_err() {
            return Err(Error::Unavailable(
                "tart is missing: `brew install cirruslabs/cli/tart`".into(),
            ));
        }

        let n = CLONES.fetch_add(1, Ordering::Relaxed);
        let name = format!("sandbox-jail-{}-{n}", std::process::id());
        tart(&["clone", image, &name])?;
        // From here on Drop deletes the clone, whatever fails next
        let mut vm = Self { name, run: None };

        let mut run = Command::new("tart");
        run.args(["run", "--no-graphics", &vm.name]);

        for s in &shares {
            let ro = if s.writable { "" } else { ":ro" };
            run.arg(format!("--dir={}:{}{ro}", s.name, s.path.display()));
        }

        vm.run = Some(
            run.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| Error::Unavailable(format!("tart run: {e}")))?,
        );
        vm.wait_for_agent()?;
        let guest = match tart(&["get", &vm.name, "--format", "json"])? {
            json if json.contains("\"darwin\"") => Guest::Macos,
            _ => Guest::Linux,
        };
        vm.mount(guest, &shares)?;
        Ok(vm)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// `argv` in the guest, run from `dir`. stdin, stdout, stderr and the exit code pass through
    pub fn command<S: AsRef<OsStr>>(&self, dir: &Path, argv: &[S]) -> Command {
        let mut cmd = Command::new("tart");
        cmd.args([
            "exec",
            "-i",
            &self.name,
            "/bin/sh",
            "-c",
            "cd \"$0\" && exec \"$@\"",
        ])
        .arg(dir)
        .args(argv);
        cmd
    }

    fn wait_for_agent(&mut self) -> Result<(), Error> {
        let start = Instant::now();

        while start.elapsed() < BOOT_TIMEOUT {
            if let Some(Ok(Some(status))) = self.run.as_mut().map(Child::try_wait) {
                return Err(Error::Unavailable(format!("tart run exited with {status}")));
            }

            let ready = Command::new("tart")
                .args(["exec", &self.name, "true"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());

            if ready {
                return Ok(());
            }

            std::thread::sleep(Duration::from_secs(1));
        }

        Err(Error::Unavailable(format!(
            "{}: the guest agent did not answer in {}s. The image needs the Tart Guest Agent",
            self.name,
            BOOT_TIMEOUT.as_secs()
        )))
    }

    // Puts each share at its host path, so paths and working dirs carry over
    fn mount(&self, guest: Guest, shares: &[Share]) -> Result<(), Error> {
        let mut script = String::from("set -e\n");

        if guest == Guest::Linux && !shares.is_empty() {
            script += &format!(
                "sudo -n mkdir -p {GUEST_MOUNT}\nsudo -n mount -t virtiofs com.apple.virtio-fs.automount {GUEST_MOUNT}\n"
            );
        }

        for s in shares {
            let path = quote(&s.path)?;
            script += &match guest {
                Guest::Linux => format!(
                    "sudo -n mkdir -p {path}\nsudo -n mount --bind {GUEST_MOUNT}/{} {path}\n",
                    s.name
                ),
                Guest::Macos => format!(
                    "sudo -n mkdir -p \"$(dirname {path})\"\nsudo -n ln -s '{GUEST_VOLUME}/{}' {path}\n",
                    s.name
                ),
            };
        }

        let out = Command::new("tart")
            .args(["exec", &self.name, "/bin/sh", "-c", &script])
            .output()
            .map_err(|e| Error::Unavailable(format!("tart exec: {e}")))?;

        if !out.status.success() {
            return Err(Error::Unavailable(format!(
                "{}: could not put the shares at their host paths: {}",
                self.name,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        Ok(())
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = Command::new("tart")
            .args(["stop", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if let Some(mut run) = self.run.take() {
            let _ = run.kill();
            let _ = run.wait();
        }

        let _ = Command::new("tart")
            .args(["delete", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn tart(args: &[&str]) -> Result<String, Error> {
    let out = Command::new("tart")
        .args(args)
        .output()
        .map_err(|e| Error::Unavailable(format!("tart: {e}")))?;

    if !out.status.success() {
        return Err(Error::Unavailable(format!(
            "tart {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn quote(p: &Path) -> Result<String, Error> {
    p.to_str()
        .map(|s| format!("'{}'", s.replace('\'', "'\\''")))
        .ok_or_else(|| Error::Policy(format!("{}: not UTF-8", p.display())))
}

/**
 * The shares for a policy, or why a VM cannot enforce it. A guest sees nothing of the host but its
 * shares, so `unreadable`, Mach services, Apple events, signals and terminals hold already. A rule
 * on a path inside a share, or one that needs the host kernel, cannot be enforced
 **/
fn shares(p: &Policy) -> Result<Vec<Share>, Error> {
    let refuse = |why: &str| Err(Error::Policy(format!("a VM cannot enforce {why}")));

    if !p.read_only.is_empty() || !p.pinned.is_empty() {
        return refuse("read_only or pinned, it shares whole dirs");
    }

    if !p.scratch.is_empty() || !p.overlays.is_empty() {
        return refuse("scratch dirs or overlays, its own disk already starts fresh");
    }

    if !p.no_exec.is_empty() {
        return refuse("no_exec, the guest runs its own binaries");
    }

    if !p.network {
        return refuse("network = false, tart has no network that reaches nothing");
    }

    if let Access::Only(dirs) = &p.unix_sockets
        && !dirs.is_empty()
    {
        return refuse("unix_sockets, a host socket does not cross into the guest");
    }

    let mut shares = vec![];
    let dirs = p
        .writable
        .iter()
        .map(|d| (d, true))
        .chain(p.readable.iter().map(|d| (d, false)));

    for (i, (dir, writable)) in dirs.enumerate() {
        let path = real(dir);

        if !path.is_dir() {
            return Err(Error::Policy(format!(
                "{}: a VM shares directories, and this is none",
                path.display()
            )));
        }

        if let Some(h) = p.hidden.iter().find(|h| real(h).starts_with(&path)) {
            return Err(Error::Policy(format!(
                "{}: a VM cannot hide a path inside the share {}",
                h.display(),
                path.display()
            )));
        }

        shares.push(Share {
            name: format!("s{i}"),
            path,
            writable,
        });
    }

    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_what_a_vm_cannot_enforce() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_path_buf();
        for policy in [
            Policy {
                writable: vec![d.clone()],
                read_only: vec![d.join("x")],
                ..Policy::default()
            },
            Policy {
                network: false,
                ..Policy::default()
            },
            Policy {
                no_exec: vec!["/usr/bin/sudo".into()],
                ..Policy::default()
            },
            Policy {
                writable: vec![d.clone()],
                hidden: vec![d.join("secret")],
                ..Policy::default()
            },
            Policy {
                writable: vec![d.join("missing")],
                ..Policy::default()
            },
        ] {
            assert!(
                matches!(shares(&policy), Err(Error::Policy(_))),
                "{policy:?}"
            );
        }
    }

    #[test]
    fn shares_writable_then_readable_dirs_by_resolved_path() {
        let (w, r) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let policy = Policy {
            writable: vec![w.path().into()],
            readable: vec![r.path().into()],
            hidden: vec!["/elsewhere".into()],
            ..Policy::default()
        };
        let shares = shares(&policy).unwrap();
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].path, real(w.path()));
        assert!(shares[0].writable && !shares[1].writable);
        assert_eq!(
            (shares[0].name.as_str(), shares[1].name.as_str()),
            ("s0", "s1")
        );
    }

    #[test]
    fn quotes_a_path_for_the_guest_shell() {
        assert_eq!(quote(Path::new("/a b/it's")).unwrap(), "'/a b/it'\\''s'");
    }
}
