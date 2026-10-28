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

/// The password of the `lume` user in lume's images, which sudo asks for
const LUME_PASSWORD: &str = "lume";

static CLONES: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tool {
    Tart,
    Lume,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guest {
    Linux,
    Macos,
}

/// A running clone of an image. Dropping it stops and deletes the clone
#[derive(Debug)]
pub struct Vm {
    tool: Tool,
    bin: PathBuf,
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
        Self::start(Tool::Tart, image, policy)
    }

    /**
     * Boots a lume clone of `image` with the policy's dirs shared. Commands run over `lume ssh`
     * as the image's `lume` user, whose password sudo needs. `lume ssh` passes no stdin and puts
     * stderr on stdout. lume names a share after its last path component, so two shares with the
     * same name are refused
     **/
    pub fn lume(image: &str, policy: &Policy) -> Result<Self, Error> {
        Self::start(Tool::Lume, image, policy)
    }

    fn start(tool: Tool, image: &str, policy: &Policy) -> Result<Self, Error> {
        let shares = shares(tool, policy)?;
        let bin = binary(tool)?;
        let n = CLONES.fetch_add(1, Ordering::Relaxed);
        let name = format!("sandbox-jail-{}-{n}", std::process::id());
        run(&bin, &["clone", image, &name])?;
        // From here on Drop deletes the clone, whatever fails next
        let mut vm = Self {
            tool,
            bin,
            name,
            run: None,
        };

        let mut boot = Command::new(&vm.bin);
        match tool {
            Tool::Tart => boot.args(["run", "--no-graphics", &vm.name]),
            Tool::Lume => boot.args(["run", &vm.name, "--no-display"]),
        };

        for s in &shares {
            let ro = if s.writable { "" } else { ":ro" };
            match tool {
                Tool::Tart => boot.arg(format!("--dir={}:{}{ro}", s.name, s.path.display())),
                Tool::Lume => boot
                    .arg("--shared-dir")
                    .arg(format!("{}{ro}", s.path.display())),
            };
        }

        vm.run = Some(
            boot.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| Error::Unavailable(format!("{} run: {e}", vm.bin.display())))?,
        );
        vm.wait_until_ready()?;
        let info = run(&vm.bin, &["get", &vm.name, "--format", "json"])?;
        let guest = if info.contains("\"darwin\"") || info.contains("\"macOS\"") {
            Guest::Macos
        } else {
            Guest::Linux
        };
        vm.mount(guest, &shares)?;
        Ok(vm)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// `argv` in the guest, run from `dir`. stdout, stderr and the exit code pass through, and stdin
    /// too under tart
    pub fn command<S: AsRef<OsStr>>(&self, dir: &Path, argv: &[S]) -> Command {
        let mut cmd = Command::new(&self.bin);
        match self.tool {
            Tool::Tart => {
                cmd.args(["exec", "-i", &self.name, "/bin/sh", "-c"])
                    .arg("cd \"$0\" && exec \"$@\"")
                    .arg(dir)
                    .args(argv);
            }
            // lume ssh joins its arguments with plain spaces, so the command goes as one quoted string
            Tool::Lume => {
                cmd.args(["ssh", &self.name, "-t", "0"])
                    .arg(remote_command(dir, argv));
            }
        }
        cmd
    }

    /// `script` run with `sh -c` in the guest
    fn shell(&self, script: &str) -> Command {
        let mut cmd = Command::new(&self.bin);
        match self.tool {
            Tool::Tart => cmd.args(["exec", &self.name, "/bin/sh", "-c", script]),
            Tool::Lume => cmd
                .args(["ssh", &self.name, "-t", "0"])
                .arg(format!("/bin/sh -c {}", quote_str(script))),
        };
        cmd
    }

    fn wait_until_ready(&mut self) -> Result<(), Error> {
        let start = Instant::now();

        while start.elapsed() < BOOT_TIMEOUT {
            if let Some(Ok(Some(status))) = self.run.as_mut().map(Child::try_wait) {
                return Err(Error::Unavailable(format!(
                    "{} run exited with {status}",
                    self.bin.display()
                )));
            }

            let mut probe = Command::new(&self.bin);
            match self.tool {
                Tool::Tart => probe.args(["exec", &self.name, "true"]),
                Tool::Lume => probe.args(["ssh", &self.name, "-t", "5", "true"]),
            };
            let ready = probe
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());

            if ready {
                return Ok(());
            }

            std::thread::sleep(Duration::from_secs(1));
        }

        let what = match self.tool {
            Tool::Tart => "the Tart Guest Agent",
            Tool::Lume => "SSH",
        };
        Err(Error::Unavailable(format!(
            "{}: {what} did not answer in {}s",
            self.name,
            BOOT_TIMEOUT.as_secs()
        )))
    }

    // Puts each share at its host path, so paths and working dirs carry over
    fn mount(&self, guest: Guest, shares: &[Share]) -> Result<(), Error> {
        let mut script = match self.tool {
            Tool::Tart => String::from("set -e\nas_root() { sudo -n \"$@\"; }\n"),
            Tool::Lume => format!(
                "set -e\nas_root() {{ printf '%s\\n' {} | sudo -S -p '' \"$@\"; }}\n",
                quote_str(LUME_PASSWORD)
            ),
        };

        if guest == Guest::Linux && !shares.is_empty() {
            script += &format!(
                "as_root mkdir -p {GUEST_MOUNT}\nas_root mount -t virtiofs com.apple.virtio-fs.automount {GUEST_MOUNT}\n"
            );
        }

        for s in shares {
            let path = quote(&s.path)?;
            let share = quote_str(&s.name);
            script += &match guest {
                Guest::Linux => format!(
                    "as_root mkdir -p {path}\nas_root mount --bind {GUEST_MOUNT}/{share} {path}\n"
                ),
                Guest::Macos => format!(
                    "as_root mkdir -p \"$(dirname {path})\"\nas_root ln -s '{GUEST_VOLUME}'/{share} {path}\n"
                ),
            };
        }

        let out = self
            .shell(&script)
            .output()
            .map_err(|e| Error::Unavailable(format!("{}: {e}", self.bin.display())))?;

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
        let _ = Command::new(&self.bin)
            .args(["stop", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if let Some(mut run) = self.run.take() {
            let _ = run.kill();
            let _ = run.wait();
        }

        let mut delete = Command::new(&self.bin);
        delete.args(["delete", &self.name]);

        if self.tool == Tool::Lume {
            delete.arg("--force");
        }

        let _ = delete.stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

/// The tool's binary. lume's installer puts it in `~/.local/bin`, which is often not on `PATH`
fn binary(tool: Tool) -> Result<PathBuf, Error> {
    let (name, install) = match tool {
        Tool::Tart => ("tart", "`brew install cirruslabs/cli/tart`"),
        Tool::Lume => (
            "lume",
            "https://github.com/trycua/cua/blob/main/libs/lume/scripts/install.sh",
        ),
    };
    let local = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/bin").join(name));
    let candidates = [Some(PathBuf::from(name)), local];

    candidates
        .into_iter()
        .flatten()
        .find(|bin| Command::new(bin).arg("--version").output().is_ok())
        .ok_or_else(|| Error::Unavailable(format!("{name} is missing: {install}")))
}

fn run(bin: &Path, args: &[&str]) -> Result<String, Error> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| Error::Unavailable(format!("{}: {e}", bin.display())))?;

    if !out.status.success() {
        return Err(Error::Unavailable(format!(
            "{} {}: {}",
            bin.display(),
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn quote_str(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn quote(p: &Path) -> Result<String, Error> {
    p.to_str()
        .map(quote_str)
        .ok_or_else(|| Error::Policy(format!("{}: not UTF-8", p.display())))
}

/// `cd dir && exec argv...` as one string for a remote shell
fn remote_command<S: AsRef<OsStr>>(dir: &Path, argv: &[S]) -> String {
    let words: Vec<String> = argv
        .iter()
        .map(|a| quote_str(&a.as_ref().to_string_lossy()))
        .collect();
    format!(
        "cd {} && exec {}",
        quote_str(&dir.to_string_lossy()),
        words.join(" ")
    )
}

/**
 * The shares for a policy, or why a VM cannot enforce it. A guest sees nothing of the host but its
 * shares, so `unreadable`, Mach services, Apple events, signals and terminals hold already. A rule
 * on a path inside a share, or one that needs the host kernel, cannot be enforced
 **/
fn shares(tool: Tool, p: &Policy) -> Result<Vec<Share>, Error> {
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
        return refuse("network = false, neither tart nor lume has a network that reaches nothing");
    }

    if let Access::Only(dirs) = &p.unix_sockets
        && !dirs.is_empty()
    {
        return refuse("unix_sockets, a host socket does not cross into the guest");
    }

    let mut shares: Vec<Share> = vec![];
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

        let name = match tool {
            Tool::Tart => format!("s{i}"),
            Tool::Lume => path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };

        if let Some(other) = shares.iter().find(|s| s.name == name) {
            return Err(Error::Policy(format!(
                "{} and {}: lume names a share after its last path component, so these collide",
                other.path.display(),
                path.display()
            )));
        }

        shares.push(Share {
            name,
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
            for tool in [Tool::Tart, Tool::Lume] {
                assert!(
                    matches!(shares(tool, &policy), Err(Error::Policy(_))),
                    "{tool:?} {policy:?}"
                );
            }
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
        let shares = shares(Tool::Tart, &policy).unwrap();
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].path, real(w.path()));
        assert!(shares[0].writable && !shares[1].writable);
        assert_eq!(
            (shares[0].name.as_str(), shares[1].name.as_str()),
            ("s0", "s1")
        );
    }

    #[test]
    fn lume_names_shares_by_last_component_and_refuses_a_clash() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        for d in [a.path(), b.path()] {
            std::fs::create_dir(d.join("src")).unwrap();
        }
        let one = Policy {
            writable: vec![a.path().join("src")],
            ..Policy::default()
        };
        assert_eq!(shares(Tool::Lume, &one).unwrap()[0].name, "src");

        let clash = Policy {
            writable: vec![a.path().join("src"), b.path().join("src")],
            ..Policy::default()
        };
        assert!(matches!(shares(Tool::Lume, &clash), Err(Error::Policy(_))));
        assert!(shares(Tool::Tart, &clash).is_ok());
    }

    #[test]
    fn quotes_a_path_for_the_guest_shell() {
        assert_eq!(quote(Path::new("/a b/it's")).unwrap(), "'/a b/it'\\''s'");
    }

    #[test]
    fn a_remote_command_keeps_each_argument_whole() {
        assert_eq!(
            remote_command(Path::new("/w d"), &["printf", "%s|", "a b", "it's"]),
            "cd '/w d' && exec 'printf' '%s|' 'a b' 'it'\\''s'"
        );
    }
}
