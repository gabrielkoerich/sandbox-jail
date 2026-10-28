//! Run a command in the OS sandbox: Seatbelt (`sandbox-exec`) on macOS, bubblewrap (`bwrap`) on
//! Linux. The caller defines the whole policy, the crate only enforces it. See docs/DESIGN.md

mod bwrap;
pub mod known;
#[cfg(target_os = "macos")]
pub mod macos;
mod seatbelt;

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Everything, or only the listed items
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Access<T> {
    #[default]
    All,
    Only(Vec<T>),
}

/// An overlay mounted on `lower`, which stays unchanged while writes go to `upper`. bwrap only
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlay {
    pub lower: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
}

/// What the command may touch. Every path must be absolute
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Directories the command may write, and read even inside `unreadable`
    pub writable: Vec<PathBuf>,
    /// Directories it may not write, even inside `writable`
    pub read_only: Vec<PathBuf>,
    /// Paths it may not replace or remove, while what is inside a directory stays writable. Seatbelt only
    pub pinned: Vec<PathBuf>,
    /// Directories whose files it may not read, but for `readable` and `writable` inside them.
    /// bwrap mounts an empty read-only directory over each
    pub unreadable: Vec<PathBuf>,
    /// Exceptions inside `unreadable`
    pub readable: Vec<PathBuf>,
    /// Paths it may not read or list, even inside `readable` or `writable`
    pub hidden: Vec<PathBuf>,
    /// TCP and UDP. Off also hides the host's localhost under bwrap
    pub network: bool,
    /// Unix sockets it may connect to, by the directory they are in. Seatbelt also allows the DNS
    /// resolver's. Under bwrap a socket is out of reach only when its directory is unreadable or hidden
    pub unix_sockets: Access<PathBuf>,
    /// Mach services it may look up. Seatbelt only
    pub mach_services: Access<String>,
    /// Whether it may send Apple events, which can start a process outside the sandbox. Seatbelt only
    pub apple_events: bool,
    /// Signals reach only its own processes. bwrap always does this with a pid namespace
    pub own_signals: bool,
    /// It reads and writes only pseudo-terminals it opened, so the caller's terminal is out of reach
    pub own_terminals: bool,
    /// Binaries it may not run. Seatbelt only, bwrap already runs setuid binaries without privileges
    pub no_exec: Vec<PathBuf>,
    /// bwrap only
    pub overlays: Vec<Overlay>,
}

impl Default for Policy {
    /// Writes nowhere, everything else open
    fn default() -> Self {
        Self {
            writable: vec![],
            read_only: vec![],
            pinned: vec![],
            unreadable: vec![],
            readable: vec![],
            hidden: vec![],
            network: true,
            unix_sockets: Access::All,
            mach_services: Access::All,
            apple_events: true,
            own_signals: false,
            own_terminals: false,
            no_exec: vec![],
            overlays: vec![],
        }
    }
}

impl Policy {
    fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        let overlays = self
            .overlays
            .iter()
            .flat_map(|o| [&o.lower, &o.upper, &o.work]);
        let sockets = match &self.unix_sockets {
            Access::All => &[][..],
            Access::Only(dirs) => &dirs[..],
        };
        self.writable
            .iter()
            .chain(&self.read_only)
            .chain(&self.pinned)
            .chain(&self.unreadable)
            .chain(&self.readable)
            .chain(&self.hidden)
            .chain(&self.no_exec)
            .chain(sockets)
            .chain(overlays)
    }

    // The sandbox matches the path a symlink resolves to, so `/tmp` must become `/private/tmp`
    fn resolved(mut self) -> Self {
        let lists = [
            &mut self.writable,
            &mut self.read_only,
            &mut self.pinned,
            &mut self.unreadable,
            &mut self.readable,
            &mut self.hidden,
            &mut self.no_exec,
        ];

        for list in lists {
            for path in list.iter_mut() {
                *path = real(path);
            }
        }

        if let Access::Only(dirs) = &mut self.unix_sockets {
            for dir in dirs.iter_mut() {
                *dir = real(dir);
            }
        }

        for o in &mut self.overlays {
            for path in [&mut o.lower, &mut o.upper, &mut o.work] {
                *path = real(path);
            }
        }

        self
    }
}

/// The real path, or for a missing one its real parent and its name, or the path as given
pub(crate) fn real(path: &Path) -> PathBuf {
    if let Ok(p) = path.canonicalize() {
        return p;
    }

    match (path.parent().map(Path::canonicalize), path.file_name()) {
        (Some(Ok(parent)), Some(name)) => parent.join(name),
        _ => path.to_path_buf(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Seatbelt,
    Bwrap,
}

impl Backend {
    /// The sandbox this machine can start, or why none starts
    pub fn detect() -> Result<Backend, Error> {
        if cfg!(target_os = "macos") {
            return seatbelt::detect().map(|_| Backend::Seatbelt);
        }

        if cfg!(target_os = "linux") {
            return bwrap::detect().map(|_| Backend::Bwrap);
        }

        Err(Error::Unavailable(
            "no OS sandbox on this platform, only sandbox-exec on macOS and bubblewrap on Linux"
                .into(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No sandbox here, with the fix when there is one
    Unavailable(String),
    /// macOS refuses a sandbox inside another one, such as an agent's
    Nested,
    /// The backend cannot enforce this policy
    Policy(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unavailable(why) => write!(f, "{why}"),
            Error::Nested => write!(
                f,
                "macOS cannot start a sandbox inside another one, such as an agent's: run this outside it"
            ),
            Error::Policy(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for Error {}

/// A policy checked against a backend, ready to wrap commands
#[derive(Debug, Clone)]
pub struct Sandbox {
    backend: Backend,
    policy: Policy,
    argv: Vec<OsString>,
}

impl Sandbox {
    pub fn seatbelt(policy: Policy) -> Result<Self, Error> {
        Self::new(Backend::Seatbelt, policy)
    }

    pub fn bwrap(policy: Policy) -> Result<Self, Error> {
        Self::new(Backend::Bwrap, policy)
    }

    /// Refuses a policy the backend cannot enforce. bwrap skips paths that do not exist yet, so
    /// build the sandbox right before running the command
    pub fn new(backend: Backend, policy: Policy) -> Result<Self, Error> {
        if let Some(p) = policy.paths().find(|p| !p.is_absolute()) {
            return Err(Error::Policy(format!(
                "{}: not an absolute path",
                p.display()
            )));
        }

        let policy = policy.resolved();
        let argv = match backend {
            Backend::Seatbelt => seatbelt::argv(&policy)?,
            Backend::Bwrap => bwrap::argv(&policy)?,
        };
        Ok(Self {
            backend,
            policy,
            argv,
        })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The policy with every path resolved, as the sandbox matches it
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The program and arguments that go before the command, for a caller that writes a script
    pub fn argv(&self) -> &[OsString] {
        &self.argv
    }

    /// `program` in the sandbox. The caller adds its arguments, environment and directory
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut cmd = Command::new(&self.argv[0]);
        cmd.args(&self.argv[1..]).arg(program);
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_a_relative_path() {
        let policy = Policy {
            hidden: vec!["relative".into()],
            ..Policy::default()
        };
        let err = Sandbox::seatbelt(policy).unwrap_err();
        assert!(matches!(err, Error::Policy(m) if m.contains("relative")));
    }

    #[test]
    fn resolves_a_missing_path_through_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert_eq!(
            real(&missing),
            dir.path().canonicalize().unwrap().join("missing")
        );
    }

    #[test]
    fn the_command_comes_after_the_sandbox_argv() {
        let sandbox = Sandbox::bwrap(Policy::default()).unwrap();
        let cmd = sandbox.command("/bin/sh");
        assert_eq!(cmd.get_program(), "bwrap");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args[args.len() - 2..], ["--", "/bin/sh"]);
    }
}
