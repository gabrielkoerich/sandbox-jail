//! Lists a caller can opt into. Nothing here applies unless the caller puts it in its policy

use std::path::{Path, PathBuf};

/// Credentials under a home directory, relative to it. Put them in `Policy::hidden`
pub const CREDENTIALS: &[&str] = &[
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".cargo/config",
    ".cargo/config.toml",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".config/pip",
    ".config/uv",
    ".docker/config.json",
    ".ssh",
    ".aws",
    ".config/gh",
];

/// [`CREDENTIALS`] under `home`
pub fn credentials(home: &Path) -> Vec<PathBuf> {
    CREDENTIALS.iter().map(|c| home.join(c)).collect()
}

/// Whether an environment variable likely carries a credential or points git at another repository
pub fn secret_env(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper == "SSH_AUTH_SOCK"
        || ["TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"]
            .iter()
            .any(|s| upper.contains(s))
        || upper.ends_with("_KEY")
        || ["AWS_", "GOOGLE_", "AZURE_", "GIT_"]
            .iter()
            .any(|p| upper.starts_with(p))
}

/// The system's temp directories, where other processes leave files and sockets
pub const TEMP_DIRS: &[&str] = &[
    "/tmp",
    "/private/tmp",
    "/var/tmp",
    "/private/var/tmp",
    "/var/folders",
    "/private/var/folders",
    "/dev/shm",
];

/// [`TEMP_DIRS`] and this process's temp dir, resolved and without duplicates
pub fn temp_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = TEMP_DIRS
        .iter()
        .map(PathBuf::from)
        .chain([std::env::temp_dir()])
        .map(|d| crate::real(&d))
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

/**
 * macOS services that cargo, npm, node, uv, go, cc, git and curl look up: user and group lookups,
 * notifications, logging, temp dirs, the clock, DNS and proxy settings and trustd, which checks TLS
 * certificates. Not securityd, which holds the keychain
 **/
pub const BASIC_MACH_SERVICES: &[&str] = &[
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.system.notification_center",
    "com.apple.logd",
    "com.apple.diagnosticd",
    "com.apple.bsd.dirhelper",
    "com.apple.timed.xpc",
    "com.apple.SystemConfiguration.configd",
    "com.apple.SystemConfiguration.DNSConfiguration",
    "com.apple.trustd",
    "com.apple.trustd.agent",
];

/// Talks to launchd over the bootstrap port, which no sandbox rule covers, so a job it starts runs outside
pub const LAUNCHCTL: &str = "/bin/launchctl";

/// A setuid root binary outside the scanned dirs
const ARD_AGENT: &str =
    "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent";

/// The system's setuid binaries, resolved, read once. A setuid binary runs as root, so a caller can
/// stop it only by never running it
pub fn setuid_binaries() -> &'static [PathBuf] {
    use std::os::unix::fs::PermissionsExt;

    static FOUND: std::sync::OnceLock<Vec<PathBuf>> = std::sync::OnceLock::new();
    FOUND.get_or_init(|| {
        let dirs = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec"];
        let mut found: Vec<PathBuf> = dirs
            .iter()
            .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
            .map(|e| e.path())
            .chain([PathBuf::from(ARD_AGENT)])
            .filter(|p| {
                std::fs::metadata(p)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o4000 != 0)
            })
            .map(|p| crate::real(&p))
            .collect();
        found.sort();
        found.dedup();
        found
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_env_refuses_credentials_and_keeps_the_rest() {
        for name in [
            "GH_TOKEN",
            "AWS_REGION",
            "OPENAI_API_KEY",
            "GIT_DIR",
            "ssh_auth_sock",
        ] {
            assert!(secret_env(name), "{name}");
        }

        for name in ["PATH", "HOME", "LANG", "TERM"] {
            assert!(!secret_env(name), "{name}");
        }
    }

    #[test]
    fn temp_dirs_include_this_process_s() {
        assert!(temp_dirs().contains(&crate::real(&std::env::temp_dir())));
    }
}
