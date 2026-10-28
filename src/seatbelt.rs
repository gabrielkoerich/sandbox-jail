use crate::{Access, Error, Policy};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

pub(crate) fn detect() -> Result<(), Error> {
    if !Path::new(SANDBOX_EXEC).exists() {
        return Err(Error::Unavailable(format!("{SANDBOX_EXEC} is missing")));
    }

    // One real rule, since macOS starts a nested profile that restricts nothing
    static STARTS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let starts = *STARTS.get_or_init(|| {
        Command::new(SANDBOX_EXEC)
            .args([
                "-p",
                "(version 1)(allow default)(deny file-write* (literal \"/var/empty/sandbox-jail\"))",
                "/usr/bin/true",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    });

    if !starts {
        return Err(Error::Nested);
    }

    Ok(())
}

pub(crate) fn argv(policy: &Policy) -> Result<Vec<OsString>, Error> {
    if !policy.overlays.is_empty() {
        return Err(Error::Policy("only bwrap mounts an overlay".into()));
    }

    Ok(vec![
        SANDBOX_EXEC.into(),
        "-p".into(),
        profile(policy)?.into(),
    ])
}

fn quote(p: &Path) -> Result<String, Error> {
    p.to_str()
        .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
        .ok_or_else(|| Error::Policy(format!("{}: not UTF-8", p.display())))
}

fn filters(kind: &str, paths: &[PathBuf]) -> Result<String, Error> {
    paths
        .iter()
        .map(|p| quote(p).map(|q| format!(" ({kind} {q})")))
        .collect()
}

/**
 * The `sandbox-exec` profile. The last rule that matches wins, so each deny comes after the allow
 * it narrows. An allow with no filter allows everything, so an empty list never writes one
 **/
pub(crate) fn profile(p: &Policy) -> Result<String, Error> {
    let mut out = String::from("(version 1)\n(allow default)\n(deny file-write*)\n");
    let writable = filters("subpath", &p.writable)?;
    out +=
        &format!("(allow file-write*{writable} (literal \"/dev/null\") (regex #\"^/dev/fd/\"))\n");

    // The com.apple.sandbox.pty extension marks a pseudo-terminal the sandboxed process opened
    if p.own_terminals {
        out += "(allow file-write* (literal \"/dev/ptmx\") (require-all (regex #\"^/dev/ttys[0-9]+$\") (extension \"com.apple.sandbox.pty\")))\n";
    } else {
        out += "(allow file-write* (literal \"/dev/ptmx\") (literal \"/dev/tty\") (regex #\"^/dev/ttys[0-9]+$\"))\n";
    }

    let mut pinned = p.pinned.clone();
    pinned.extend(ruled_parents(p));

    if !pinned.is_empty() {
        out += &format!("(deny file-write*{})\n", filters("literal", &pinned)?);
    }

    // A hidden path that could be renamed would leave its rule behind
    let fixed: Vec<PathBuf> = p.read_only.iter().chain(&p.hidden).cloned().collect();

    if !fixed.is_empty() {
        out += &format!("(deny file-write*{})\n", filters("subpath", &fixed)?);
    }

    if !p.unreadable.is_empty() {
        out += &format!(
            "(deny file-read-data{})\n",
            filters("subpath", &p.unreadable)?
        );
        let allowed = filters("subpath", &p.readable)? + &writable;

        if !allowed.is_empty() {
            out += &format!("(allow file-read-data{allowed})\n");
        }
    }

    if !p.hidden.is_empty() {
        out += &format!("(deny file-read*{})\n", filters("subpath", &p.hidden)?);
    }

    if p.own_terminals {
        out += "(deny file-read* (require-all (regex #\"^/dev/ttys[0-9]+$\") (require-not (extension \"com.apple.sandbox.pty\"))))\n";
    }

    if !p.network {
        out += "(deny network-outbound (remote ip))\n(deny network-bind (local ip))\n";
    }

    if let Access::Only(dirs) = &p.unix_sockets {
        out += "(deny network-outbound (remote unix-socket))\n";
        out += "(allow network-outbound (remote unix-socket (path-literal \"/private/var/run/mDNSResponder\")))\n";
        // A `remote unix-socket` filter takes one path, so each dir gets its own
        let sockets: String = dirs
            .iter()
            .map(|d| quote(d).map(|q| format!(" (remote unix-socket (subpath {q}))")))
            .collect::<Result<_, _>>()?;

        if !sockets.is_empty() {
            out += &format!("(allow network-outbound{sockets})\n");
        }
    }

    if !p.apple_events {
        out += "(deny appleevent-send)\n";
    }

    if let Access::Only(names) = &p.mach_services {
        out += "(deny mach-lookup)\n";

        if !names.is_empty() {
            let mach: String = names
                .iter()
                .map(|n| format!(" (global-name \"{}\")", n.replace(['\\', '"'], "")))
                .collect();
            out += &format!("(allow mach-lookup{mach})\n");
        }
    }

    if p.own_signals {
        out += "(deny signal)\n(allow signal (target same-sandbox))\n";
    }

    if !p.no_exec.is_empty() {
        out += &format!("(deny process-exec*{})\n", filters("literal", &p.no_exec)?);
    }

    Ok(out)
}

/**
 * Every parent of a read-only, pinned or hidden path that the command could rename. Seatbelt matches
 * the path at each access, so renaming a parent moves the path out from under its rule. Denying writes
 * to the parent itself keeps it in place, while what is inside it stays writable
 **/
fn ruled_parents(p: &Policy) -> Vec<PathBuf> {
    let mut parents: Vec<PathBuf> = p
        .read_only
        .iter()
        .chain(&p.pinned)
        .chain(&p.hidden)
        .flat_map(|path| path.ancestors().skip(1))
        .filter(|a| p.writable.iter().any(|w| a.starts_with(w)))
        .map(Path::to_path_buf)
        .collect();
    parents.sort();
    parents.dedup();
    parents
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_lists_write_no_allow_that_matches_everything() {
        let policy = Policy {
            unreadable: vec!["/u".into()],
            unix_sockets: Access::Only(vec![]),
            mach_services: Access::Only(vec![]),
            ..Policy::default()
        };
        let profile = profile(&policy).unwrap();

        for rule in ["file-read-data", "network-outbound", "mach-lookup"] {
            assert!(!profile.contains(&format!("(allow {rule})")), "{profile}");
        }

        assert!(profile.contains("(deny mach-lookup)"));
    }

    #[test]
    fn each_deny_comes_after_the_allow_it_narrows() {
        let policy = Policy {
            writable: vec!["/w".into()],
            read_only: vec!["/w/ro".into()],
            hidden: vec!["/w/secret".into()],
            unreadable: vec!["/w".into()],
            ..Policy::default()
        };
        let profile = profile(&policy).unwrap();
        let at = |s: &str| {
            profile
                .find(s)
                .unwrap_or_else(|| panic!("{s} in {profile}"))
        };
        assert!(
            at("(allow file-write* (subpath \"/w\")") < at("(deny file-write* (subpath \"/w/ro\")")
        );
        assert!(at("(allow file-read-data") < at("(deny file-read* (subpath \"/w/secret\")"));
    }

    #[test]
    fn pins_each_parent_of_a_ruled_path_inside_a_writable_dir() {
        let policy = Policy {
            writable: vec!["/home".into()],
            read_only: vec!["/home/.config/git".into()],
            hidden: vec!["/elsewhere/key".into()],
            ..Policy::default()
        };
        let parents: Vec<PathBuf> = vec!["/home".into(), "/home/.config".into()];
        assert_eq!(ruled_parents(&policy), parents);
    }

    #[test]
    fn quotes_a_path_with_a_quote() {
        assert_eq!(quote(Path::new("/a\"b")).unwrap(), "\"/a\\\"b\"");
    }

    #[test]
    fn refuses_an_overlay() {
        let policy = Policy {
            overlays: vec![crate::Overlay {
                lower: "/l".into(),
                upper: "/u".into(),
                work: "/w".into(),
            }],
            ..Policy::default()
        };
        assert!(matches!(argv(&policy), Err(Error::Policy(_))));
    }
}
