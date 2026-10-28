use sandbox_jail::vm::Vm;
use sandbox_jail::{Backend, Policy, Sandbox, known};
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: sandbox-jail exec [options] \"command\"
       sandbox-jail exec [options] -- <program> [<args>...]
       sandbox-jail --version

exec    runs the command in the OS sandbox: Seatbelt on macOS, bubblewrap on Linux. It may write
        the current directory and the temp dirs, and nothing else. Credentials in your home are
        hidden, signals reach only its own processes, and on macOS it cannot run launchctl or a
        setuid binary such as sudo. One string runs with sh -c. With --vm it runs in a throwaway
        clone of a VM image instead, which sees only the current directory and the -w paths,
        each at its host path

exec options:
      --vm tart:<image>   run in a tart clone of <image>, deleted afterwards. The image needs the
                          Tart Guest Agent, as ghcr.io/cirruslabs/ubuntu and macos-*-base have
  -w, --write <path>      also let it write <path>
  -r, --read-only <path>  never let it write <path>, even inside a writable one
      --hide <path>       never let it read <path>
      --no-network        no TCP or UDP
      --dry-run           print the sandbox command instead of running it";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let res = match args.first().and_then(|a| a.to_str()) {
        Some("exec") => exec(&args[1..]),
        Some("--version" | "-V") => {
            println!("sandbox-jail {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => return usage(),
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sandbox-jail: {e}");
            ExitCode::from(2)
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

struct ExecArgs {
    policy: Policy,
    dry_run: bool,
    vm: Option<String>,
    command: Vec<OsString>,
}

fn parse_exec(args: &[OsString]) -> Result<ExecArgs, String> {
    let mut args = args.iter().cloned();
    let mut policy = Policy::default();
    let mut dry_run = false;
    let mut vm = None;
    let mut command = vec![];

    while let Some(arg) = args.next() {
        let mut path = |flag: &str| {
            args.next()
                .map(|p| absolute(PathBuf::from(p)))
                .ok_or(format!("{flag} needs a path"))
        };

        match arg.to_str() {
            Some("-w" | "--write") => policy.writable.push(path("--write")?),
            Some("-r" | "--read-only") => policy.read_only.push(path("--read-only")?),
            Some("--hide") => policy.hidden.push(path("--hide")?),
            Some("--no-network") => policy.network = false,
            Some("--dry-run") => dry_run = true,
            Some("--vm") => {
                let spec = args.next().and_then(|s| s.into_string().ok());
                let image = spec.as_deref().and_then(|s| s.strip_prefix("tart:"));
                vm = Some(image.ok_or("--vm takes tart:<image>")?.to_string());
            }
            Some("--") => {
                command.extend(args.by_ref());
                break;
            }
            Some(flag) if flag.starts_with('-') => return Err(format!("unknown option {flag}")),
            _ => {
                command = vec!["/bin/sh".into(), "-c".into(), arg];
                command.extend(args.by_ref());
                break;
            }
        }
    }

    if command.is_empty() {
        return Err("exec needs a command".into());
    }

    Ok(ExecArgs {
        policy,
        dry_run,
        vm,
        command,
    })
}

fn absolute(path: PathBuf) -> PathBuf {
    std::env::current_dir().map_or(path.clone(), |cwd| cwd.join(path))
}

/// What every run gets on top of the flags: the current dir and the temp dirs writable, credentials
/// hidden, and no way to start a process outside the sandbox
fn defaults(policy: &mut Policy, backend: Backend) -> Result<(), String> {
    let cwd = std::env::current_dir().map_err(|e| format!("current directory: {e}"))?;
    policy.writable.push(cwd);
    policy.writable.push(std::env::temp_dir());

    if backend == Backend::Seatbelt {
        policy.writable.push("/private/tmp".into());
        policy.apple_events = false;
        policy.no_exec.push(known::LAUNCHCTL.into());
        policy
            .no_exec
            .extend(known::setuid_binaries().iter().cloned());
    }

    policy.own_signals = true;

    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        policy.hidden.extend(known::credentials(&home));
        policy.hidden.push(home.join(".gnupg"));
    }

    Ok(())
}

unsafe extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
}

const SIGINT: i32 = 2;
const SIG_IGN: usize = 1;

// The guest shares only what the flags name, so none of the host defaults apply
fn exec_in_vm(image: &str, mut args: ExecArgs) -> Result<ExitCode, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("current directory: {e}"))?;
    args.policy.writable.insert(0, cwd.clone());
    let vm = Vm::tart(image, &args.policy).map_err(|e| e.to_string())?;

    // Ctrl-C reaches the guest command through tart exec, and this process stays to delete the clone
    // Safe: ignoring a signal changes no state but the disposition of SIGINT
    unsafe {
        signal(SIGINT, SIG_IGN);
    }

    let status = vm
        .command(&cwd, &args.command)
        .status()
        .map_err(|e| format!("tart exec: {e}"))?;
    drop(vm);
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn exec(args: &[OsString]) -> Result<ExitCode, String> {
    let mut args = parse_exec(args)?;

    if let Some(image) = args.vm.take() {
        return exec_in_vm(&image, args);
    }

    let backend = Backend::detect().map_err(|e| e.to_string())?;
    defaults(&mut args.policy, backend)?;
    let sandbox = Sandbox::new(backend, args.policy).map_err(|e| e.to_string())?;
    let mut cmd = sandbox.command(&args.command[0]);
    cmd.args(&args.command[1..]);

    if args.dry_run {
        let argv: Vec<String> = std::iter::once(cmd.get_program())
            .chain(cmd.get_args())
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        println!("{}", argv.join(" "));
        return Ok(ExitCode::SUCCESS);
    }

    // exec only returns on failure, and the sandboxed command then owns this process's exit code
    Err(format!(
        "{}: {}",
        args.command[0].to_string_lossy(),
        cmd.exec()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<ExecArgs, String> {
        parse_exec(&list.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn one_string_runs_through_sh() {
        let a = args(&["--no-network", "rm -rf ~"]).unwrap();
        assert_eq!(a.command, ["/bin/sh", "-c", "rm -rf ~"]);
        assert!(!a.policy.network);
    }

    #[test]
    fn a_program_after_the_separator_runs_as_is() {
        let a = args(&["-w", "/out", "--", "ls", "-la"]).unwrap();
        assert_eq!(a.command, ["ls", "-la"]);
        assert_eq!(a.policy.writable, [PathBuf::from("/out")]);
    }

    #[test]
    fn refuses_no_command_and_unknown_options() {
        assert!(args(&[]).is_err());
        assert!(args(&["--frobnicate", "x"]).is_err());
        assert!(args(&["--write"]).is_err());
    }

    #[test]
    fn vm_takes_a_tart_image() {
        let a = args(&["--vm", "tart:ghcr.io/cirruslabs/ubuntu:24.04", "true"]).unwrap();
        assert_eq!(a.vm.as_deref(), Some("ghcr.io/cirruslabs/ubuntu:24.04"));
        assert!(args(&["--vm", "ubuntu", "true"]).is_err());
        assert!(args(&["--vm"]).is_err());
    }
}
