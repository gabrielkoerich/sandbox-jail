# sandbox-jail

[![CI](https://github.com/gabrielkoerich/sandbox-jail/actions/workflows/ci.yml/badge.svg)](https://github.com/gabrielkoerich/sandbox-jail/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/gabrielkoerich/sandbox-jail)](https://github.com/gabrielkoerich/sandbox-jail/releases/latest) [![crates.io](https://img.shields.io/crates/v/sandbox-jail)](https://crates.io/crates/sandbox-jail) [![docs.rs](https://img.shields.io/docsrs/sandbox-jail)](https://docs.rs/sandbox-jail) [![License](https://img.shields.io/crates/l/sandbox-jail)](LICENSE)

Run a command in the OS sandbox: Seatbelt (`sandbox-exec`) on macOS, bubblewrap (`bwrap`) on Linux. The caller defines the whole policy, and the crate turns it into a Seatbelt profile or `bwrap` arguments. A backend refuses a policy it cannot enforce before anything runs.

## Command line

```bash
cargo install sandbox-jail

sandbox-jail exec "curl -fsSL https://example.com/install.sh | sh"   # one string runs with sh -c
sandbox-jail exec -w ~/out --no-network -- make build                # a program and its arguments
sandbox-jail exec --dry-run true                                     # print the sandbox command
```

`exec` may write the current directory and the temp dirs, and nothing else. Credentials in your home are hidden, signals reach only its own processes, and on macOS it cannot run `launchctl` or a setuid binary such as `sudo`. `-w` adds a writable path, `-r` a read-only one inside it, `--hide` an unreadable one. The exit code is the command's, or 2 when the sandbox cannot start.

## Library

Import it as `sandbox_jail`.

```rust
use sandbox_jail::{Access, Backend, Policy, Sandbox};

let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
let policy = Policy {
    writable: vec![worktree.clone(), std::env::temp_dir()],
    read_only: vec![worktree.join(".git/hooks")],
    hidden: sandbox_jail::known::credentials(&home),
    unix_sockets: Access::Only(vec![]),
    ..Policy::default()
};

let sandbox = Sandbox::new(Backend::detect()?, policy)?;
let status = sandbox.command("cargo").arg("test").current_dir(&worktree).status()?;
```

`Sandbox::argv()` gives the program and arguments that go before the command, for a caller that writes a script instead of spawning, such as one that runs the command in tmux.

## Policy

| Field | Meaning | Seatbelt | bwrap |
|-------|---------|----------|-------|
| `writable` | May write, and read inside `unreadable` | `subpath` allow | `--bind`, must exist |
| `read_only` | May not write, even inside `writable` | `subpath` deny, and its parents pinned | `--ro-bind` |
| `pinned` | May not replace or remove the path itself | `literal` deny | Refused |
| `unreadable` | May not read files in it | `file-read-data` deny | Empty read-only `--tmpfs` |
| `readable` | Exceptions inside `unreadable` | `file-read-data` allow | `--ro-bind` |
| `scratch` | Starts empty and writable, writes go away with the command | Refused | Writable `--tmpfs`, refused inside a bound path |
| `hidden` | May not read, list, write or rename, wins over everything | `file-read*` and `file-write*` deny, and its parents pinned | `--tmpfs` or `/dev/null` over it |
| `network` | TCP and UDP | `remote ip` deny | `--unshare-net` |
| `unix_sockets` | Sockets it may connect to, by directory | `remote unix-socket` filters, plus the DNS resolver | Only what `unreadable` and `hidden` keep out of reach |
| `mach_services` | macOS services it may look up | `mach-lookup` allowlist | Not applicable |
| `apple_events` | May send Apple events | `appleevent-send` deny | Not applicable |
| `own_signals` | Signals reach only its own processes | `signal` same-sandbox | Always, pid namespace |
| `own_terminals` | Only pseudo-terminals it opened | `com.apple.sandbox.pty` extension | `--new-session` |
| `no_exec` | Binaries it may not run | `process-exec*` deny | Refused |
| `overlays` | Writes go to a layer over a directory | Refused | `--overlay`, check first with `overlay_supported()` |

`sandbox_jail::known` has lists a caller can opt into: credential paths, an env filter for credentials, the temp dirs, the Mach services common tools need, the setuid binaries and `launchctl`. None applies unless the caller puts it in its policy.

On macOS, `sandbox_jail::macos::sandboxed()` and `sandbox_jail::macos::denies()` ask the kernel about the sandbox the current process runs in. macOS cannot start a sandbox inside another one, and `Backend::detect()` returns `Error::Nested` there.

## Development

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The tests in `tests/sandbox.rs` run real commands in the sandbox. On Linux they need bubblewrap and unprivileged user namespaces. A container's root is an overlay, which overlayfs will not stack on, so `TMPDIR` points the tests at a tmpfs. To run them from a Mac:

```bash
docker run --rm --privileged -e TMPDIR=/dev/shm -e SANDBOX_JAIL_EXPECT_OVERLAY=1 -v "$PWD":/src:ro rust:1-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq bubblewrap && cp -r /src /work && cd /work && cargo test'
```

See [docs/DESIGN.md](docs/DESIGN.md) for why it is built this way, and [docs/orch.md](docs/orch.md) for the first planned user.
