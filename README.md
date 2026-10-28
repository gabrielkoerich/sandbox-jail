# sandbox-jail

Run a command in the OS sandbox: Seatbelt (`sandbox-exec`) on macOS, bubblewrap (`bwrap`) on Linux. The caller defines the whole policy, and the crate turns it into a Seatbelt profile or `bwrap` arguments. A backend refuses a policy it cannot enforce before anything runs.

The package is `sandbox-jail`, the library is `jail`.

```rust
use jail::{Access, Backend, Policy, Sandbox};

let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
let policy = Policy {
    writable: vec![worktree.clone(), std::env::temp_dir()],
    read_only: vec![worktree.join(".git/hooks")],
    hidden: jail::known::credentials(&home),
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
| `read_only` | May not write, even inside `writable` | `subpath` deny | `--ro-bind` |
| `pinned` | May not replace or remove the path itself | `literal` deny | Refused |
| `unreadable` | May not read files in it | `file-read-data` deny | Empty read-only `--tmpfs` |
| `readable` | Exceptions inside `unreadable` | `file-read-data` allow | `--ro-bind` |
| `hidden` | May not read or list, wins over everything | `file-read*` deny | `--tmpfs` or `/dev/null` over it |
| `network` | TCP and UDP | `remote ip` deny | `--unshare-net` |
| `unix_sockets` | Sockets it may connect to, by directory | `remote unix-socket` filters, plus the DNS resolver | Only what `unreadable` and `hidden` keep out of reach |
| `mach_services` | macOS services it may look up | `mach-lookup` allowlist | Not applicable |
| `apple_events` | May send Apple events | `appleevent-send` deny | Not applicable |
| `own_signals` | Signals reach only its own processes | `signal` same-sandbox | Always, pid namespace |
| `own_terminals` | Only pseudo-terminals it opened | `com.apple.sandbox.pty` extension | `--new-session` |
| `no_exec` | Binaries it may not run | `process-exec*` deny | Refused |
| `overlays` | Writes go to a layer over a directory | Refused | `--overlay` |

`jail::known` has lists a caller can opt into: credential paths, an env filter for credentials, the temp dirs, the Mach services common tools need, the setuid binaries and `launchctl`. None applies unless the caller puts it in its policy.

On macOS, `jail::macos::sandboxed()` and `jail::macos::denies()` ask the kernel about the sandbox the current process runs in. macOS cannot start a sandbox inside another one, and `Backend::detect()` returns `Error::Nested` there.

## Development

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The tests in `tests/sandbox.rs` run real commands in the sandbox. On Linux they need bubblewrap and unprivileged user namespaces. To run them from a Mac:

```bash
docker run --rm --privileged -v "$PWD":/src:ro rust:1-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq bubblewrap && cp -r /src /work && cd /work && cargo test'
```

See [docs/DESIGN.md](docs/DESIGN.md) for why it is built this way, and [docs/orch.md](docs/orch.md) for the first planned user.
