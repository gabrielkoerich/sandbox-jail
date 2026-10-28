# sandbox-jail

[![CI](https://github.com/gabrielkoerich/sandbox-jail/actions/workflows/ci.yml/badge.svg)](https://github.com/gabrielkoerich/sandbox-jail/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/gabrielkoerich/sandbox-jail)](https://github.com/gabrielkoerich/sandbox-jail/releases/latest) [![crates.io](https://img.shields.io/crates/v/sandbox-jail)](https://crates.io/crates/sandbox-jail) [![docs.rs](https://img.shields.io/docsrs/sandbox-jail)](https://docs.rs/sandbox-jail) [![License](https://img.shields.io/crates/l/sandbox-jail)](LICENSE)

Run a command in a sandbox under a policy the caller defines: Seatbelt (`sandbox-exec`) on macOS, bubblewrap (`bwrap`) on Linux, or a throwaway tart or lume VM. The crate turns the policy into a Seatbelt profile, `bwrap` arguments or VM shares, and refuses a policy it cannot enforce before anything runs.

## Command line

```bash
cargo install sandbox-jail

sandbox-jail exec "curl -fsSL https://example.com/install.sh | sh"   # one string runs with sh -c
sandbox-jail exec -w ~/out --no-network -- make build                # a program and its arguments
sandbox-jail exec --dry-run true                                     # print the sandbox command
sandbox-jail exec --vm tart:ghcr.io/cirruslabs/ubuntu:24.04 make     # in a throwaway tart VM
sandbox-jail exec --vm lume:ubuntu-noble-vanilla_latest make         # in a throwaway lume VM
```

`exec` may write the current directory and the temp dirs, and nothing else. Credentials in your home are hidden, signals reach only its own processes, and on macOS it cannot run `launchctl` or a setuid binary such as `sudo`. `-w` adds a writable path, `-r` a read-only one inside it, `--hide` an unreadable one. The exit code is the command's, or 2 when the sandbox cannot start.

With `--vm` the command runs in a clone of the image instead, deleted when it ends. The guest has its own kernel and sees only the current directory and the `-w` paths, each at its host path. See [VMs](#vms) for what each image needs.

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

`sandbox_jail::vm::Vm::tart(image, &policy)` and `Vm::lume(image, &policy)` boot a clone with the policy's `writable` dirs shared read-write and its `readable` dirs read-only. `vm.command(dir, &argv)` runs a command in the guest, and dropping the handle stops and deletes the clone.

`sandbox_jail::known` has lists a caller can opt into: credential paths, an env filter for credentials, the temp dirs, the Mach services common tools need, the setuid binaries and `launchctl`.

On macOS, `sandbox_jail::macos::sandboxed()` and `sandbox_jail::macos::denies()` ask the kernel about the sandbox the current process runs in.

## Rules

- The caller defines the whole policy. The crate holds no policy of its own, and `sandbox_jail::known` holds lists a caller opts into, never defaults it gets silently.
- The caller names the backend for each use, or takes `Backend::detect()`.
- A backend checks the policy before anything runs and refuses what it cannot enforce. A rule that silently does nothing is worse than an error.
- Every path is resolved first. Seatbelt matches the real path, so `/tmp` must become `/private/tmp`.
- Seatbelt matches the path at each access, so renaming a parent would move a ruled path out from under its rule. Every parent of a `read_only`, `pinned` or `hidden` path inside a writable dir is pinned: it stays in place, and what is inside it stays writable. bwrap needs nothing here, since its mounts move with a renamed parent and a hard link cannot cross them.

## Policy

| Field | Meaning | Seatbelt | bwrap |
|-------|---------|----------|-------|
| `writable` | May write, and read inside `unreadable` | `subpath` allow | `--bind`, must exist |
| `read_only` | May not write, even inside `writable` | `subpath` deny, and its parents pinned | `--ro-bind` |
| `pinned` | May not replace or remove the path itself | `literal` deny | Refused |
| `unreadable` | May not read files in it | `file-read-data` deny | Empty `--tmpfs`, read-only once every mount in it exists |
| `readable` | Exceptions inside `unreadable` | `file-read-data` allow | `--ro-bind` |
| `scratch` | Starts empty and writable, writes go away with the command | Refused, macOS cannot give one process an empty directory | Writable `--tmpfs`, refused inside a bound path |
| `hidden` | May not read, list, write or rename, wins over everything | `file-read*` and `file-write*` deny, and its parents pinned | `--tmpfs` or `/dev/null` over it |
| `network` | TCP and UDP | `remote ip` deny | `--unshare-net` |
| `unix_sockets` | Sockets it may connect to, by directory | `remote unix-socket` filters, plus the DNS resolver | Only what `unreadable` and `hidden` keep out of reach. Abstract sockets stay reachable unless `network` is off |
| `mach_services` | macOS services it may look up | `mach-lookup` allowlist | Not applicable |
| `apple_events` | May send Apple events | `appleevent-send` deny | Not applicable |
| `own_signals` | Signals reach only its own processes | `signal` same-sandbox | Always, pid namespace |
| `own_terminals` | Only pseudo-terminals it opened | `com.apple.sandbox.pty` extension | `--new-session` |
| `no_exec` | Binaries it may not run | `process-exec*` deny | Refused. bwrap runs setuid binaries without privileges |
| `overlays` | Writes go to a layer over a directory | Refused | `--overlay`. `overlay_supported(dir)` says up front whether this bwrap and kernel mount one: it needs bwrap 0.10 or later, and overlayfs refuses layers on another overlay |

bwrap skips a path that does not exist yet, but for `writable`, which it refuses. Build the sandbox right before running the command.

## VMs

A clone shares the policy's `writable` and `readable` dirs and puts each at its host path: a bind mount of the virtiofs share in a Linux guest, a symlink to `/Volumes/My Shared Files` in a macOS guest. The guest sees nothing else of the host, so `unreadable`, Mach services, Apple events, signals and terminals hold without a rule. What a guest cannot enforce is refused:

| Rule | Why |
|------|-----|
| `read_only`, `pinned`, `hidden` inside a share | A share is a whole directory |
| `scratch`, `overlays` | The clone's own disk already starts fresh |
| `no_exec` | The guest runs its own binaries, and root in it is not root on the host |
| `network = false` | tart and lume have NAT, bridged and host-only networks, none of which reaches nothing |
| `unix_sockets` with paths | A host socket does not cross into the guest |

| | tart | lume |
|---|---|---|
| Images | `ghcr.io/cirruslabs/ubuntu`, `macos-*-base`, any image with the Tart Guest Agent and passwordless sudo | `ubuntu-noble-vanilla`, `macos-*-vanilla`, any image with SSH and the `lume` user |
| Commands | `tart exec`: stdin, stdout, stderr and the exit code pass through | `lume ssh`: no stdin, and stderr arrives on stdout. The exit code passes through |
| Shares | Named by the crate | Named after their last path component, so two with the same name are refused |
| Boot to the first command, M4 Max | Linux about 3 s, macOS about 20 s | Linux about 2 min, macOS about 11 s |

## Limits

- Apple marks `sandbox-exec` deprecated. Codex and Claude Code still use it, and nothing replaces it for an unsigned CLI. If Apple removes it, the macOS backend goes.
- Seatbelt cannot nest. A tool that sandboxes its own children fails inside a caller's sandbox and must run outside it, and `Backend::detect()` returns `Error::Nested` there.
- Under Seatbelt, the parents of a ruled path cannot be renamed, deleted or have their mode changed. With `$HOME` writable and `~/.ssh` read-only, that includes `$HOME` itself.
- bwrap needs unprivileged user namespaces. Ubuntu 23.10 and later restrict them with AppArmor, and `Backend::detect()` names the fix.
- A VM sees no host toolchain. The image has to carry every tool the command needs, and a macOS image is 25 GB or more. Apple allows two macOS VMs at once per Mac.

## Development

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The tests in `tests/sandbox.rs` run real commands in the sandbox. On Linux they need bubblewrap and unprivileged user namespaces. A container's root is an overlay, which overlayfs will not stack on, so `TMPDIR` points the tests at a tmpfs. To run them from a Mac:

```bash
docker run --rm --privileged -e TMPDIR=/dev/shm -e SANDBOX_JAIL_EXPECT_OVERLAY=1 -v "$PWD":/src:ro rust:1-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq bubblewrap && cp -r /src /work && cd /work && cargo test'
```

The tests in `tests/vm.rs` boot real tart and lume clones, so they are ignored by default: `cargo test --test vm -- --ignored`. `SANDBOX_JAIL_{TART,LUME}_{LINUX,MACOS}` pick other images.
