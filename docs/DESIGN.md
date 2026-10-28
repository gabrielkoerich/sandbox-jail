# Design

## What it is

A library that runs a command under a path policy enforced by the kernel. Seatbelt on macOS, bubblewrap on Linux. It started as the `Jail` in shipcheck's `src/runner/host.rs`, with every choice shipcheck made for its checks turned into a policy field.

## Rules

- The caller defines the whole policy. The crate holds no policy of its own. `sandbox_jail::known` has lists a caller opts into, never defaults it gets silently.
- The caller names the backend for each use, or takes `Backend::detect()`.
- `Sandbox::new` checks the policy against the backend and refuses what that backend cannot enforce, before anything runs. A rule that silently does nothing is worse than an error.
- Every path is resolved first. Seatbelt matches the real path, so `/tmp` must become `/private/tmp`.
- Seatbelt matches the path at each access, so renaming a parent would move a ruled path out from under its rule. Every parent of a `read_only`, `pinned` or `hidden` path inside a writable dir is pinned: it stays in place, and what is inside it stays writable. bwrap needs nothing here, its mounts move with a renamed parent and a hard link cannot cross them.

## What came from shipcheck

| Piece | shipcheck | Here |
|-------|-----------|------|
| Seatbelt profile | `Jail::profile()` | `seatbelt::profile()`, every rule behind a policy field |
| bwrap arguments | `Jail::bwrap_args()` | `bwrap::argv()` |
| Detection, nested sandbox probe, AppArmor fix | `sandbox()`, `userns_fix()` | `Backend::detect()`, `Error::Nested` |
| Kernel query | `in_a_jail()` | `sandbox_jail::macos::sandboxed()`, `sandbox_jail::macos::denies()`. shipcheck builds its `in_a_jail()` from them |
| Lists | `SECRETS`, `MACH_SERVICES`, `TEMP`, `setuid()`, `LAUNCHCTL`, `refused_env()` | `sandbox_jail::known` |

What stays in shipcheck: the environment it builds for a check, its `TOOLCHAINS` list, its caches and the launchd jobs that kill a check's whole process tree. The launchd code is a candidate for this crate once a second user needs it.

## Where the backends differ

| Case | Behavior | Why |
|------|----------|-----|
| `pinned`, `no_exec` under bwrap | Refused | bwrap has no rule for either. It runs setuid binaries without privileges, which covers what `no_exec` is for in shipcheck |
| `overlays` under Seatbelt | Refused | macOS has no overlay mount |
| `unix_sockets` under bwrap | A socket is out of reach only when `unreadable` or `hidden` covers its directory. Abstract sockets stay reachable unless `network` is off | bwrap has no socket filter. shipcheck relies on the same hiding today |
| `unreadable` under bwrap | An empty directory, read-only once every mount in it exists | Matches Seatbelt, where writes there are already denied |
| `scratch` under Seatbelt | Refused | macOS cannot give one process an empty directory. shipcheck sets it on Linux only, for the writable `/tmp`, `/run` and `/var/tmp` each check gets today |
| `overlays` | `overlay_supported(dir)` says up front whether this bwrap and kernel mount one | It needs bwrap 0.10 or later and overlayfs in a user namespace, and overlayfs refuses layers on another overlay. shipcheck uses the answer to choose between an overlay and a copy |
| Missing paths under bwrap | `writable` refused, others skipped | `--bind` needs a source. Build the sandbox right before running |
| `mach_services`, `apple_events` under bwrap | Ignored | Linux has neither |

## VMs

`vm::Vm::tart` clones an image, boots it headless with `--dir` shares and waits for the Tart Guest Agent. It then puts each share at its host path: a bind mount of the virtiofs share in a Linux guest, a symlink to `/Volumes/My Shared Files` in a macOS guest. Commands run through `tart exec`, which passes stdin, the exit code and output through. Dropping the handle stops and deletes the clone.

The guest sees nothing of the host but its shares, so `unreadable`, Mach services, Apple events, signals and terminals hold without a rule. What it cannot enforce is refused:

| Rule | Why |
|------|-----|
| `read_only`, `pinned`, `hidden` inside a share | A share is a whole directory |
| `scratch`, `overlays` | The clone's own disk already starts fresh |
| `no_exec` | The guest runs its own binaries, and root in it is not root on the host |
| `network = false` | tart has NAT, softnet and host-only networks, none of which reaches nothing |
| `unix_sockets` with paths | A host socket does not cross into the guest |

Measured on an M4 Max: a `cirruslabs/ubuntu:24.04` clone answers `tart exec` in about 3 s, a `macos-tahoe-base` clone in about 20 s. lume comes next, on the same handle. Its `lume ssh` drops stdin, names shares after their last path component and needs the image's password for sudo, and its Ubuntu image takes about 2 minutes to boot.

## Rejected

| Alternative | Why not |
|-------------|---------|
| A VM as a `Backend` | A VM needs a boot before the command and a cleanup after it, so it cannot be an argv prefix. `vm::Vm` is a handle that deletes its clone on drop |
| A copy of the profile code in orch | Two copies of rules shipcheck already tested (setuid, `launchctl`, AppArmor, Mach services) would drift |
| `ai-jail` | A CLI with no library target, under GPL-3.0 |
| Anthropic `sandbox-runtime` | TypeScript |
| `jail` as the name | A FreeBSD jail library holds it on crates.io. `sandbox-jail` also says what it is to someone searching for a sandbox, and the package, the import and docs.rs all match |

## Costs

- Apple marks `sandbox-exec` deprecated. Codex and Claude Code still use it, and nothing replaces it for an unsigned CLI. If Apple removes it, the macOS backend goes.
- Under Seatbelt, the parents of a ruled path cannot be renamed, deleted or have their mode changed. With `$HOME` writable and `~/.ssh` read-only, that includes `$HOME` itself.
- A VM sees no host toolchain. The image has to carry every tool the command needs, and a macOS image is 25 GB or more.
- Seatbelt cannot nest. A tool that sandboxes its own children, like shipcheck, fails inside a caller's sandbox and must run outside it.
- bwrap needs unprivileged user namespaces. Ubuntu 23.10 and later restrict them with AppArmor, and `Backend::detect()` names the fix.
- Under bwrap, `unix_sockets` depends on hiding, see above.

## Next

1. Move shipcheck to this crate with no change in behavior.
2. Orch, see [orch.md](orch.md).
3. The launchd process tree kill, when orch needs it.
