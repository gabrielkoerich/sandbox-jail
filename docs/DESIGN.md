# Design

## What it is

A library that runs a command under a path policy enforced by the kernel. Seatbelt on macOS, bubblewrap on Linux. It started as the `Jail` in shipcheck's `src/runner/host.rs`, with every choice shipcheck made for its checks turned into a policy field.

## Rules

- The caller defines the whole policy. The crate holds no policy of its own. `jail::known` has lists a caller opts into, never defaults it gets silently.
- The caller names the backend for each use, or takes `Backend::detect()`.
- `Sandbox::new` checks the policy against the backend and refuses what that backend cannot enforce, before anything runs. A rule that silently does nothing is worse than an error.
- Every path is resolved first. Seatbelt matches the real path, so `/tmp` must become `/private/tmp`.

## What came from shipcheck

| Piece | shipcheck | Here |
|-------|-----------|------|
| Seatbelt profile | `Jail::profile()` | `seatbelt::profile()`, every rule behind a policy field |
| bwrap arguments | `Jail::bwrap_args()` | `bwrap::argv()` |
| Detection, nested sandbox probe, AppArmor fix | `sandbox()`, `userns_fix()` | `Backend::detect()`, `Error::Nested` |
| Kernel query | `in_a_jail()` | `macos::sandboxed()`, `macos::denies()`. shipcheck builds its `in_a_jail()` from them |
| Lists | `SECRETS`, `MACH_SERVICES`, `TEMP`, `setuid()`, `LAUNCHCTL`, `refused_env()` | `known::*` |

What stays in shipcheck: the environment it builds for a check, its `TOOLCHAINS` list, its caches and the launchd jobs that kill a check's whole process tree. The launchd code is a candidate for this crate once a second user needs it.

## Where the backends differ

| Case | Behavior | Why |
|------|----------|-----|
| `pinned`, `no_exec` under bwrap | Refused | bwrap has no rule for either. It runs setuid binaries without privileges, which covers what `no_exec` is for in shipcheck |
| `overlays` under Seatbelt | Refused | macOS has no overlay mount |
| `unix_sockets` under bwrap | A socket is out of reach only when `unreadable` or `hidden` covers its directory. Abstract sockets stay reachable unless `network` is off | bwrap has no socket filter. shipcheck relies on the same hiding today |
| `unreadable` under bwrap | An empty directory, read-only once every mount in it exists | Matches Seatbelt, where writes there are already denied. shipcheck left its `/tmp` and `/run` writable on Linux, so a check that writes there fails after the move |
| Missing paths under bwrap | `writable` refused, others skipped | `--bind` needs a source. Build the sandbox right before running |
| `mach_services`, `apple_events` under bwrap | Ignored | Linux has neither |

## Rejected

| Alternative | Why not |
|-------------|---------|
| A VM backend (lume, tart) now | It needs an image, a boot and a share, and it cannot see host toolchains. The interface leaves room for it. Nothing needs it yet |
| A copy of the profile code in orch | Two copies of rules shipcheck already tested (setuid, `launchctl`, AppArmor, Mach services) would drift |
| `ai-jail` | A CLI with no library target, under GPL-3.0 |
| Anthropic `sandbox-runtime` | TypeScript |
| `jail` as the package name | A FreeBSD jail library holds it on crates.io. The library is still `jail` |

## Costs

- Apple marks `sandbox-exec` deprecated. Codex and Claude Code still use it, and nothing replaces it for an unsigned CLI. If Apple removes it, the macOS backend goes.
- Seatbelt cannot nest. A tool that sandboxes its own children, like shipcheck, fails inside a caller's sandbox and must run outside it.
- bwrap needs unprivileged user namespaces. Ubuntu 23.10 and later restrict them with AppArmor, and `Backend::detect()` names the fix.
- Under bwrap, `unix_sockets` depends on hiding, see above.

## Next

1. Move shipcheck to this crate with no change in behavior, apart from the read-only `unreadable` dirs on Linux.
2. Orch, see [orch.md](orch.md).
3. The launchd process tree kill, when orch needs it.
