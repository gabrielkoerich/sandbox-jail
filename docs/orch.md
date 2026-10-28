# Plan: orch agents in the sandbox

Status: plan, 2026-10-28. Orch is the second user of this crate, after shipcheck.

## What it is

Orch wraps each agent process in the OS sandbox. The sandbox limits which files the agent can write and read, and the network stays open. Orch builds the `Policy`, this crate enforces it.

## Why

Today isolation is per agent CLI and uneven:

| Agent | Isolation today |
|-------|-----------------|
| claude, kimi, minimax | `--disallowedTools` patterns (`Bash(rm *)`, `Read(<main dir>/*)`). They match the command text, so `bash -c`, `python` or `/bin/rm` gets past them |
| codex | Its own Seatbelt, `--sandbox workspace-write`, plus `--add-dir` for git dirs |
| grok | `--sandbox off` for tasks, the CLI cannot add the git dir |
| opencode | None, it runs with `--dangerously-skip-permissions` and ignores the deny list |

One OS-level policy gives every agent the same limits, and the kernel enforces it.

## Where it plugs in

All task and review agents start in one place. `build_tmux_runner_scripts()` (`src/engine/runner/agent.rs`) writes `agent_cmd.sh`:

```bash
{agent_cmd} 2>{stderr_file}
```

With the sandbox, `Sandbox::argv()` goes in front:

```bash
{argv...} /bin/bash -c {agent_cmd} 2>{stderr_file}
```

The redirect, `script`, `tee` and tmux stay outside the sandbox, so `output.json`, `stderr.txt` and `exit.txt` in the attempt dir need no write rule. `review.rs` uses `spawn_in_tmux` too and gets the sandbox with no extra work.

Not covered in the first phase: `direct.rs` (control session, router) and `control.rs`. They run `orch` CLI commands that write `orch.db`, and they already use `deny_read_only`.

## What the probes showed

Run on macOS 26 (Darwin 25.6) with a profile of `(allow default)`, `(deny file-write*)`, writes allowed in a temp worktree, and reads of `~/.ssh` and `~/.orch/orch.db` denied:

| Check | Result |
|-------|--------|
| Write inside the worktree | Works |
| Write outside | `Operation not permitted` |
| Read `~/.ssh` | `Operation not permitted` |
| Keychain (`security find-generic-password`, Claude OAuth) | Works, it goes through `securityd`, not a file |
| `claude -p` writes a file and commits, no home writes | Works |
| `codex exec` with no home writes | Fails, cannot write `~/.codex` |
| `codex exec` with `~/.codex` writable | Starts and reaches the API |
| `opencode run` with no home writes | Fails, cannot write `~/.local/share/opencode/log` |
| `sandbox-exec` inside `sandbox-exec` | `sandbox_apply: Operation not permitted`, exit 71 |
| `$HOME` writable, then `~/.zshrc` and `.git/hooks` denied | The deny wins |

Seatbelt cannot nest, so with the sandbox on, codex runs with `--dangerously-bypass-approvals-and-sandbox` and the outer sandbox does the job. Its `--add-dir` handling and the shipcheck rule escape stop mattering.

## Policy

| Field | Value |
|-------|-------|
| `writable` | The task worktree, its `--git-dir` and `--git-common-dir` (`resolve_git_dir_arg()` finds both), `$TMPDIR`, `/private/tmp`, `$HOME` |
| `read_only` | `<git common dir>/hooks` and `<git common dir>/config`, the main checkout of every configured project except its `.git`, every entry of `~/.orch` but the task's worktree and git dir, `~/.ssh`, `~/.gnupg`, `~/Library/LaunchAgents`, `~/.local/bin`, `~/bin`, and the shell and git startup files (`~/.zshrc`, `~/.zshenv`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.gitconfig`, `~/.config/git`) |
| `hidden` | `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/Library/Keychains` |
| Everything else | The default: readable, network open, all sockets and Mach services |

Why each line:

- `$HOME` writable covers agent state (`~/.claude`, `~/.codex`, `~/.local/share/opencode`) and every language's caches without naming any.
- A hook or `core.hooksPath` written in the git common dir runs outside the sandbox the next time the operator runs git.
- The startup files, `~/.local/bin` and `LaunchAgents` run later as the operator.
- A `read_only` path wins over a `writable` one, so `~/.orch` cannot be one rule with the worktree as an exception. Orch lists the entries of `~/.orch` and of `~/.orch/worktrees` and leaves out the task's own.
- `~/.orch` stays readable. Job prompts read `orch.db` and `~/.orch/state/*/tasks/*/attempts/`, and agents read the template under `~/.orch/state/templates/<project>` and the main checkout.
- Job agents run `orch task list` and `orch task runs`, which write `orch.db-wal` and `orch.db-shm`. Internal (job) tasks get `orch.db*` writable, GitHub-issue tasks do not.

Rejected: an allowlist of tool caches (`~/.cargo`, `~/.npm`, `~/.bun`). It is tighter, but it puts per-language logic in orch, which orch #3674 rejected, and it breaks the first time a project uses a tool that is not on it.

## Shipcheck inside the sandbox

An agent that runs `shipcheck run` or `shipcheck commit`, as orch's `prompts/agent_system.md` tells it to, gets shipcheck's nested sandbox error and no checks run. An outer sandbox around the whole agent has no per-command exemption.

| Option | Cost |
|--------|------|
| A. With the sandbox on, the agent prompt drops `shipcheck run`. The pre-push hook runs checks when orch pushes, outside the sandbox, and the daemon runs them on the PR head | The agent loses its loop of check, fix, commit. Failures come back a cycle later |
| B. `shipcheck run` inside a sandbox asks the shipcheck daemon over a local socket to run the checks on the worktree, in shipcheck's own jail. The policy allows that one socket | A new daemon socket in shipcheck, which must accept only worktrees of installed repositories |
| C. Orch runs `shipcheck run` outside the sandbox after the agent exits, and re-dispatches on failure | Same loop loss as A, and the shipcheck call moves into orch's runner |

Recommendation: A while the sandbox is opt-in, then B. B keeps the agent's loop and shipcheck's guarantees, and other agents' sandboxes (codex, Claude Code's own) get the same fix.

## Changes in orch

1. `SandboxLevel::Os`, set by `workflow.permissions.sandbox: os`. It is opt-in, and the operator sets it in `config.yml`.
2. `spawn_in_tmux` builds the `Policy` above. The git dir lookup runs for codex only today and moves out of that `if`.
3. `build_tmux_runner_scripts` writes `Sandbox::argv()` in front of the agent command.
4. Codex maps `SandboxLevel::Os` to `--dangerously-bypass-approvals-and-sandbox`. Grok already runs `--sandbox off` for tasks. Claude's `--disallowedTools` patterns stay as a second layer.
5. When `Backend::detect()` fails with `sandbox: os` set, the task blocks with the error. It never falls back to running unsandboxed.
6. A sandbox denial blocks the task with the denied path in `block_reason`. It is a policy gap for the operator, so it must not cool down the agent or the model. `detect_permission_denied` already matches `operation not permitted`. The path comes from the agent's stderr or the Seatbelt log (`log show --predicate 'sender == "Sandbox"'`).
7. Docs: orch's `docs/content/agents.md` and `configuration.md` get the `os` level, the policy and how to read a denial.

## Phases

1. This crate, and shipcheck on it.
2. Orch steps 1 to 5, task and review agents only, with shipcheck option A.
3. Denial reporting (step 6). Then run it on the operator's projects and widen the policy where real tasks hit it.
4. Control session and router (`direct.rs`), with `orch.db` writable.

## Costs

- A `$HOME` denylist is weaker than an allowlist. A path that should be denied and is not on the list stays writable.
- The network stays open, so an agent can still send out anything it can read. `hidden` covers keys only.
- Codex loses its own sandbox. The outer one is stricter on paths, but a bug in orch's policy is now the only layer.
- A denial blocks a task that ran before. Expect a few blocked tasks in phase 3 until the policy settles.

## Open items

- Shipcheck option B: design the daemon socket in shipcheck.
- Opencode hung on the test machine even without the sandbox, so it was not verified.
