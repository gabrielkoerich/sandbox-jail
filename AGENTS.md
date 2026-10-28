<!-- shipcheck:start v3 -->

## Tests and commits

- Work on a branch, never on the default branch: `git switch -c <branch>`. Then `shipcheck run`, `shipcheck commit`, push, and open a PR. The PR carries the checks.
- Do not run the test commands (`pytest`, `cargo test`, `npm test`, `go test`, `just test` and the like). Run `shipcheck run`. It runs this repository's CI on your working copy, and its result is the PR's required check.
- Commit with `shipcheck commit -m "<subject>"`, never `git commit`. It commits every file, exactly the tree that passed.
- Work in small steps: one change, `shipcheck run`, `shipcheck commit`. Delete scratch files first, because every file is committed.
- Exit 1: read `shipcheck logs`, fix, then `shipcheck run --job <id>` for the failed job as often as needed. A partial run is never the check, so finish with one full `shipcheck run`, then `shipcheck commit`. Exit 2: shipcheck could not run, so run `shipcheck doctor` and follow it.
- If `shipcheck` is not on PATH, run the project's tests and commit with git.
- Never edit `.github/workflows/` or `shipcheck.toml` to get a pass. Details: https://shipcheck.run/llms.txt

<!-- shipcheck:end -->
