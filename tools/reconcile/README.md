# Branch Reconciliation Planner

`reconcile.ps1` analyzes divergence between a branch and a target (default
`origin/main`) and emits a **non-destructive** integration plan. It never
force-pushes, resets, rebases, or rewrites the shared branch; with `-Execute` it
only creates a NEW local integration branch (no push).

## Key finding (current repo)

`origin/main` (`1c7d6a0000`) and `origin/fix/ide-default-model-scan`
(`ca9f2c2c1b`) have **no common ancestor** (`git merge-base` is empty). The
divergence is therefore **unrelated histories**, not a normal ahead/behind: the
branch is ~773 ahead / ~3195 behind with no shared base. A plain rebase or 3-way
merge is impossible without `--allow-unrelated-histories`.

## Safe strategy (emitted by the tool)

1. Do NOT rebase/merge the shared branch directly (would replay commits with no base).
2. Create a throwaway integration branch from the branch tip:
   `git branch integrate/<target>-recon <branch>`
3. Merge the target with unrelated histories (review conflicts):
   `git merge --allow-unrelated-histories <target> -m 'integrate: ...'`
4. Regression-test the integration branch; open a reviewed PR.
5. NEVER force-push, reset, or rewrite the shared branch or target.

## Usage

```powershell
pwsh tools/reconcile/reconcile.ps1 -Target origin/main -Branch origin/fix/ide-default-model-scan
pwsh tools/reconcile/reconcile.ps1 -Target origin/main -Execute   # creates local integrate/* branch only
```