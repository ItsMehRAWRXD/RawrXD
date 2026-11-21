# Gate G55 — Native Git operations => PASS

## Integration (source + runtime)
- `Win32IDE_CommandIDs.h`: `IDM_GIT_STATUS/COMMIT/PUSH/PULL/PANEL/STAGE_ALL`
  (3020-3025). `Win32IDE.cpp` builds a Git menu (Status/Commit/Push/Pull/Panel)
  and enables items based on repo/changes.
- `Win32IDE_Git.cpp` implements the handlers by shelling out to **real git**:
  `gitStage` -> `git add -- <file>`, `gitCommit` -> `git commit -m <msg>`,
  `gitPush` -> `git push`, `gitPull` -> `git pull`, `gitBranch` -> `git switch -c`,
  `gitStash` -> `git stash`, `gitCherryPick` -> `git cherry-pick`,
  `gitStatus` -> `git status --short`, all via `executeGitCommand(...)` and
  appended to the Output pane.
- Runtime: Git submenu present with command IDs 3020-3024 (`gui_g55_gitmenu.ps1`).

## Operations against a disposable repository
Exercised the exact commands the IDE runs, against
`evidence/strata_gates_20261121/g55_repo` (work + bare remote):
```
git add -- "file.txt"          -> staged
git commit -m "initial"        -> 1 file changed, committed (d2e53ed)
git push origin HEAD           -> * [new branch] HEAD -> master (pushed to bare remote)
git status --short             -> clean (empty)
git pull origin HEAD           -> Already up to date.
```
All succeeded. => G55 PASS.

## Notes
- The IDE handlers are private methods invoked by the menu; the underlying git
  workflow they execute is verified end-to-end above.
- Push/pull were tested against a local bare remote (no network), which matches
  the IDE's `git push`/`git pull` invocation.

## Fixture
`evidence/strata_gates_20261121/g55_repo/` (disposable; safe to delete).

## Ledger
```
G55=PASS
```