# Branch consolidation rule (AUTHORITY) — 2026-08-29

**Canonical tree:** `main` @ `d7651c5f0` (and successors).  
**Preserve everything. Inspect before integrating. No deletions. No wholesale merges of stale ancestry.**

## Live remote branches (audit)

- `main` — canonical engineering line
- `master` — GitHub default; **1 ahead / 4048 behind** `main`; unique tip moves 391 root entries → `_overflow/`
- 3 Dependabot branches — rooted on stale `master`, not current `main`

## Forbidden

- `git merge master`
- `git merge <dependabot-branch>` when ancestry includes the stale `_overflow/` move
- Deleting branches used as provenance
- Blindly replaying rename/move mass operations onto today's tree

## Required procedure

1. `main` remains canonical.
2. Inspect each non-main branch against its merge-base with `main`.
3. Extract **only** that branch's unique functional changes (cherry-pick / patch transplant).
4. Apply onto current `main`.
5. Preserve existing `main` paths unless a change absolutely requires modification.
6. Build/test after each imported change.
7. Keep original branches untouched as provenance.
8. Future branches get the same treatment.

## Next integration work (queued, not executed here)

1. Transplant the three Dependabot unique dependency updates onto `main` (strip stale `_overflow/` ancestry).
2. Separately evaluate whether `_overflow/` organization has residual value in today's tree.
3. Switch GitHub default branch `master` → `main` when a safe settings API/UI path is available (not altered in this freeze).

## Engineering progression (unchanged)

```
03c0e3651 → d7651c5f0 → next gate = AGENT-E2E-002
```
