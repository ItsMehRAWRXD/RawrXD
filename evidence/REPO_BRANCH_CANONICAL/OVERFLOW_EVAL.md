# `_overflow/` independent evaluation — 2026-08-29

## Proposal (from `365daa6f3` on stale `master`)

Move ~391 root entries into `_overflow/` to mitigate GitHub directory truncation (claimed: root 1289 → 899).

## Verdict

| Decision | Status |
|----------|--------|
| Import via merge of `master` / `365daa6f3` | **REJECT** |
| Organizational intent (reduce root clutter) | **ACCEPT as problem statement** |
| Apply as dedicated hygiene on `main` | **DEFER** (separate PR; inspect path-by-path) |

## Why reject as merge

- Ancestry is 4048 commits behind canonical `main`.
- Commit is a mass path move over an obsolete tree, not a delta against current paths.
- Replaying it would collide with today's layout and violate "branches are candidate deltas, never alternate trees."

## Why the intent still matters on `main`

Measured on tip `43661f090`:

- Top-level tracked entries via `git ls-tree --name-only HEAD`: **~4647**
- That far exceeds GitHub's practical root listing limits.
- Root includes large doc/script noise (2000+ `.md`/`.txt` at top level alone in this measurement set).

So `_overflow/` (or better: `docs/archive/`, `scripts/legacy/`, etc.) remains a **valid future hygiene proposal** for canonical `main`, but must be designed against *current* paths, not transplanted from stale `master`.

## Recommended future procedure (not executed here)

1. Inventory top-level entries on `main`; classify keep / archive / delete-candidate (delete only with explicit owner approval — default is archive).
2. Move **documentation and one-off scripts only** first; never move live `src/`, `include/`, `CMakeLists.txt`, or cert evidence without review.
3. One PR, build/test, freeze evidence.
4. Do not reuse commit `365daa6f3`.

## Residual value of stale commit

Provenance only: documents that GitHub truncation was previously observed. No unique functional dependency content beyond that (deps already transplanted separately).
