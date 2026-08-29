# Repository branch canonical note — 2026-08-29

## Verified tips (closure-origin)

| Ref | SHA | Tip subject |
|-----|-----|-------------|
| `main` | `d7651c5f0ca72c0a21724167d25b7529861c0267` | valuation snapshot (~$105M) |
| `main` parent line | `03c0e3651e2696edcb6d1a49bc6fc47d1982578a` | AGENT-E2E-001 candidate-pass |
| `master` | `365daa6f393d8449769e52398e2c2347b1ed543a` | overflow-dir truncation fix |

## Divergence

`git rev-list --left-right --count origin/master...origin/main` → **`1 4048`**

- `master` is the GitHub **default branch**
- Engineering progression lives on **`main`**
- Default-branch browsers/clones do **not** currently land on AGENT-E2E-001 / valuation evidence

## Canonical progression

```
03c0e3651 → d7651c5f0 → next gate = AGENT-E2E-002
```

## Recommendation

Set GitHub default branch to `main` (or FF/replace `master` only with an explicit migration plan). Do not treat `master` tip as current product state.
