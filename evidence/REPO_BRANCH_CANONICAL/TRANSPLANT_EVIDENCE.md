# Dependency transplant evidence — 2026-08-29

**Canonical base:** `02eca52cd` (consolidation rule)  
**Did not import:** `365daa6f3` (`_overflow/` mass-move)

## Transplants (in order)

| # | Source | Result on main | Validation |
|---|--------|----------------|------------|
| 1 | `5d9869644` Maven | `cd5633f273` | pom versions 3.10.0 / 2.18.6 / 1.4.12 |
| 2 | `5347a1565` npm (4 updates) | `b99237a9c4` | package.json parse OK |
| 3 | `f933dc5ef` npm (5 updates) | `296ae1b53c` | conflicts → picked versions; JSON OK |
| 4 | `776e0ba11` Keras | `60c06e476b` | remapped `_overflow/requirements.txt` → live `3rdparty/ggml/requirements.txt` (+ Full Source mirror) |

## Invariant held

Branches are sources of **candidate deltas**, never alternate project trees. No wholesale merge.

## Deferred

- Independent evaluation of `_overflow/` organizational proposal
- GitHub default branch `master` → `main`
- AGENT-E2E-002

## Tip

`60c06e476b` (and successors)
