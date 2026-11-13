# REAP physical bank — calibrated per-layer allowlist wire

**PROMOTE=0** · **CERTIFIED=0** · witness / wire note only (not a PASS).

## API (`src/deep2/ReapPhysicalBank.hpp`)

| Symbol | Role |
|--------|------|
| `ReapPhysicalBankInstall` | Prefix bank: active ⇒ `expertId < retainedPerLayer` |
| `ReapPhysicalBankInstallAllowlist(packedBits, layerCount, expertCap)` | Fixed bitmasks: max 128 layers × 512 experts (`uint64_t` words) |
| `ReapPhysicalSetRouteLayer(layer)` | TLS current layer for route/mask sites |
| `ReapPhysicalExpertAllowed(expertId)` | Uses route layer; allowlist bit **or** prefix |
| `ReapPhysicalExpertAllowedAtLayer(layer, expertId)` | Explicit layer (acquire / place) |
| `ReapPhysicalAllowlistActive()` | True when calibrated bits installed |
| Snapshot `.allowlistStatus` | `INACTIVE` or `CALIBRATED_ALLOWLIST_ACTIVE` |

When allowlist is **inactive**, behavior is unchanged: prefix `[0, retained)`.

## Env

| Env | Authority |
|-----|-----------|
| `RAWR_REAP_SELECTION_MANIFEST` | Path to `RAWRXD_REAP_EXPERT_SELECTION_001` JSON (`layers[].selected[].expert`) |
| `RAWR_REAP_CALIBRATION` | Rank file still **BANK_REMAP_PENDING** — does **not** remap the bank |

Install path: `ApplyPhysicalReducePlan` → bank install → `TryInstallSelectionAllowlist` (`src/reap/ReapPhysicalAllowlistInstall.cpp`).

## Mask sites

- `MoERouter.cpp` — logits + choiceScores via `ExpertAllowed`
- `K2MoEWeights.cpp` — choice mask + route checks
- `MoEWeightProxy.cpp` / `K2NativeMoEFfn_Place.cpp` — acquire allow
- Route layer set at Deep2 B03 + K2 `LoadAndRoute`

## Parity how-to (not executed here)

**FULL + `--reap` + allowlist (same IDs as calib export):**

```text
set RAWR_REAP_SELECTION_MANIFEST=<path\to\RAWRXD_REAP_EXPERT_SELECTION_001.json>
rawr.exe run FULL --reap <A/B...>
```

Expect stderr: `CALIBRATED_ALLOWLIST_ACTIVE` · receipt `allowlist_status` · **PROMOTE=0**.

**PHYS CALIB export:** build/run physical sidecar with the **same** selection JSON (export path already reads `RAWR_REAP_SELECTION_MANIFEST`). Full-model runtime with allowlist should route/acquire only those expert IDs — not remapped prefix `[0,R)`.

Without the env var, bank stays prefix-only (legacy).
