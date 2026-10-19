# Deep2 Streamer Env Catalog (`deep2_streamer_parity.exe`)

Authority: [Catalog getenv DEEP2/RAWRXD](99d8734e-28e1-4f6b-bff7-84721560e004)  
Scope: `src/deep2/**` via `getenv` / `GetEnvironmentVariable` / harness `SetEnv*`.

## Hardcoded `SetEnv` (`StreamerArmSpeedEnv`)

| Name | Forced |
|------|--------|
| TOKEN_PACING | OFF |
| DECODE_SLEEP | 0 |
| DEEP2_CERT_STEP_LOG | 0 |
| QKV_OWNER_RESI_LOG | 0 (write-only) |
| TOK_RESIDUAL_SPAM | 0 (write-only) |
| RAWRXD_FFN_TRACE | 0 |
| DUST2_FTL | 0 |
| DEEP2_LIVE_POLICY | TRAMPOLINE |
| DEEP2_LIVE_MECH | trampoline |
| DEEP2_GEN_ALG | lukewarm |

### `SetEnvIfUnset`

| Name | Default |
|------|---------|
| RAWRXD_HOST_DECODE | 0 |
| DEEP2_GPU_POLICY | MULTI |
| DEEP2_GPU_DEVICE_CLASS | DISCRETE |
| RAWRXD_DEEP2_ALLOW_ELASTIC | 1 |
| DEEP2_MARS | 1 |
| DEEP2_WEIGHT_BUDGET_MIB | E8B0M |
| FREETOKEN_MICROZONE | 1 |
| DEEP2_NO_TRUNCATE_NEEDLE | 1 (write-only) |

### Re-force in `Deep2GenerateStream`

TOKEN_PACING=OFF, DECODE_SLEEP=0, DUST2_FTL=0 (`Deep2StreamApi.cpp`).

### DualStick arm (`ArmDualStickNoTruncate`)

Forces DISCRETE + MULTI; clears DEEP2/RAWRXD GPU_SELECT and RAWRXD_GPU_NAME; sets DEEP2_STICK0/1_BUDGET_MIB.

## Phase catalogs (summary)

### 1 PRE_HARNESS

Speed/mute/live/gen-alg forces above; budget parse; `DEEP2_DUALSTICK_ARM` (`0` skips arm); model roots (`RAWRXD_MODEL_ROOT`, `RAWRXD_MANIFEST_CACHE`, `RAWRXD_PRODUCT_MODEL`); token law (`RAWR_MAX_TOKENS` / `DEEP2_MAX_TOKENS` / `DEEP2_UNLIMITED_TOKENS`).

### 2 DEVICE_SELECT / VULKAN_OPEN

`DEEP2_GPU_POLICY` / `RAWRXD_GPU_POLICY`, `*_GPU_DEVICES`, `*_GPU_SELECT`, `RAWRXD_GPU_NAME`, `*_GPU_DEVICE_CLASS`, hybrid/split (`DEEP2_HYBRID`, `DEEP2_FORCE_SPLIT`, `DEEP2_HYBRID_CPU_LAYERS`, `DEEP2_GPU_SOLO_STRICT`), `RAWRXD_GPU_FWD`, `VK_ICD_FILENAMES`, GPU-forward isolation ladder vars.

### 3 WEIGHT / BUDGET / MARS / ELASTIC / ENHANCE

`DEEP2_WEIGHT_BUDGET_MIB`, stick budgets, `DEEP2_WEIGHT_MODE` / `SLOTS` / `PREFETCH` / `OVERLAP`, `DEEP2_MARS` / `DEEP2_MARS_FORCE`, `RAWRXD_ENHANCE_SKIP`, `DEEP2_MINIMAL_ENHANCE`, elastic/lookahead/hot MiB caps, `FREETOKEN_MICROZONE`. Shard/real-K2 envs disqualify MARS.

### 4 DUALSTICK

`DEEP2_DUALSTICK_ARM`, stick budgets, policy/class re-force, select-needle clear.

### 5 DECODE / HOST / GENERATE

`RAWRXD_HOST_DECODE`, `RAWRXD_GREEDY`, `DEEP2_GEN_ALG`, live-path family (`DEEP2_LIVE_*`), MLA/logits/K2 stream switches, tokenizer allow flags.

### 6 DIAGNOSTIC_ONLY

`RAWRXD_DEEP2_LAYER_PROBE`, embed/LinearW/kernel/stage/B3/greedy/top-logits traces, `DEEP2_CERT_STEP_LOG`, evidence512, decode feedback / blocker attribution.

## Pre-runtime order

1. argv (`--model` required)  
2. Forbidden arg/exe scan  
3. ImportSpace68 cert (fail → exit 5)  
4. `StreamerArmSpeedEnv` (fail → exit 4)  
5. DXGI enum + `Deep2Device_ApplyPolicy`  
6. DualStick plan/arm unless `DEEP2_DUALSTICK_ARM=0`  
7. FreeToken + FutureConsumer init + law emit  
8. `Deep2GenerateStream` → first token callback  

## Notes

- `DEEP2_NO_TRUNCATE_NEEDLE`, `QKV_OWNER_RESI_LOG`, `TOK_RESIDUAL_SPAM`: harness/arm writes only (no getenv consumer under `src/deep2`).
- G3 min-stack evidence overrides harness defaults (`DEEP2_MARS=0`, enhance skip, elastic deny, optional SOLO + R9700 needle).
- Does **not** claim DualStick live; GPU1 create remains `DRIVER_OR_DEVICE_STATE` per `G3_GPU1_CREATEDEVICE_DIAG_001`.
