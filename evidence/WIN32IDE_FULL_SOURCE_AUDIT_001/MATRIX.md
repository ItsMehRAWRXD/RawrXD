# MATRIX — WIN32IDE_FULL_SOURCE_AUDIT_001

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 PERFECT=0
EXE_SHA=866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F
ASOF_UTC=2026-10-28T09:20:00Z
POST_GATE=COMMAND_HANDLERS_FICTION_GATE_001
```

Statuses: CLEARED | GATED | BLOCKED | OPEN | NOT_RUN | HISTORICAL_SHA_ONLY

| ID | Surface | Linked? | Bucket | Note / cite |
|----|---------|---------|--------|-------------|
| A01 | EXE SHA bind | — | CLEARED | on-disk matches `866E9D1B…` |
| A02 | Camellia HMAC absorb | ASM+C | CLEARED | `CAMELLIA_HMAC_PRODUCT_ABSORB_001` |
| A03 | Live tetrad post-HMAC | YES | CLEARED | `LIVE_TETRAD_POST_HMAC_ABSORB_001` |
| A04 | TOKEN64 / TPS seal | YES | CLEARED | `TOKEN64_PRODUCT_RUN_003` on CURRENT |
| A05 | MULTI_FAMILY gemma3 | YES | CLEARED | `MULTI_FAMILY_PRODUCT_002` |
| A06 | Mode* GateMode | YES `subsystem_api` | GATED | fail-closed; no fake PASS |
| A07 | SO_*/AD_* -1/nullptr | YES same | GATED | B03 |
| A08 | batch_010/011 Mode/SO/AD | NO | GATED | CMake omit |
| A09 | batch_005 XOR auth file | YES but `#if !RAWR_HAS_MASM` | GATED | lines 181–188; MASM=1 → ASM Auth owns |
| A10 | crypto_stubs.cpp | NO | GATED | CMake `# REMOVED` |
| A11 | Watchdog MagBuf CRC init | YES | CLEARED | `win32ide_watchdog_init.cpp:40` real CRC publish |
| A12 | Watchdog/HMAC ASM body | .obj | CLEARED | absorb seal; self_test independent |
| A13 | Camellia self_test=-8 | ASM | BLOCKED | `CAMELLIA_SELFTEST_RFC_001` BLOCKED_DOCUMENTED |
| A14 | FEATURE_FICTION handlers | YES | GATED | `COMMAND_HANDLERS_FICTION_GATE_001` GateFiction×276; LAW `GATED_FICTION_EXPLICIT` |
| A15 | AgenticBridge product path | YES | CLEARED/GATED | failclose wired; no empty fake ProductRun found this audit |
| A16 | AgenticFeatures / LoRA / WAL | NO | GATED | `LORA_KERNEL_STUB_GATE_001` |
| A17 | LogpointBridge / SidebarBridge | NO | GATED | `WIN32IDE_BRIDGE_SWEEP_002` |
| A18 | ShellLayout | YES | CLEARED | `return true` = real HWND allow-list logic |
| A19 | Headless ToolRoutes | YES | CLEARED/HISTORICAL | routes linked; prior seal `HEADLESS_TOOL_ROUTES_001` on `89BFD614…` |
| A20 | Inference SPLIT | — | GATED | HOLD (`PROMOTE_READY_CONJUNCTION` C12) |
| A21 | PromoteReady rows C01–C08 | — | CLEARED inputs | MET on CURRENT; ≠ PROMOTE_READY=1 |
| A22 | PromoteReady emit C13 | — | OPEN | `PROMOTE_READY=0` |
| A23 | R28 APPLY | — | GATED | HELD |
| A24 | TIP_CLIMB | — | GATED | HOLD |
| A25 | PROMOTE flip | — | GATED | always 0 |
| A26 | K2 full product gen | — | BLOCKED_OOM | `K2_FULL_PRODUCT_GEN_002` on CURRENT `866E9D1B…` GENERATED_TOKENS=0 AUTO_BACKEND OOM (weights 44152MB > host 37099MB); prior `K2_FULL_PRODUCT_GEN_001` HISTORICAL `89BFD614…` also BLOCKED_OOM; no smaller on-disk quant |
| A27 | TOKEN64_001 clamp | — | BLOCKED + HISTORICAL | BLOCKED_CLAMP on `89BFD614…` |
| A28 | TOKEN64_002 | — | HISTORICAL_SHA_ONLY | `D121659F…` only |
| A29 | Live tetrad post-Camellia | — | HISTORICAL_SHA_ONLY | `89BFD614…` |
| A30 | Live tetrad post-relink | — | HISTORICAL_SHA_ONLY | `D121659F…` |
| A31 | Bridge/stub sweeps 001/002 | — | HISTORICAL_SHA_ONLY | EXE_SHA_HOLD `89BFD614…` (source dispositions remain) |
| A32 | win32app orphans (332) | NO | GATED/OPEN | many intentional omit; product-intent orphans remain OPEN until dispositioned |
| A33 | IDE perfect coverage | — | OPEN | OPEN list non-empty; seals not uniformly CURRENT |

## Linked stub scan (return-true empty / XOR / FEATURE_FICTION / stub)

| Pattern | Result |
|---------|--------|
| return-true empty fake-success (Mode/SO/AD/Camellia/HMAC) | **none found** (prior sweeps hold) |
| XOR auth in linked TU | `batch_005.cpp:182,186` under `!RAWR_HAS_MASM` only → **GATED** |
| FEATURE_FICTION | **0 OPEN** — **276 GATED** via `COMMAND_HANDLERS_FICTION_GATE_001` |
| GateStub in linked net | **0 hits** |
| crypto_stubs linked | **0** (omitted) |

### FEATURE_FICTION holes (LINKED) — GATED

`src/core/command_handlers_comprehensive.cpp` — `GateFiction`×276

Pattern: `return GateFiction("NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 <Name>");`

LAW `GATED_FICTION_EXPLICIT`: fail-closed linked theater = **GATED** (not OPEN; ≠ PASS).
Cite: `evidence/COMMAND_HANDLERS_FICTION_GATE_001/`. RELINK=NO tip `866E9D1B…`.

### Prioritized OPEN backlog

1. **P0** — `INIT_SELF_TEST_BLOCK=-8` / RFC Camellia schedule (`CAMELLIA_SELFTEST_RFC_001`) [A13 BLOCKED]
2. **P1** — `PROMOTE_READY=0` emit + R28 APPLY HELD + TIP_CLIMB HOLD + Inference SPLIT HOLD [A22 OPEN]
3. **P1** — Re-seal / re-run remaining HISTORICAL_SHA_ONLY product proofs (Headless tool E2E / bridge RUNTIME if claimed); K2 sealed CURRENT as `K2_FULL_PRODUCT_GEN_002` BLOCKED_OOM
4. **P2** — Disposition remaining win32app orphans with product intent (vs keep GATED_OMIT) [A32]
5. **P2** — IDE perfect coverage [A33 OPEN] — CERTIFIED/PERFECT remain 0 until OPEN empty **and** seal SHAs match CURRENT

### OPEN row tally (post A14 gate)

| Bucket row | Status |
|------------|--------|
| A14 FEATURE_FICTION | **GATED** (cleared from OPEN) |
| A22 PromoteReady emit | OPEN |
| A32 win32app orphans | GATED/OPEN (partial) |
| A33 IDE perfect coverage | OPEN |
| **OPEN count (strict rows)** | **2** (A22, A33) + A32 partial |
