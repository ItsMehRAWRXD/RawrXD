# RELEASE_BLOCKERS — RAWRXD_FULL_IDE_AUDIT_003

```
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
SOURCE_MUTATION=0
PRODUCTION_BINARY_MUTATION=0
AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
```

Law: `SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`. `NOT_RUN != PASS`.

## Top 15 RELEASE_BLOCKERS

1. **P0 — Dirty SOURCE_MATERIAL vs authority tip** — Working tree modifies GhostText + Deep2 GDN/Vulkan/MoE vs `a5ae60ef`. Release must build clean tip only (`GITHUB_LOCAL_DIFF.csv`).

2. **P0 — No product-certified IDE binary seal** — Gate6 PASS is candidate-scoped (`F_GATE6_COMBINED_AB_RUNTIME_PROOF_002`); `PROMOTE=0` / `CERTIFIED=0` explicit. `rawr_production_cert` lists tools, not `RawrXD-Win32IDE-Native.exe`.

3. **P0 — Debugger is STUB** — `Win32IDE_Debugger.cpp` attach/step/watch simulate UI state; no Win32 debug loop. Commercial/correctness blocker for Debugger feature.

4. **P0 — Product E2E 64-token NOT_VERIFIED** — No sealed 64-token product E2E evidence found this audit.

5. **P0 — ChatWindow runtime NOT_VERIFIED** — Chat source wired; sealed ChatWindow product runtime missing.

6. **P1 — Host stability NOT_VERIFIED** — Prior GhostText runs HELD on focus failure / stale dual windows; no sealed HOST_STABILITY=PASS for authority product binary.

7. **P1 — Installer E2E NOT_VERIFIED** — `compilers/installer/build_installer.bat` exists; sealed Dist.Installer runtime absent.

8. **P1 — Qwen full-model parity OPEN** — `DEEP2_QWEN36_GDN_PRODUCTION_001`: `GDN_PRODUCTION_REACHED=PASS_SCOPE` but `FULL_MODEL_PARITY=OPEN` / cert blocked without independent reference.

9. **P1 — K2 / REAP product certify incomplete** — Logs show MoE/REAP tokenizer paths; no promote-ready IDE-integrated K2/REAP seal.

10. **P1 — Dual-GPU not IDE product E2E** — `DUAL_GPU_FORWARD_20261028` tool-level forward evidence only.

11. **P1 — Agentic.Swarm / PathB NOT_PRESENT** — Zero win32app symbols; swarm agentic commercial parity gap.

12. **P1 — Agentic rollback NOT_PRESENT** — No dedicated rollback path found in win32app audit.

13. **P1 — Qt Win32IDE path unusable by default** — `RAWRXD_BUILD_WIN32IDE_QT=OFF`; Copilot sources ABSENT; native target is the real product path — packaging must not ship wrong target.

14. **P1 — GhostText cancel / remaining acceptance gates open** — Gate6 NEXT_GATE requires remaining GhostText acceptance items before certify.

15. **P2 — Compare-tree divergence** — `G:\~dev\rawrxd` at `f88360e8…` branch `feature/ide-agentic-product-path-20261026` ≠ authority; mixing trees risks false release claims.

## Explicit non-blockers (inventory only)

- `src/ide/win32_ide.h` / `Win32IDE_SovereignCLI.h` absent at authority: `ABSENT_AT_AUTHORITY_COMMIT` / `DEFAULT_BRANCH_ONLY` — **not defects**.
