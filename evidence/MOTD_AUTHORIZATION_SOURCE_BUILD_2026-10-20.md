# MOTD Authorization — Source and Build Verification

Captured 2026-10-20. Repository: `F:/rawrxd`, branch `local-30b-backend`, base HEAD `d053716b120b17c9a177549f87c14a3d2f070bf7`.

The workspace policy is `.cursor/rules/PassiveRoleNotRoleplay.md`, SHA-256 `3d08b40abb22482209e7585175e76fa8cffc4d999f9edfc252910a38e1ed98de`. The shared guard reads only the canonical policy path within the configured workspace, binds acknowledgment to a session and turn, re-hashes the file before each subsequent tool authorization, and revokes the acknowledgment when its turn guard leaves scope. A changed or missing policy blocks the next tool.

## Implemented paths

- `tools/deep2_agentic_loop.cpp` recognizes `TOOL read_motd`, returns the policy bytes and digest to the model, and denies other dispatched actions before acknowledgment.
- `src/agentic/ToolCallBridge.h` provides the reserved read tool, blocks execution before acknowledgment, rejects overlapping turns on one bridge, and supports RAII turn revocation. `src/agentic/SelfRepairLoop.cpp` opens and scopes a fresh authorization turn per task.
- `src/rawrxd_cli_v2.cpp` gates direct `rawr tools run` commands. Each `rawr run` prompt turn reads the policy and supplies the exact bytes to model context. Project Wizard callbacks pass through the same digest check before registry tools execute.
- `src/api_server.cpp` explicitly rejects `/api/tool`; `src/api_contract.json` now describes the route as disabled. The API translation unit has compile-only evidence; the configured build has no active API listener or executable dispatch path.
- `tests/motd_authorization_test.cpp` covers the known SHA-256 vector, pre-ACK denial, session/turn binding, policy replacement, missing policy, independent concurrent sessions, bridge overlap rejection, and RAII revocation.

## Verification receipts

| Check | Result |
| --- | --- |
| VS2022 CMake build of `deep2_agentic_loop` and `RawrXD-CLI-V2` | Exit 0; both linked |
| Standalone state-machine and ToolCallBridge test | Exit 0 — `MOTD_AUTHORIZATION_TEST PASS` |
| `deep2_agentic_loop.exe --motd-selftest --workdir F:\rawrxd` | Exit 0 — `MOTD_LOOP_SELFTEST PASS`; policy digest matched |
| `rawr.exe tools run read_motd` in `F:\rawrxd` | Exit 0 — returned `MOTD_ACK=1`, expected digest, and policy text |
| Same CLI command from a temporary workspace without the MOTD | Exit 3 — `DENIED: MOTD_NOT_FOUND` |
| Compile `src/api_server.cpp` as a translation unit | Exit 0; compile only, no link or API runtime test |
| `git diff --check` on scoped changes | Exit 0 |

Commands used are recorded in `MOTD_AUTHORIZATION_VERIFICATION_2026-10-20.json`. No model inference or GPU benchmark ran; the benchmark pause remains preserved.

## Coverage limits and certification

Gate 9 remains **PARTIAL**. `rawr run` still has no model-generated tool-dispatch loop, and the GUI-to-final-answer workflow has not been exercised end to end. The IDE-launched Deep2 loop independently reads the workspace file in its child process, but the parent does not pass a signed authorization identity.

Gate 18 remains **OPEN**. The `/api/tool` route is deliberately inert, but this checkout has no live listener to test it. HexMag and SubAgent dispatch paths are not all routed through the guard. SHA-256 is an integrity fingerprint, not a signed or externally anchored receipt, so this evidence does not establish non-repudiation. Tool-specific permission checks remain separate from MOTD acknowledgment.

S07 and S12 remain **OPEN**. No GPU or model performance acceptance was attempted.
