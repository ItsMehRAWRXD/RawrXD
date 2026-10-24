# RAWRXD Batch 011 — 15 + 15 + 15 IDE completion audit

Status vocabulary: **committed** means source change, **configured** means workflow step, **pending** means no passing runtime receipt. This is not 45 completed features.

## Batch A: Native IDE and GitHub Actions (15)
01 inspect native IDE CMake target [prior]; 02 inspect CLI CMake target [prior]; 03 inspect Qt optionality [prior]; 04 fix MSVC toolchain path to vswhere [committed]; 05 Linux standalone smoke [configured]; 06 MSVC standalone smoke [configured]; 07 Win32 IDE build [configured]; 08 headless build [configured]; 09 machine-readable source audit [configured]; 10 no-deps audit [configured]; 11 run logs [pending]; 12 native executable artifact [pending]; 13 launch smoke [pending]; 14 IDE gateway handshake [pending]; 15 Qt-free linked binary dependency proof [pending].

## Batch B: ROM / REAP / dual AMD (15)
16 inspect projection residency accounting [done]; 17 add backend release callback [committed]; 18 gate release on verified GPU idle [committed]; 19 release all three projections after idle [committed]; 20 test release count and byte accounting [committed]; 21 test insufficient aggregate budget [prior]; 22 preflight three projections [prior]; 23 reject unsafe eviction [prior]; 24 R9700 admission [configured]; 25 RX7800XT admission [configured]; 26 actual Vulkan fence integration [pending]; 27 partial upload failure cleanup [pending]; 28 actual native 1.5-bit codec [pending]; 29 multi-token MoE numerical parity [pending]; 30 dual-GPU TPS receipt [pending].

## Batch C: End-to-end feature completeness (15)
31 native editor source [present]; 32 GhostText source [present]; 33 PowerShell panel source [present]; 34 LSP framing source [present]; 35 snapshot engine source [present]; 36 LSP process and JSON-RPC lifecycle [pending]; 37 GhostText physical accept/dismiss [pending]; 38 terminal output and cancellation [pending]; 39 browser renderer [pending]; 40 debugger expressions [pending]; 41 autonomous multi-file edit [pending]; 42 build/test/rollback certification [pending]; 43 extension compatibility [pending]; 44 evidence-based top-25 AI IDE parity [pending]; 45 100% release completeness certification [pending].

## Critical limitations and next implementation work
- ProjectionBridge release callback only safely runs when the caller-provided idle check succeeds. It is not a Vulkan fence implementation. A callback that returns false after allocating must manage its own resource cleanup; the bridge has no ownership transfer contract for failed uploads.
- Packed-byte preflight is conservative but cannot predict backend allocation overhead. If a later upload reports excess residency, previously admitted bindings remain until a verified idle/release.
- GitHub-hosted Windows runners do not provide R9700 + RX7800XT; the manually dispatched self-hosted workflow requires a registered labeled Windows runner and workflow availability on default branch.
- GitHub Actions run status has not been obtained via the connected tools; no green builds claimed.
- Root CMake CLI links nlohmann_json; native Win32 feature parity and strict no-deps runtime remain unproven.
- The 25-product comparison matrix is not a product certification.
