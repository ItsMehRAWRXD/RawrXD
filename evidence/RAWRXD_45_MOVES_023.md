# RawrXD Batch 023 — 45 release acceptance checks

Status semantics: FIXED = committed change; CONFIGURED = automated job defined; REPORTED = user-provided local result; PENDING = no successful end-to-end receipt. This is not a claim of 45 completed fixes.

## A — 15 LSP and build checks
01 FIXED zero-length LSP rejection; 02 FIXED zero-length regression framing; 03 SOURCE signed-length validation; 04 SOURCE duplicate header detection; 05 SOURCE frame-size bound; 06 SOURCE partial-frame buffering; 07 SOURCE multi-frame buffering; 08 CONFIGURED GCC smoke; 09 CONFIGURED MSVC smoke; 10 CONFIGURED Win32 IDE build; 11 CONFIGURED headless agent build; 12 CONFIGURED snapshot build; 13 CONFIGURED per-file inventory; 14 PENDING CI compiler/test logs; 15 PENDING native LSP process handshake.

## B — 15 IDE and no-deps checks
16 REPORTED local parent IDE build; 17 REPORTED local parent IDE launch; 18 PENDING canonical IDE build artifact; 19 PENDING file edit/save/reopen; 20 PENDING completion acceptance; 21 PENDING diagnostics and navigation; 22 PENDING GhostText UI; 23 PENDING terminal lifecycle; 24 PENDING browser/debugger; 25 PENDING agent edit/build/test; 26 PENDING snapshot rollback; 27 PENDING Qt-free linked imports; 28 PENDING external JSON removal; 29 PENDING extension lifecycle; 30 PENDING enterprise packaging.

## C — 15 GPU and enterprise checks
31 REPORTED R9700 hardware enumeration; 32 REPORTED RX7800XT hardware enumeration; 33 REPORTED Vulkan compiler smoke; 34 CONFIGURED self-hosted GPU admission; 35 PENDING registered runner; 36 PENDING R9700 inference; 37 PENDING RX7800XT inference; 38 PENDING dual-GPU dispatch; 39 PENDING FFN/GEMV multi-token correctness; 40 PENDING CPU/GPU parity; 41 PENDING GGUF family sweep; 42 PENDING TPS target; 43 PENDING release security/reliability; 44 PENDING top-25 AI IDE feature parity; 45 PENDING 100% enterprise release certification.

PR #53 remains draft; neither configured CI nor user-reported toolchain readiness is equivalent to release certification.
