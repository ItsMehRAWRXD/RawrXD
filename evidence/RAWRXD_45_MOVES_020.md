# Batch 020 — 45 production acceptance gates

Statuses: FIXED = code committed; CONFIGURED = CI exists; REPORTED = user local receipt; PENDING = not certified. These are acceptance checks, not 45 completed changes.

## A. Build and CI (15)
01 FIXED MSVC discovery; 02 FIXED MSVC environment script verification; 03 FIXED fail-fast MSVC smoke execution; 04 CONFIGURED six Windows C++20 smoke tests; 05 CONFIGURED six portable C++20 smoke tests; 06 CONFIGURED native IDE build; 07 CONFIGURED headless agent build; 08 CONFIGURED snapshot build; 09 CONFIGURED per-file source inventory; 10 CONFIGURED Qt/dependency inventory; 11 CONFIGURED CMake missing-source inventory; 12 CONFIGURED artifact upload; 13 PENDING passing CI receipts; 14 PENDING full optional-target build; 15 PENDING reproducible release artifact.

## B. Native IDE end-to-end (15)
16 REPORTED parent IDE launch; 17 PENDING canonical native IDE launch; 18 PENDING file open/save/reopen; 19 PENDING syntax/diagnostics; 20 PENDING LSP initialization; 21 PENDING LSP completion; 22 PENDING GhostText acceptance; 23 PENDING PowerShell output; 24 PENDING process cancellation; 25 PENDING browser embedding; 26 PENDING debugger stepping; 27 PENDING extension lifecycle; 28 PENDING Qt-free binary imports; 29 PENDING agent edit/build/test/verify; 30 PENDING snapshot rollback and restore.

## C. GPU and enterprise parity (15)
31 REPORTED R9700 enumeration; 32 REPORTED RX7800XT enumeration; 33 REPORTED Vulkan compile/link/execute; 34 CONFIGURED self-hosted GPU admission; 35 PENDING runner registration; 36 PENDING R9700 forward execution; 37 PENDING RX7800XT forward execution; 38 PENDING dual-GPU synchronization; 39 PENDING multi-token FFN/GEMV; 40 PENDING CPU/GPU numerical parity; 41 PENDING model-family GGUF sweep; 42 PENDING throughput certification; 43 PENDING security and reliability soak; 44 PENDING top-25 feature parity test results; 45 PENDING enterprise release certification.

Do not merge draft PR #53 as a certified release without passing job logs, hardware receipts, recovery testing and feature-level parity evidence.
