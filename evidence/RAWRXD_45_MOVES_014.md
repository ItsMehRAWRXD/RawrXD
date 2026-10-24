# RAWRXD Batch 014 — 45 end-to-end acceptance checks

**This batch fixes a previously confirmed partial-execution defect.** Source commit is not proof of a successful GitHub Actions build or GPU runtime certification.

## 15 native IDE / CI checks
01 Native Win32 IDE target [configured]; 02 Native CLI target [source]; 03 Native headless agent target [configured]; 04 Snapshot CLI target [configured]; 05 MSVC compiler discovery [configured]; 06 Linux C++20 smoke [configured]; 07 Windows C++20 smoke [configured]; 08 No-deps static inventory [configured]; 09 LSP framing smoke [configured]; 10 GhostText UI acceptance [pending]; 11 PowerShell cancellation [pending]; 12 Browser/debugger interactions [pending]; 13 Native IDE launch [pending]; 14 Remove external JSON/Qt dependencies [pending]; 15 Capture successful hosted build artifact [pending].

## 15 Deep2 / dual AMD checks
16 Gate slice admission [source]; 17 Up slice admission [source]; 18 Down slice admission [source]; 19 Aggregate residency preflight [source]; 20 Upload-failure cleanup callback [source]; 21 GPU-idle-gated release [source]; 22 Defer Gate execution until all projections uploaded [fixed]; 23 Defer Up execution until all projections uploaded [fixed]; 24 Late Down upload failure executes zero projections [test committed]; 25 Successful expert still executes Gate/Up/Down [existing test]; 26 Actual Vulkan allocator integration [pending]; 27 Actual Vulkan fence integration [pending]; 28 R9700 execution [pending]; 29 RX 7800 XT execution [pending]; 30 Dual-GPU numerical and TPS certification [pending].

## 15 autonomous IDE / product parity checks
31 Editor buffer lifecycle [pending]; 32 LSP initialize [pending]; 33 LSP completion [pending]; 34 LSP diagnostics [pending]; 35 GhostText accept/dismiss [pending]; 36 PowerShell process output [pending]; 37 Terminal cancellation [pending]; 38 Browser rendering [pending]; 39 Debugger breakpoints [pending]; 40 Extension activation [pending]; 41 Agent multi-file edit [pending]; 42 Agent build/test/verify [pending]; 43 Snapshot rollback after failure [pending]; 44 Feature-by-feature top-25 parity evidence [pending]; 45 Complete daily-driver release certification [pending].

## Technical limitations
- Two-phase load-before-execute prevents an earlier projection from executing when a later upload fails. It does not make three execution callbacks atomic; an execution failure can still follow a successful earlier execution.
- A failed upload after allocating resources needs a correctly wired backend release callback and proven GPU-idle condition. Unowned allocations are not automatically reclaimed.
- No full Deep2 Vulkan forward, no real dual AMD dispatch, and no 150 TPS receipt are demonstrated by this bridge-level fix.
- Hosted Actions build and run statuses have not been obtained in this session. Physical GPU tests require the labeled self-hosted runner.
- Qt-free end-to-end IDE and top-25 parity are unverified; existing source or static matrices alone do not establish completeness.
