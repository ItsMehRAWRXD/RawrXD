# Batch 016 — Enterprise release gate register (15 + 15 + 15)

Statuses: **committed** means a change is present on the feature branch; **configured** means CI is defined; **pending** means there is no verified end-to-end receipt. This register is not 45 completed fixes.

## A. Per-file audit and no-deps closure (15)
1 [committed] Git-tracked path enumeration; 2 [committed] Source-extension classification; 3 [committed] SHA-256 per source file; 4 [committed] Per-source byte and line counts; 5 [committed] Skip reading non-source artifact contents; 6 [committed] Qt header detection; 7 [committed] Qt CMake detection correction; 8 [committed] nlohmann indicators; 9 [committed] curl/boost include indicators; 10 [configured] JSON artifact upload; 11 [pending] Actual repository-wide report from CI; 12 [pending] Remove Qt from native linked executable; 13 [pending] Remove external JSON from CLI; 14 [pending] Dependency closure of every target; 15 [pending] File-by-file semantic code review.

## B. Native IDE and Actions (15)
16 [configured] Linux C++20 smoke; 17 [configured] Windows MSVC smoke; 18 [configured] Native Win32 IDE CMake configure; 19 [configured] Native Win32 IDE build; 20 [configured] Headless agent build; 21 [configured] Snapshot target build; 22 [configured] Source inventory job; 23 [confirmed] Draft PR #53 exists; 24 [pending] PR workflow PASS; 25 [pending] Native IDE executable artifact; 26 [pending] Windows launch receipt; 27 [pending] Editor/terminal/browser runtime; 28 [pending] LSP process and completion; 29 [pending] GhostText physical acceptance; 30 [pending] Agent edit/build/test/rollback.

## C. GPU and enterprise release (15)
31 [source] REAP projection residency bridge; 32 [source] Three-projection staging; 33 [source] Upload-failure regression; 34 [configured] Dual AMD admission workflow; 35 [pending] Self-hosted GPU runner connected; 36 [pending] Vulkan allocator ownership; 37 [pending] Fence synchronization; 38 [pending] R9700 multi-token decode; 39 [pending] RX7800XT multi-token decode; 40 [pending] Dual-GPU parity; 41 [pending] Model-family correctness sweep; 42 [pending] Sustained performance target; 43 [pending] Release threat model and security tests; 44 [pending] Feature-by-feature top-25 AI IDE parity evidence; 45 [pending] Enterprise production release certification.

## Critical evidence rule
Source presence, a configured GitHub Actions job, or an empty GitHub commit status response cannot be called PASS. No full-repository semantic audit, hardware GPU run, or top-25 parity certification has been established. Draft PR #53 must remain unmerged until verification.
