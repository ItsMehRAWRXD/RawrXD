# RAWRXD 45-MOVE BATCH 005 — GitHub Actions build/test and no-deps audit

## Actual repository changes this batch
- Fixed pre-top-k REAP masking to validate the entire mask before mutating logits.
- Extended route-mask smoke test to assert atomicity on validation failure.
- Added Windows native x64 CMake configure/build job for `rawr-agent-headless` and `rawr-snapshot`.
- Explicitly disabled Qt requirement and optional ZLIB download in that job.
- Enabled manual `workflow_dispatch` in addition to push/PR triggers.
- Inspected root CMake: `RAWRXD_REQUIRE_QT` is optional (default OFF), but Qt6 references remain. No repository-wide Qt removal has occurred.
- Attempted to create a draft PR to obtain PR-based run visibility; GitHub connector blocked the PR operation. No PR was created.
- CI run results are not yet available through the connected workflow-run query. No successful GitHub build is claimed.

## Batch A — 15 tasks: Native build evidence
01 Inspect root CMake [done]
02 Identify Qt requirement switch [done]
03 Identify optional ZLIB fetch [done]
04 Add native Windows configure job [done]
05 Force x64 VS2022 generator [done]
06 Build headless agent [configured, not run-confirmed]
07 Build snapshot CLI [configured, not run-confirmed]
08 Compile portable bridge smoke [configured, not run-confirmed]
09 Compile projection bridge smoke [configured, not run-confirmed]
10 Compile route mask smoke [configured, not run-confirmed]
11 Compile ternary reference smoke [configured, not run-confirmed]
12 Compile top25 matrix smoke [configured, not run-confirmed]
13 Collect CI logs [pending]
14 Repair actual CI failures [pending]
15 Mark native build PASS only on green receipts [pending]

## Batch B — 15 tasks: ROM/MoE correctness
16 Check route mask pre-top-k contract [done]
17 Validate logits before mutation [done]
18 Fail closed for insufficient retained experts [done]
19 Add atomicity test [done]
20 Validate invalid expert rejection [source present]
21 Preserve projection-aware bindings [source present]
22 Validate shard offset semantics [source present]
23 Add packed weight format identity [pending]
24 Integrate historical native 1.5-bit codec [pending]
25 Verify GGUF quant compatibility [pending]
26 Wire router mask into real forward pass [pending]
27 Wire projection bridge into real forward pass [pending]
28 Add GPU fence ownership [pending]
29 Run multi-token DeepSeek inference [pending]
30 Certify numerical output parity [pending]

## Batch C — 15 tasks: IDE parity/completeness
31 Inventory native Win32 IDE [pending]
32 Inventory Qt-only targets [pending]
33 Identify feature parity benchmark protocol [matrix scaffold present]
34 Verify terminal [pending]
35 Verify debugger [pending]
36 Verify LSP [pending]
37 Verify extensions [pending]
38 Verify GhostText [pending]
39 Verify browser surface [pending]
40 Verify multi-file agent edit [pending]
41 Verify build/test/rollback [pending]
42 Verify snapshot restore [pending]
43 Verify all 25 competitor capabilities with reproducible evidence [pending]
44 Measure completeness from required acceptance gates [pending]
45 Claim 100% only when all required gates pass [pending]

## Execution constraints
GitHub-hosted Windows runners can compile MSVC and execute CPU tests. They do not provide the user's dual AMD GPUs or local GGUF shards. A self-hosted runner on that machine is needed for hardware-specific parity and throughput. A source file, task ledger, or unobserved workflow trigger is not a test receipt.

## Links
Workflow: `.github/workflows/reap-rom-parity-ci.yml`.
Branch: `feature/reap-deepseek-671b-150tps`.
