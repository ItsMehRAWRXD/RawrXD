# MASTER_REGISTER â€” deduped hidden-gap investigation register

ASOF_UTC=2026-11-09T12:45:00Z
MOTD_ACK=1
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
CONTROLLING_TIP=CC79
CONTROLLING_TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
A4F_SHA256=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
INTEG_004_SEALED_SHA=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
INTEG_004_LIVE_SHA=69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVESTIGATE_NE_CONFIRMED=1
NO_ARITHMETIC_SUM=1
78_REGISTER=ABSENT_LOCALLY

## Status legend

- CONFIRMED â€” reported failure evidence on a named SHA
- UNVERIFIED â€” required behavior not demonstrated on controlling tip
- INVESTIGATE â€” plausible mechanism; not assumed defect
- OVERLAP â€” covered by Finish-25 / Issue / PR ledger; do not double-count
- OUT_OF_SCOPE â€” beyond Windows daily-driver minimum unless 100% spec mandates

## Evidence SHA map (authorities)

| Label | SHA-256 |
|-------|---------|
| CC79 tip_final_005 / integ_002 | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` |
| INTEG_004 Problems seal | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` |
| INTEG_004 live on-disk image | `69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB` |
| A4F immutable slim | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` |

## Counts (non-summation)

```
H_ENTRIES=120
CONFIRMED_COUNT=see_table_footer
78_ABSENT + 120 + 45 + PR_OPEN != DEFECT_TOTAL
FINISH25_HISTORICAL=19/25
FINISH25_CURRENT=4/25
```

| ID | Hidden gap | Status | Evidence SHA / receipt | Overlap |
|----|------------|--------|------------------------|---------|
| H01 | Implemented source files excluded from the production CMake target | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H02 | Duplicate implementations with only the older version linked | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H03 | Stub functions silently replacing production functionality | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H04 | Feature flags disabling important components in release builds | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H05 | Missing source dependencies concealed by incremental builds | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H06 | Stale object files producing apparently successful builds | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H07 | Debug and Release configurations behaving differently | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H08 | Incorrect compiler definitions or inherited environment variables | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H09 | Unresolved symbols hidden behind optional build paths | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H10 | Different branches containing incompatible implementations | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H11 | Generated headers or resources missing from clean checkout | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H12 | Non-reproducible binaries despite identical source revisions | **INVESTIGATE** | Build integrity INVESTIGATE; clean-checkout gates OPEN on GitHub | #57A/build |
| H13 | Menu commands pointing to missing or incorrect handlers | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H14 | Toolbar buttons displaying but not executing | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H15 | Keyboard shortcuts bypassing the correct command path | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H16 | HWND references surviving after window destruction | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H17 | Worker threads modifying Win32 controls directly | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H18 | Posted messages arriving after session cancellation | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H19 | Reentrant window procedures corrupting application state | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H20 | Focus switching between panels breaking keyboard input | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H21 | Incorrect DPI scaling or panel geometry | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H22 | Resize operations destroying or obscuring controls | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H23 | Modal dialogs blocking active background operations | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H24 | UI thread deadlocks during compiler or model execution | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H25 | Unhandled exceptions inside message dispatch | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H26 | Window recreation losing application state | **INVESTIGATE** | Partial UI exercised on CC79; full menu matrix absent | GUI/HWND |
| H27 | Compiler subprocess inheriting incompatible environment variables | **CONFIRMED** | CC79 Problems FAIL; VS_UNICODE_OUTPUT class; seal fix on 47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F only (PROBLEMS_UI_CC79_RECEIPT / LINEAGE) | PR77/INTEG_004 |
| H28 | Stdout/stderr pipe backpressure causing deadlocks | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H29 | Compiler child processes surviving cancellation | **INVESTIGATE** | Cancel/descendant â€” Finish-25 T05 cancel history; NOT_RUN != PASS | F25-T05 |
| H30 | Timeout terminating the parent but not descendants | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H31 | Diagnostics parsed incorrectly when paths contain spaces | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H32 | Unicode diagnostic text corrupted | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H33 | Compiler warnings mistaken for errors | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H34 | Duplicate Problems entries from repeated builds | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H35 | Old diagnostics remaining after successful rebuild | **UNVERIFIED** | CC79 items=0 so stale-clear not demonstrated on controlling tip; INTEG_004 REBUILD_CLEARS=PASS on sealed SHA only | INTEG_004 |
| H36 | Problems click-to-line dispatching without actual navigation | **UNVERIFIED** | CC79 CLICK_TO_LINE=NOT_RUN; sealed integ_004 POSTED_NM_DBLCLK only | INTEG_004 |
| H37 | Incorrect line/column offsets | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H38 | Multiple projects mixing diagnostic ownership | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H39 | Linker errors missing from Problems | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H40 | Failed builds reporting success because artifacts already exist | **INVESTIGATE** | CC79 Problems FAIL items=0; see H027; other rows INVESTIGATE | Problems/compiler |
| H41 | Native PE/COFF linker accepting malformed relocations | **OVERLAP** | PR#75 native-linker unexecuted | PR75 |
| H42 | Compiler adapter passing while native compiler functionality remains incomplete | **OVERLAP** | PR#75 37 local PASS / 16 native-linker UNEXECUTED | PR75 |
| H43 | Extension discovery works but activation never executes | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; activation-never-executes not confirmed; reload matrix open | PR79/CC79 |
| H44 | Worker starts without completing IPC handshake | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H45 | IPC messages lack framing or size validation | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H46 | Extension commands execute on the wrong thread | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H47 | Host and worker disagree on protocol version | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H48 | Extension crashes terminate the entire IDE | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H49 | Unloading leaves callbacks registered | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H50 | Reloading creates duplicate commands or subscriptions | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H51 | Extension process survives IDE shutdown | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H52 | Crashed workers cannot restart cleanly | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H53 | Extension filesystem access bypasses permissions | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H54 | Extension event handlers block the UI | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H55 | Extension state corrupts across projects | **INVESTIGATE** | CC79 EXT_LOAD=PASS once; lifecycle/reload not closed | PR79 |
| H56 | A test extension passes but real extensions fail | **INVESTIGATE** | Fixture/dir extension PASS != real marketplace extensions | PR79 |
| H57 | Agent session lifetime not owned by a single controller | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H58 | Cancelled agent continues executing tools | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H59 | Old tool results injected into a newer conversation | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H60 | Model-generated tool calls parsed incorrectly | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H61 | Tool permission checks bypassed by alternate entry points | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H62 | Agent edits wrong workspace or file | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H63 | Partial writes leave corrupted source | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H64 | Failed edits cannot be rolled back | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H65 | Agent reports build success without executable evidence | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H66 | Agent loops indefinitely after repeated failures | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H67 | Tool execution blocks model streaming | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H68 | Concurrent agents overwrite one another's changes | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H69 | Agent state cannot recover after application restart | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H70 | Review agent approves untested changes | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H71 | Git commit includes unrelated modifications | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H72 | Agent reports task completion before final tests finish | **OVERLAP** | Maps AgentSession / Issue#49 agent loop; no E2E receipt | PR78/#49 |
| H73 | Model selector points to wrong model or backend | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H74 | Ollama streaming parser mishandles fragmented JSON | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H75 | Inference cancellation leaves active GPU work | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H76 | Backend shutdown leaks threads or memory | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H77 | Model loading succeeds but inference produces invalid output | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H78 | GPU offload counters differ from actual executed operations | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H79 | Quantized kernels produce incorrect numerical results | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H80 | KV-cache rollback corrupts subsequent generations | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H81 | Long-context allocation exceeds available VRAM/RAM | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H82 | Multi-GPU partitioning causes incorrect tensor placement | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H83 | GPU synchronization serializes supposedly parallel execution | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H84 | Fallback paths silently execute on CPU | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H85 | Driver incompatibility is mistaken for a model defect | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H86 | Model switching retains stale tokenizer or sampler state | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H87 | GPU device loss cannot be recovered without restarting the IDE | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H88 | Benchmark throughput excludes prefill, waits or transfers without disclosure | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H89 | Model-format and GGUF shard validation accepts corrupt data | **OVERLAP** | Deep2/GPU ladder #50/#57C / PR76; local Deep2 PARTIAL | PR76/#50/#57 |
| H90 | Local-only operation inadvertently depends on external services | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H91 | Workspace path traversal through agent or extension tools | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H92 | Untrusted model output bypasses tool authorization | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H93 | Shell argument handling allows unintended command execution | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H94 | Sensitive values leak into logs or crash dumps | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H95 | Extension IPC accepts unauthorized commands | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H96 | Downloaded or installed extensions lack appropriate validation | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H97 | Security-sensitive production paths use placeholder cryptography | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H98 | Release binaries depend on undeclared DLLs | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H99 | Installer writes outside intended directories | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H100 | Uninstall or rollback destroys user data | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H101 | Crash recovery replays unsafe or incomplete operations | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H102 | Build artifacts or test receipts are accepted without provenance | **INVESTIGATE** | No CONFIRMED exploit/defect receipt this audit; required proof absent | SEC/PKG |
| H103 | GitHub Actions reports success without executing mandatory tests | **OVERLAP** | Issue #57 A01 CI runner_id=0 / empty steps OPEN; PR75/76 CI fail-before-run | #57/PR75/PR76 |
| H104 | LFS or branch divergence leaves the release source incomplete | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H105 | Signed artifact differs from the tested executable | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H106 | Final release is certified using evidence from multiple SHAs | **INVESTIGATE** | Lineage docs forbid multi-SHA cert; pressure documented; PROMOTE=0 so not a completed false-cert | LINEAGE/H106 |
| H107 | LSP handshake succeeds but diagnostics/completion do not work | **OVERLAP** | Issue #57 A11 LSP gate OPEN | #57 |
| H108 | GhostText appears but accept/cancel edits the wrong range | **OVERLAP** | Issue #57 A12 GhostText OPEN | #57 |
| H109 | Native browser renders but lacks origin or navigation isolation | **OVERLAP** | Issue #57 A13 native browser OPEN | #57 |
| H110 | Git operations modify an unintended repository or branch | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H111 | Snapshot restoration fails after a partially completed edit | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H112 | Settings persist but are not applied to active components | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H113 | Feature registry advertises commands with no real backend | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H114 | Cross-platform functionality is claimed without native execution | **OUT_OF_SCOPE** | Multi-platform native claims (#57 B13-B15) beyond Windows daily-driver unless 100% spec mandates | #57B |
| H115 | Performance tests use synthetic kernels instead of real model decode | **OVERLAP** | Issue #57 C12 synthetic TPS forbidden; perf ladder OPEN | #57C/#50 |
| H116 | Release documentation describes capabilities absent from the binary | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H117 | Acceptance tests omit negative and recovery scenarios | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H118 | Multiple passing components fail when operated simultaneously | **UNVERIFIED** | FOUR_PANEL=NOT_VERIFIED on CC79; oneshot OUTPUT_GUI_E2E=FAIL axis; final-completion OUTPUT_GUI=PASS axis â€” no single integrated PASS | F25/PR77/#49 |
| H119 | Test fixtures conceal environment or dependency requirements | **INVESTIGATE** | No SHA-specific failure receipt this audit; investigate-only | â€” |
| H120 | Final product acceptance omits the complete autonomous coding loop | **UNVERIFIED** | Issue #49 product-final E2E OPEN/NOT_PROVEN | #49 |

## Status tallies (informational; not defect arithmetic)

```
CONFIRMED=1
UNVERIFIED=4
INVESTIGATE=74
OVERLAP=40
OUT_OF_SCOPE=1
```

## Dedup notes

1. Do not add Issue #57 (45) + H01â€“H120 + absent-78 + PR checklists into one failure total.
2. INTEG_004 Problems PASS on sealed 47451F24 is candidate evidence only; CC79 remains controlling.
3. Live integ_004 image 69FE3D92 must not inherit 47451F24 Problems PASS.
4. Finish-25 historical 19/25 is not Finish25_CURRENT 4/25 and is not Issue #49.
5. PR OPEN/CONFLICTING is unfinished acceptance inventory, not automatic CONFIRMED product defect.

## Law

```
INVESTIGATE != CONFIRMED
NOT_RUN != PASS
PROMOTE=0
```
