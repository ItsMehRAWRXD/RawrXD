# RAWRXD_ENTERPRISE_PRODUCT_CERT_001 — CHECKLIST_V1

VERSION=1.0
ASOF_LOCAL=2026-11-13T22:35:00-05:00
GATES_TOTAL=128
GATES_VERIFIED_PASS=0
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0
LAW=NOT_RUN != PASS; maturity scoreboard ≠ checklist completion
CROSS_SHA_CREDIT=0 for any PASS

Binder note: CLI/GUI board floor % (67/48/48) is engineering maturity only — does **not** imply checklist completion.


## CAT01 — Source integrity and reproducible builds

- [ ] G01-01 Freeze exact release Git commit and submodule revisions
- [ ] G01-02 Complete source dependency license and artifact inventories
- [ ] G01-03 Build CLI from clean checkout without undocumented prerequisites
- [ ] G01-04 Build Win32 GUI from same frozen source baseline
- [ ] G01-05 Verify deterministic or explainably reproducible build outputs
- [ ] G01-06 Record compiler SDK linker flags and executable SHA-256
- [ ] G01-07 Run CI on Windows and supported secondary platforms
- [ ] G01-08 Reject missing symbols unresolved dependencies and development stubs

## CAT02 — Native inference engine

- [ ] G02-01 Parse and validate GGUF headers metadata tensors and shard indices
- [ ] G02-02 Verify tokenizer BOS EOS and chat-template parity
- [ ] G02-03 Certify Q4_K Q5_K Q6_K F16 and F32 supported operations
- [ ] G02-04 Verify embedding norm QKV RoPE attention FFN logits vs reference
- [ ] G02-05 Prove numerical parity across multi-token decode and KV reuse
- [ ] G02-06 Generate coherent deterministic text across supported model matrix
- [ ] G02-07 Reject invalid shapes nonfinite tensors unsupported architectures safely
- [ ] G02-08 Prove CPU and GPU execution with no silent backend fallback

## CAT03 — GPU VRAM and performance

- [ ] G03-01 Validate Radeon AI PRO R9700 runtime and device selection
- [ ] G03-02 Validate RX 7800 XT runtime and device selection
- [ ] G03-03 Verify dual-GPU allocation synchronization and ownership
- [ ] G03-04 Verify GPU-resident decode with transfer and fallback counters
- [ ] G03-05 Prove cancellation unload reload and VRAM reclamation
- [ ] G03-06 Benchmark TTFT decode TPS throughput and peak memory
- [ ] G03-07 Run sustained concurrency thermal and resource-pressure tests
- [ ] G03-08 Verify numerical correctness under promoted performance optimizations

## CAT04 — Large models MoE and REAP

- [ ] G04-01 Validate Qwen DeepSeek Kimi MiniMax and Nemotron supported variants
- [ ] G04-02 Verify architecture-specific attention routing GDN and KV semantics
- [ ] G04-03 Verify MoE expert ID mapping top-k and tensor acquisition correctness
- [ ] G04-04 Export physically reduced models without modifying originals
- [ ] G04-05 Measure reduced-model disk RAM and VRAM footprints separately
- [ ] G04-06 Compare reduced and full model quality on fixed evaluations
- [ ] G04-07 Verify streaming and multi-shard integrity under memory pressure
- [ ] G04-08 Certify unsupported-model rejection and corruption recovery

## CAT05 — CLI product completeness

- [ ] G05-01 Complete all documented CLI commands and help contracts
- [ ] G05-02 Implement stable local model selection loading and unloading
- [ ] G05-03 Verify interactive chat session resume and streaming
- [ ] G05-04 Verify tool invocation permission checks and result reinjection
- [ ] G05-05 Verify terminal ConPTY start output stop and cleanup
- [ ] G05-06 Verify real read edit build test agent workflows
- [ ] G05-07 Verify deterministic errors exit codes and cancellation
- [ ] G05-08 Pass clean-machine CLI end-to-end acceptance

## CAT06 — Win32 GUI product completeness

- [ ] G06-01 Launch and close without crashes or leaked resources
- [ ] G06-02 Verify editor open save reopen encoding and undo redo
- [ ] G06-03 Verify dock layout resizing themes and persistence
- [ ] G06-04 Verify local chat generation stop and session lifecycle
- [ ] G06-05 Verify Output Problems and terminal HWND interactions
- [ ] G06-06 Verify real model generation for every advertised model family
- [ ] G06-07 Verify editor-to-agent file edits and reviewable diffs
- [ ] G06-08 Pass clean-machine GUI end-to-end acceptance

## CAT07 — Language services and debugging

- [ ] G07-01 Complete LSP process launch and JSON-RPC initialization
- [ ] G07-02 Verify diagnostics completion hover and go-to-definition
- [ ] G07-03 Verify rename references formatting and workspace edits
- [ ] G07-04 Verify language-server restart timeout and crash recovery
- [ ] G07-05 Verify debugger attach launch breakpoints and stepping
- [ ] G07-06 Verify call stacks watches locals and variable inspection
- [ ] G07-07 Verify click-to-line and Problems navigation
- [ ] G07-08 Prove LSP and debugger behavior inside the actual GUI

## CAT08 — Autonomous agents and tools

- [ ] G08-01 Verify planner executor reviewer roles with local models
- [ ] G08-02 Enforce explicit filesystem shell and Git tool authority
- [ ] G08-03 Run real multi-file edits with patch validation
- [ ] G08-04 Recover automatically from a deliberately failing build
- [ ] G08-05 Run tests and inspect their actual outputs
- [ ] G08-06 Verify rollback checkpoints and transaction recovery
- [ ] G08-07 Verify bounded retries cancellation and loop termination
- [ ] G08-08 Prove multi-agent concurrency without state corruption

## CAT09 — Sunshine game-development workflow

- [ ] G09-01 Open a real Sunshine engine project
- [ ] G09-02 Index and navigate the game source and assets
- [ ] G09-03 Implement a real gameplay or engine source change
- [ ] G09-04 Build the engine and a representative game target
- [ ] G09-05 Run automated game and engine regression tests
- [ ] G09-06 Debug a real runtime issue through the IDE
- [ ] G09-07 Verify asset pipeline packaging and executable launch
- [ ] G09-08 Complete a fully offline agent-driven game-development task

## CAT10 — Security and privacy

- [ ] G10-01 Complete threat model and privileged-operation review
- [ ] G10-02 Enforce local-only model and tool execution by default
- [ ] G10-03 Prove no mandatory cloud calls telemetry or account sign-in
- [ ] G10-04 Test prompt-injection and untrusted-repository defenses
- [ ] G10-05 Validate sandbox boundaries and command authorization
- [ ] G10-06 Run dependency secret and vulnerability scans
- [ ] G10-07 Verify update integrity signature validation and rollback
- [ ] G10-08 Complete security incident handling and vulnerability disclosure

## CAT11 — Reliability and recovery

- [ ] G11-01 Run crash restart and process-lifecycle tests
- [ ] G11-02 Run memory leak and handle leak detection
- [ ] G11-03 Run out-of-memory disk-full and device-loss tests
- [ ] G11-04 Verify corrupt-model and partial-shard rejection
- [ ] G11-05 Verify power-loss and interrupted-write recovery
- [ ] G11-06 Verify concurrent sessions and workspace isolation
- [ ] G11-07 Run extended soak tests with defined failure thresholds
- [ ] G11-08 Demonstrate backup restore and data-integrity preservation

## CAT12 — Packaging and deployment

- [ ] G12-01 Create versioned CLI and GUI release artifacts
- [ ] G12-02 Produce a signed Windows installer and uninstaller
- [ ] G12-03 Install on a clean supported Windows machine
- [ ] G12-04 Verify required runtimes and GPU dependencies
- [ ] G12-05 Verify upgrades preserve settings and project data
- [ ] G12-06 Verify uninstall removes owned components safely
- [ ] G12-07 Produce offline installation and recovery instructions
- [ ] G12-08 Validate release checksums provenance and distribution

## CAT13 — Enterprise operations

- [ ] G13-01 Publish supported hardware OS and model compatibility matrix
- [ ] G13-02 Document configuration policies and deployment controls
- [ ] G13-03 Provide local logs metrics and diagnostic export
- [ ] G13-04 Implement least-privilege and access-control policies
- [ ] G13-05 Define support lifecycle patching and maintenance windows
- [ ] G13-06 Define service-level objectives and incident response
- [ ] G13-07 Validate organizational deployment and rollback procedures
- [ ] G13-08 Complete enterprise administration and troubleshooting documentation

## CAT14 — Quality assurance and competitive parity

- [ ] G14-01 Freeze a dated list of 25 comparable AI IDE products
- [ ] G14-02 Define common feature usability and reliability benchmarks
- [ ] G14-03 Run identical coding tasks for RawrXD CLI and GUI
- [ ] G14-04 Measure task success latency resource use and failure recovery
- [ ] G14-05 Compare offline autonomy and local inference capabilities
- [ ] G14-06 Publish evidence and uncertainty for each benchmark result
- [ ] G14-07 Run independent user acceptance and accessibility testing
- [ ] G14-08 Resolve all release-blocking defects and regressions

## CAT15 — Legal licensing and commercial readiness

- [ ] G15-01 Verify ownership and contribution provenance of source assets
- [ ] G15-02 Audit third-party and model licenses and redistribution rights
- [ ] G15-03 Generate and review software bill of materials
- [ ] G15-04 Publish EULA privacy and support terms where applicable
- [ ] G15-05 Document warranty liability and security obligations
- [ ] G15-06 Establish versioning release notes and customer documentation
- [ ] G15-07 Validate licensing and offline activation requirements
- [ ] G15-08 Prepare a defensible commercial valuation and due-diligence package

## CAT16 — Final certification and release

- [ ] G16-01 Bind every acceptance receipt to exact tested source and executable SHAs
- [ ] G16-02 Obtain independent review of CLI evidence
- [ ] G16-03 Obtain independent review of GUI evidence
- [ ] G16-04 Prove the full local inference-to-tool-to-test workflow
- [ ] G16-05 Run final offline clean-machine acceptance on release binaries
- [ ] G16-06 Obtain security QA and release-owner sign-offs
- [ ] G16-07 Publish immutable certification evidence and release manifest
- [ ] G16-08 Set PROMOTE=1 only after every mandatory gate passes
