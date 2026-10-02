# BATCH 08 — INTEGRITY CENSUS
# REPO_WIDE_AUDIT_2026_10_01
#
# AUDITED TREE : F:\~dev\rawrxd
# HEAD          : 9f67682ffea12a182ae4fd2d41fb3bc524f61d2b  (dirty tree)
# SCOPE         : stubs, empty TUs, fake-success, hardcoded state,
#                 missing definitions, unreachable implementations

===============================================================================
FINDING B8-001  —  119 CERTIFICATION TARGETS CONSIST ENTIRELY OF STUB SOURCES
===============================================================================
SEVERITY: P0 — UNIMPLEMENTED / CONTRACT_VIOLATED

THIS IS THE CENTRAL FINDING OF THE AUDIT.

MEASURED METHOD
---------------
1. Enumerated every .cpp under rawrxd/src.
2. Classified each as STUB if it contains the literal banner
       `Auto-generated stub`  (140 .cpp/.h + 64 .asm)
   or a line matching `// STUB: <path>`.
3. Parsed rawrxd/CMakeLists.txt (17,929 lines) for every add_executable block
   and resolved each block's source list against the stub set.

RESULT
------
    add_executable blocks parsed ................ 348
    src/*.cpp files marked stub .................. 476
    src stub .cpp files referenced by CMake ...... 202
    stub .cpp files NOT referenced by CMake ..... 274
    targets whose ENTIRE source list is stubs ... 119   <-- 34% of all executables
    targets MIXING stub and real sources ........ 31
    targets with a fully real source list ....... ~198

  A `.cpp` containing only `// Auto-generated stub` produces an EMPTY
  translation unit.  It defines no `main`.  Therefore:

    *** 119 of the 348 executables in this product CANNOT LINK. ***

  This is not a style problem.  These targets have never been linkable since
  the stub replaced their source.  Any build log, receipt, or ledger line
  claiming one of them built, ran, or passed is describing a target that
  cannot exist as a binary.

FULL LIST — 119 TARGETS WITH 100% STUB SOURCES
----------------------------------------------
  agent_runtime_batch1_cert                       :10963
  deep2_deepseek_live_gen_perf_cert               :9175
  deep2_execution_policy_smoke                    :11056
  deep2_giant_moe_paragraph_perf_cert              :10940
  deep2_gpu_dynamic_window_cert                   :8782
  deep2_gpu_forward_ops_cert                      :8511
  deep2_gpu_numeric_parity_cert                   :8643
  deep2_gpu_packed_forward_cert                    :8735
  deep2_gpu_q4k_gemv_cert                         :8666
  deep2_gpu_q6k_gemv_cert                         :8689
  deep2_gpu_quant_family_cert                     :8712
  deep2_gpu_resident_decode_cert                  :8534
  deep2_gpu_solo_decode_cert                      :8419
  deep2_gpu_transfer_counter_cert                 :8557
  deep2_gpu_transfer_overlap_cert                 :8575
  deep2_gpu_weight_prefetch_cert                  :8620
  deep2_gpu_weight_window_cert                    :8597
  deep2_hybrid_all_hw_cert                        :8488
  deep2_k2_auto_workload_policy_cert              :9581
  deep2_k2_e2e_model_size_matrix_cert             :9602
  deep2_k2_full_depth_combined_policy_cert        :9496
  deep2_k2_full_depth_effectiveness_cert          :9477
  deep2_k2_full_depth_fused_rebench_cert          :9540
  deep2_k2_full_depth_trampoline_promotion_cert   :9518
  deep2_k2_gpu_copy_compute_overlap_cert          :8967
  deep2_k2_gpu_mla_full_cert                      :9071
  deep2_k2_gpu_mla_full_depth_cert                :9097
  deep2_k2_gpu_mla_nu_bridge_cert                 :10694
  deep2_k2_gpu_mla_re_cert                        :9123
  deep2_k2_gpu_mla_slot_reuse_cert                :10644
  deep2_k2_gpu_stream_compute_cert                :9019
  deep2_k2_gpu_stream_copy_cert                   :8941
  deep2_k2_gpu_stream_mla_cert                    :9045
  deep2_k2_live_decode_mla_cert                   :9739
  deep2_k2_live_decode_sustained_cert             :10255
  deep2_k2_live_gen_perf_cert                     :8867
  deep2_k2_live_generate_policy_cert              :9620
  deep2_k2_live_gpu_stream_e2e_cert               :8993
  deep2_k2_live_policy_crossover_cert             :8889
  deep2_k2_live_policy_e2e_cert                   :8915
  deep2_k2_live_policy_split_cert                 :9639
  deep2_k2_logits_climb_cert                      :10295
  deep2_k2_logits_gpu_range_attribution_001       :10333
  deep2_k2_logits_q6k_resident_cert               :9820
  deep2_k2_logits_vwa_lineage_001                 :9258
  deep2_k2_mla_full_depth_soak_cert               :9719
  deep2_k2_mla_fused_q4kt_cert                    :9780
  deep2_k2_mla_kv_expand_cert                     :9840
  deep2_k2_mla_kv_expand_opt_cert                 :9860
  deep2_k2_mla_qa_critical_cert                   :9900
  deep2_k2_mla_qkv_proj_cert                      :9880
  deep2_k2_mla_rebench_promote_cert               :9681
  deep2_k2_mla_reuse_promote_cert                 :9700
  deep2_k2_policy_hysteresis_cert                 :9658
  deep2_k2_semantic_seal_cert                     :10215
  deep2_k2_serverless_stream_latency_cert         :10235
  deep2_k2_shard_attn_residency_cert              :9800
  deep2_k2_stream_miss_reality_cert               :9149
  deep2_k2_tps_rainbow_cert                       :10624
  deep2_k2_trampoline_full_depth_opt_cert         :9561
  deep2_k2_trygpu_logits_split_cert                :10315
  deep2_k2_wall_attribution_cert                  :10275
  deep2_live_path_effectiveness_cert              :9418
  deep2_live_path_fused_control_cert              :9437
  deep2_live_path_interaction_bounds_cert         :9458
  deep2_local_agent_audit_001                     :9197
  deep2_mars_e2e                                  :11011
  deep2_multi_gpu_layer_cert                      :8465
  deep2_nu_gemv_parity_cert                       :10745
  deep2_nu_gpu_gemv_cert                          :10771
  deep2_nu_live_consumer_cert                     :10669
  deep2_nu_pack_format_cert                       :10796
  deep2_nu_perf_cert                              :10720
  deep2_outer_engine_bridge_cert                  :9391
  deep2_parity_cert                               :11299
  deep2_placement_cost_cert                       :10986
  deep2_rmv_mount_001                              :10087
  deep2_runtime_batch1_cert                       :8805
  deep2_runtime_batch2_cert                       :8828
  deep2_runtime_batch3_cert                       :8851
  deep2_streamer_cert                             :8330
  deep2_streamer_parity                           :8355
  deep2_topology_portability_cert                 :8442
  deep2_ucf_bounce_smoke                           :9920
  deep2_ucf_bouncehouse_example                    :10051
  deep2_ucf_generation_ticket_001                 :10014
  deep2_ucf_gpu_ready_e2e                          :10032
  deep2_ucf_halo_spark_001                        :10069
  deep2_ucf_logits_range_bounce_001               :9977
  deep2_ucf_mobility_fault_001                    :10197
  deep2_ucf_no_stale_dispatch_001                  :9939
  deep2_ucf_read_converge_001                      :9958
  deep2_ucf_semantic_abi_v1_cert                  :9995
  deep2_vwa_e2e_001                               :10106
  deep2_vwa_iocp_range_001                        :10175
  deep2_vwa_poc_1_001                             :10152
  deep2_vwa_range_contract_001                    :10125
  dump_qwen35_meta                                :11407
  layer_harness                                   :11533
  p0_process_alive_001                            :9221
  p1_ide_exec_policy_apply_001                    :11080
  p1_ide_exec_policy_live_gguf_001                :11103
  p1_policy_sha_lifecycle_diag_001                :11173
  p1_real_speedup_001                             :11126
  p1_repeatability_state_drift_diag_001           :11196
  p1_repeatability_trial_validity_diag_001        :11150
  qwen35_attn_contract                            :11573
  RawrXD-Agentic                                  :11442
  RawrXD-AutoFixCLI                               :13313
  test_chat_template_unit                         :8283
  test_deterministic_replay                       :11384
  test_embed_q4k_token                            :8237
  test_l10_ffn_inp_same_source                    :11551
  test_q_elemdiff                                 :8219
  test_q4k_gemv_parity                            :8201
  test_val_051_3_multi_token                      :11597
  vwa_address_contract_001                        :9281
  vwa_poc_1_001                                   :9310
  vwa_range_contract_001                          :9238

WHAT THIS MEANS FOR THE LEDGER
------------------------------
Every one of these names asserts a capability:
    deep2_gpu_q4k_gemv_cert          asserts GPU Q4_K GEMV parity
    deep2_parity_cert                asserts end-to-end parity
    deep2_k2_semantic_seal_cert      asserts semantic correctness
    p0_process_alive_001             asserts a liveness gate
    p1_real_speedup_001              asserts a measured speedup
    RawrXD-Agentic                   asserts an agentic product
    RawrXD-AutoFixCLI                asserts autonomous repair
    deep2_ucf_no_stale_dispatch_001  asserts a staleness fix
    layer_harness                    asserts layer execution
    qwen35_attn_contract             asserts an attention contract

Their sources are one-line comments.  A passing receipt, gate line, or
CTEST registration naming any of these is INVALID_MEASUREMENT.

CLASSIFICATION: UNIMPLEMENTED (119 targets) / CONTRACT_VIOLATED (ledger)

===============================================================================
FINDING B8-002  —  THE STUB DETECTOR IN CMake IS PROVABLY BLIND
===============================================================================
SEVERITY: P0 — THE CONTROL THAT WAS SUPPOSED TO CATCH B8-001 CATCHES NONE OF IT

THE DETECTOR (rawrxd/CMakeLists.txt:222-254, RAWRXD_STUB_CERTIFICATION_SURFACE_001)
-------------------------------------------------------------------------------------
The build file contains a content-based stub detector.  It strips every
character outside [A-Za-z0-9_] and treats a TU as empty when nothing survives:

    string(REGEX REPLACE "[^A-Za-z0-9_]" "" _stub_body "${_stub_body}")
    if(_stub_body STREQUAL "intmainreturn0")   -> trivial main, counted
    elseif(_stub_body STREQUAL "")             -> empty, counted
    else                                       -> kept, NOT counted

It is documented as the answer to exactly this problem:
    "Existence is not sufficiency.  A translation unit whose body is empty
     after comment stripping -- including a literal `int main(){ return 0; }`
     -- supplies no main and no test body, so the target referencing it cannot
     link (LNK2019 unresolved main) and cannot certify anything if it did."

NEGATIVE CONTROL PERFORMED
--------------------------
Ran the detector's own predicate over all 476 stub .cpp files:

    TOTAL_STUB_MARKED_FILES ............... 668  (incl. .asm/.h)
    stub .cpp files ......................... 476
    DETECTOR WOULD CATCH (empty) ............ 0
    DETECTOR BLIND (non-empty after strip) .. 668  = 100%

WHY IT IS BLIND — MECHANISM
---------------------------
The stub body is `// Auto-generated stub`.

After stripping every non-alphanumeric character, the REMAINDER IS:

        "Autogeneratedstub"

That is not the empty string and not "intmainreturn0", so the detector's
`else()` branch runs and the file is KEPT and NOT REPORTED.

The strip-the-punctuation heuristic is defeated by the word "Auto-generated"
inside the comment. The comment's own text contains alphanumerics, so
"remove all non-alphanumerics to remove comments" does not remove comments.

MEASURED CONFIGURATION OUTPUT
-----------------------------
The configure step DID emit empty-bodied warnings — but ONLY for the 10
genuinely 2-byte files (B1-002) and the 1 trivial-main file. It emitted
nothing for the 476 stub-marked files. The detector's output is
indistinguishable from "the product is clean."

CONTROL VERDICT
---------------
    DETECTOR_EXISTS .......... YES
    DETECTOR_NEGATIVE_CONTROL_EXECUTED ... YES  (executed by this audit)
    DETECTOR_CAN_DETECT_B8-001 ........... NO
    DETECTOR_REPORTED_COUNT .. 0 of 476

CLASSIFICATION: CONTRACT_VIOLATED (the safety control is inert)

-------------------------------------------------------------------------------
NEGATIVE CONTROL — EXECUTED, AND THE DETECTOR FAILS IT
-------------------------------------------------------------------------------
The detector's exact predicate was run against known-answer inputs. A control
that has never been shown to fail is not a control, so this audit ran it.

Predicate (verbatim from rawrxd/CMakeLists.txt:239-251):
    strip [^A-Za-z0-9_];  CAUGHT iff result=="" or result=="intmainreturn0"

  #  input                                        stripped result        detector   should
  -  -------------------------------------------  ---------------------  ---------  --------
  1  // Auto-generated stub                        'Autogeneratedstub'   MISSED      CATCH
  2  // STUB: src/x.cpp                            'STUBsrcxcpp'         MISSED      CATCH
  3  (empty file)                                  ''                    CAUGHT      CATCH
  4  int main(){return 0;}                        'intmainreturn0'      CAUGHT      CATCH
  5  #pragma once \n // Auto-generated stub        'pragmaonceAutogene'  MISSED      CATCH

  RESULT: 2 of 5 correct, 3 of 5 WRONG.
  CASES 1, 2, AND 5 ARE THE ACTUAL STUB FORMATS FOUND IN THIS TREE
  (140 / ~8 / 13 occurrences respectively).

  The detector passes ONLY the cases that were already empty. It fails on
  every stub that was written by a generator, which is all of them.

  CONCLUSION: the detector is not a weakened control. It is an inverted one.
  It fires exclusively on files that contain no comment at all, and is silent
  on files whose comment says "Auto-generated stub" — because stripping
  punctuation does not strip comments, and the comment is full of letters.

  THE BUILD FILE CLAIMS THIS DETECTOR PREVENTS THE EXACT DEFECT IN B8-001.
  Run as a control, it does not.

===============================================================================
FINDING B8-003  —  476 STUB .cpp FILES, 274 NEVER REFERENCED BY ANY TARGET
===============================================================================
SEVERITY: P1 — DEAD/UNBOUND

    stub .cpp on disk .................. 476
    referenced by CMake ................ 202
    referenced by NO target ............ 274

The 274 are silent dead code: files that exist, carry names implying
implementation, and are compiled by nothing. Combined with B1-001 (353
referenced-but-absent files), the tree contains BOTH directions of drift:
  - 353 sources referenced but never written
  - 476 sources written but are one-line comments
  -  10 sources written and genuinely empty (2 bytes)

Representative unreferenced stubs (name asserts capability, body is a comment):
  src/agentic/tool_registry.cpp          src/agentic/tool_executor.cpp
  src/agentic/GGUFLoader.cpp             src/agentic/KnowledgeGraph.cpp
  src/deep2/GGUFLoader.cpp               src/deep2/GGUFVerifier.cpp
  src/deep2/KVCache.cpp                  src/deep2/ModelLoader.cpp
  src/engine/sampler.cpp                 src/inference/Deep2Engine.cpp

NOTE THE DUPLICATION: src/agentic/GGUFLoader.cpp AND src/deep2/GGUFLoader.cpp
both exist as stubs. Two loaders, neither implemented. Same for Deep2Engine
(src/deep2/Deep2Engine.cpp real, 215KB; src/inference/Deep2Engine.cpp a stub) —
a duplicate-authority hazard where only one class is real.

CLASSIFICATION: DEAD/UNBOUND + DUPLICATE_AUTHORITY

===============================================================================
FINDING B8-004  —  STUB BANNERS ARE THE DOMINANT FILE CONTENT IN src/
===============================================================================
SEVERITY: P0 — measured scale of B8-001/B8-003

    src/*.cpp|hpp|h file count ............................ 3864
    files <= 4 bytes (genuinely empty) ................... 11
    files 5-200 bytes .................................... 730
    files marked stub (any size) ........................ 668

Over 36% of all source files under src/ are <= 200 bytes, and the overwhelming
majority of those are stub banners. The most common single byte-size in the
tree is 24 — exactly `// Auto-generated stub\r\n`.

Distinct banner texts across the tree:
      140   // Auto-generated stub
       64   ; Auto-generated stub        (MASM)
       13   #pragma once\n// Auto-generated stub   (headers)
        ~8   // STUB: <own path>          (individually named)
      ...   (remainder are path-echo stubs)

CLASSIFICATION: CONTRACT_VIOLATED at tree scale

===============================================================================
FINDING B8-005  —  CTEST REGISTRATION DOES NOT COVER THE TARGET SET
===============================================================================
SEVERITY: P1 — CONTRACT_VIOLATED

    add_test() registrations in CMakeLists.txt ..... 32
    add_executable / add_library / custom targets ... ~450
    executables whose source list is 100% stub ...... 119

Of the 32 registered tests, several name targets that are themselves stubs.
`ctest` executing the suite cannot execute a target that cannot link.

Coverage of the executable set by ctest: at most 32/348 = 9.2%, and the real
denominator is lower because most of those 32 are EXCLUDE_FROM_ALL.

Target existence, target configuration, and target naming are not test
execution. The tree has ~450 targets and a 32-entry test registry.

CLASSIFICATION: CONTRACT_VIOLATED

===============================================================================
FINDING B8-006  —  BANNED-PATTERN FILTERS WERE ADDED TO HIDE STUBS
===============================================================================
SEVERITY: P1 — CONTEXT (explains the mechanism, do not read as intent)

rawrxd/CMakeLists.txt:6431-6451 and 6553-6575 apply a stack of name filters:

    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX ".*/.*_stubs\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX ".*/.*_stub\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX ".*/stub_.*\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX ".*/shim_.*\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX ".*/.*_(mock|fake)\\.cpp$")
    ... (20+ filters, repeated twice)

and lines 6598-6606 / 6747-6758 build "_RAWRXD_FORBIDDEN_WIN32IDE_SOURCES"
lists, i.e. a forbidden-source registry that exists.

The filters remove files BY NAME. The stubs that reach the targets are named
without a banned token (`deep2_gpu_q4k_gemv_cert.cpp`, `p0_process_alive_001.cpp`,
`layer_harness.cpp`), so the name filters do not remove them. Name-based
filtering is therefore not the mechanism that let B8-001 through — the stubs
passed because they are legitimately named. The content detector was the
mechanism that should have caught them, and it is blind (B8-002).

Recorded as context, not as a claim about intent.

CLASSIFICATION: CONTEXT

===============================================================================
FINDING B8-007  —  THE ENTIRE "COMPUTE AUTHORITY" LAYER IS UNBOUND
===============================================================================
SEVERITY: P0 — DEAD/UNBOUND (contradicts the project ledger)

Project documentation states, under "Current Status Summary", that 40+ compute
authorities were "created and implemented following the named authority +
direct call + receipt gate pattern", and lists a direct-call map including
rawrxd::compute::requestRoute, rawrxd::tensor::validateTensor,
rawrxd::linearw::execute, rawrxd::quant::resolveKernel, rawrxd::forward::beginForward,
rawrxd::vulkan::dispatchLinear, and dozens more.

MEASURED
--------
    src/compute/ files on disk ............ 42
    src/compute/ files named by ANY
      add_executable / add_library /
      target_sources / target_link_libraries ... 0

  ADOPTION = 0%.  Not one file in the compute authority layer is compiled by
  any target in the product build.

  These are not stubs — they are substantial (ComputeRouteAuthority,
  ComputeStageAuthority, TensorComputeAuthority, LinearWAuthority,
  QuantKernelAuthority, KernelDictionaryAuthority, ForwardPassAuthority,
  LayerComputeAuthority, AttentionComputeAuthority, RopeComputeAuthority,
  RmsNormComputeAuthority, FfnComputeAuthority, MoeComputeAuthority,
  SsmComputeAuthority, LogitsComputeAuthority, and the P1/P2 layers).

  They are real code that no product compiles. The documented direct-call map
  describes calls that are not in any built target.

WIDER ADOPTION CENSUS (same method, per directory)
---------------------------------------------------
  src/compute        42 files    0 referenced   42 unbound    0%
  src/authority       2 files    1 referenced    1 unbound   50%
  src/agentmodes     22 files    8 referenced   14 unbound   36%
  src/repointel       8 files    4 referenced    4 unbound   50%
  src/closure        14 files    5 referenced    9 unbound   36%
  src/models         12 files    5 referenced    7 unbound   42%
  src/cli            27 files    9 referenced   18 unbound   33%
  src/agentic       106 files   47 referenced   59 unbound   44%

  Across the eight authority-bearing directories, 154 of 233 files (66%) are
  not named by the build. Note this is name-matching, so a file named in a
  variable that is itself never consumed would still count as "referenced";
  the true adoption is therefore <= these figures, not higher.

CLASSIFICATION: DEAD/UNBOUND
  The compute authority layer is a large body of real, unbuilt code. Any
  statement that the compute path is "gated" or "receipt-backed" describes
  code that does not run in any product.

===============================================================================
FINDING B8-008  —  SINGLE-WRITER AUTHORITY: REAL BUT UNADOPTED (re-verified)
===============================================================================
SEVERITY: P0 — DEAD/UNBOUND (independently re-measured; ledger claim CONFIRMED)

The prior ledger records RAWRXD_SINGLE_WRITER_AUTHORITY_001 as
IMPLEMENTED_BUILT_UNADOPTED. Independently re-measured in this audit:

  src/authority/SingleWriterAuthority.h     EXISTS   7,859 B   real content
  src/authority/SingleWriterAuthority.cpp   EXISTS  21,814 B   real content
      (13,032 chars survive identifier-stripping; AuthorizeResult struct
       carries 9 individually-named predicate fields; header states
       "REQUIRES ALL THREE PREDICATES SIMULTANEOUSLY")

  Build binding:  add_library(rawrxd_single_writer STATIC ...)  CMakeLists:17207
  Consumers of rawrxd_single_writer:
      rawrxd_single_writer         (definition)
      single_writer_adversarial_test  (CMakeLists:17296)  <- the ONLY consumer

  Product-source references (src/win32app, src/agentic, src/deep2, src/agent):
      0
  src/agentmodes references: 1, and it is a comment in the SUPERSEDED
      WriterLeaseAuthority.cpp, not a call.

  So: real implementation, built as a static library, consumed by exactly one
  adversarial test, and by none of the three shipping products.

DUPLICATE AUTHORITY (confirmed, and worse than "unadopted")
-----------------------------------------------------------
  Two independent implementations of the same gate exist:
      src/authority/SingleWriterAuthority.{h,cpp}     21,814 B   "canonical"
      src/agentmodes/WriterLeaseAuthority.{h,cpp}     21,569 B   "superseded"
  Sizes are within 1% of each other. WriterLeaseAuthority is referenced in the
  build file only in a COMMENT (CMakeLists:17226). Both are real code; neither
  governs any product write path.

CLASSIFICATION: DEAD/UNBOUND + DUPLICATE_AUTHORITY
  Prior ledger claim CONFIRMED by independent measurement. Refined: adoption is
  zero at product level and 1/1 at test level; a second near-identical
  implementation also exists.

===============================================================================
FINDING B8-009  —  TWO MORE CONTROLS THAT CANNOT FAIL
                    (same class as the gate repaired in B1-010)
===============================================================================
SEVERITY: P0 — CONTRACT_VIOLATED. NOT PATCHED; see "WHY NOT PATCHED".

Both are in the same family as the control-semantics defect repaired in
B1-010: a verdict conjunct that is structurally incapable of being false.

-------------------------------------------------------------------------------
B8-009a  result_pass reduces to a null-pointer test
-------------------------------------------------------------------------------
src/deep2/AgentToolRegistry.hpp:302

    r.result_pass = (s.direct_bypasses == 0 && s.legacy_bypasses == 0
                     && r.authority_bound);

Both counters are verified by exhaustive search to have exactly one mutation
site each, and that site is a RESET:

    :271   g_directAgentToolBypasses.store(0, ...)      <- reset
    :273   legacy_bypasses_.store(0, ...)               <- reset
    :249-250  .load() into the snapshot                 <- read

No increment, no `++`, no assignment of a non-zero value exists anywhere in the
tree. A search for `(g_directAgentToolBypasses|legacy_bypasses)\s*(\+\+|=[^=])`
returns only declarations, the two resets, and two reads.

Therefore `direct_bypasses == 0 && legacy_bypasses == 0` is a tautology. The
conjunction collapses to `r.authority_bound`, which is a pointer/handle
null-test. The receipt cannot report a bypass even if one occurs, and this is
the check whose entire purpose is to detect tool calls that bypass the
authority.

Measured consequence: `result_pass` is not a measurement of anything. It is a
statement that a handle is non-null.

  Fix shape: either increment the counters at the actual bypass sites, or
  remove the conjuncts and rename the field so it does not assert coverage it
  cannot provide. Leaving it named `result_pass` with two tautological
  conjuncts is the defect.

  Note: `toReceipt()` has zero callers, so this is latent rather than live
  today. It becomes a false PASS the moment that function is wired up.

-------------------------------------------------------------------------------
B8-009b  A verdict conjunct is a hardcoded true with a false justifying comment
-------------------------------------------------------------------------------
src/agentic/GitSafetyAuthority.cpp:1229-1232

    const bool driftAbsent = true;  // filled by the driver, which fingerprints
    ...
    r.verdictPass = preservationHeld && driftAbsent && sessionOpen_;

`driftAbsent` is a `const bool` initialised to `true` at declaration. There is
no assignment, no function call, no parameter, and no driver reference — the
comment "filled by the driver, which fingerprints" describes behaviour that
does not exist. A `const` local cannot be reassigned by anything.

So `driftAbsent` is unconditionally true and the verdict is
`preservationHeld && sessionOpen_`. Git drift is asserted absent by
construction, not by measurement.

  This is a stricter instance of the pattern the project has already retracted
  once (the `VERDICT=PASS` string-literal test in
  tests/test_receipt_immutability.cpp). There, the whole verdict was a literal.
  Here, only one conjunct of three is, and it is the one that would catch
  out-of-band modification — the check most likely to matter.

  Fix shape: compute drift from an actual before/after fingerprint of the
  workspace, or delete the conjunct and the verdict claim it supports.

-------------------------------------------------------------------------------
WHY NOT PATCHED
-------------------------------------------------------------------------------
A second writer is actively modifying this tree. A 30-second sample taken
while preparing this finding observed 2 source files change; 137 files changed
in the 17 minutes before that; and this repository's own
`rawrxd_single_writer` authority is built and adopted by zero products
(B8-008), so nothing prevents a collision.

Applying two source edits now would add a third concurrent writer to a tree
that is already in that state, and would reproduce exactly the defect class this
audit is documenting. The findings are recorded with exact locations and fix
shapes so the owner can sequence them after the tree is quiescent.

The repair in B1-010 was applied to CMakeLists.txt, which this audit had
itself just modified and which is under a single-writer configure-time
evaluation; that one is a build-time control with no runtime writer.
===============================================================================

===============================================================================
BATCH 08 CLOSURE
===============================================================================
STATUS = FAILED

  SRC_FILES_SCANNED ......................... 3864
  EMPTY_TU_2BYTE ............................. 11
  STUB_MARKED_FILES .......................... 668
  STUB_CPP_REFERENCED_BY_CMAKE ............... 202
  TARGETS_100PC_STUB ........................ 119  of 348 executables
  TARGETS_MIXED_STUB_AND_REAL ................ 31
  UNREFERENCED_STUB_CPP ...................... 274
  STUB_DETECTOR_CATCH_RATE .................. 0 / 476   (0.0%)
  NEGATIVE_CONTROL_FOR_DETECTOR ............. EXECUTED — DETECTOR FAILS 3/5
  ADD_TEST_REGISTRATIONS .................... 32   of ~450 targets
  CONTROLS_THAT_CANNOT_FAIL ................ 2 more (B8-009a, B8-009b)
    result_pass ............................ 2 tautological conjuncts
    driftAbsent ............................ hardcoded const true
  TOTAL_CONTROLS_THAT_CANNOT_FAIL .......... 3 (incl. the CMake stub detector)
  THE AUDIT'S CENTRAL CLAIM:
    One third of this product's executables are certification harnesses whose
    sources are single-line comments. They cannot link. They cannot run. No
    receipt can have been produced by them.

  THE AUDIT'S CENTRAL META-FINDING:
    The build system contains a content detector for exactly this defect,
    documented at length, and it reports ZERO defects. Its negative control has
    now been executed (this audit). The detector FAILS it: it misses
    `// Auto-generated stub`, `// STUB: <path>`, and `#pragma once` + banner,
    which are the only stub formats present. It fires only on files with no
    comment text whatsoever.