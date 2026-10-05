RAWRXD_MISSING_SOURCE_001 — End-to-end test closure, measured
Date: 2026-10-04
Tree:  F:\~dev\rawrxd   Build: F:\~dev\rawrxd\build   Config: Release x64
Compiler: MSVC 14.44.35207 (VS2022 BuildTools), ML64 for MASM

================================================================================
1. WHAT THE USER ASKED FOR, AND THE MEASURED ANSWER
================================================================================
"Please continue adding any source file that isn't already here."

Measured, not estimated. Two different things are called a missing file in this
tree, and they need different work:

  (a) A translation unit declared in CMakeLists.txt with no file on disk.
      Count at the start of this session: RAWRXD_GRAPH_SOURCES_ABSENT=2, of which
      RAWRXD_DROPPED_SOURCE_TOTAL=1 (src/unresolved_asm_stubs.asm).

  (b) A header that a translation unit #includes with no file on disk.
      Count: 7. The build-graph census CANNOT see this class -- it scans
      CMakeLists.txt for declared SOURCES, and an #include is not a source-list
      entry. RAWRXD_BUILD_GRAPH_CENSUS_001 reports these files as PRESENT.

Class (b) is the real work and all 7 are now authored. This is the third
instance in this project's history of the pattern the ledger names: a declared
unit counted PRESENT while being unable to compile.

================================================================================
2. FILES AUTHORED (7) — each has its implementation already in the tree
================================================================================
Every one of these was reconstructed from use sites in an existing
implementation, not from a specification. A wrong declaration is a compile
error, not a silent mismatch; all 7 now compile.

  NEW  src/core/context_config.h
       Missing: src/core/gold_link_closure.cpp:20 C1083.
       Derived from src/core/context_config.cpp (417 lines, NOT in any target).
       NOTE: 7 ContextLimits CONSTANT VALUES could not be recovered — no
       definition survives anywhere in the tree. They are tagged UNMEASURED in
       the header and are chosen, not recovered. This is the single judgement
       call in this session.

  NEW  include/InferenceProfiler.h
       Missing: src/core/gold_inference_profiler_minimal.cpp:2 C1083.
       4 methods, all from the .cpp. GetPrometheusText() returns a fixed
       string; the class records nothing. Documented as such in the header.

  NEW  include/enterprise/support_tier.h
       Missing: src/core/support_tier.cpp:12 C1083.
       Derived from a complete 340-line implementation. Enum orderings and the
       7-member SLAConfig layout are forced by the aggregate initialisers.

  NEW  include/reasoning_pipeline_orchestrator.h
       Missing: reasoning_pipeline_orchestrator.cpp:12 AND
                reasoning_cot_bridge.cpp:18 C1083. Two live TUs, 1549 lines of
       implementation. 7 types + 40 methods. Two items flagged as having NO
       use site: StreamingInferenceCallback's signature, and the OnComplete
       callback's parameter type.

  NEW  src/core/sqlite3.h
       Missing: src/core/sqlite_wrapper.cpp:14 C1083.
       NOT the upstream header. 25 entry points, every prototype transcribed
       from src/core/sqlite3.c (9,455,951 B, SQLite 3.47.2) so the declarations
       match the definitions they link against.

  NEW  src/sovereign/SovereignCoreWrapper.hpp
       Missing: src/core/gold_link_closure.cpp:419 C1083.
       src/sovereign/ existed; this header did not. Stale .obj copies survive
       in 3 older build dirs, which is why it reads as a deletion rather than
       a never-written file.

  NEW  src/video/tubi_backend.h
       Missing: src/core/gold_link_closure.cpp:772 C1083.
       src/video/ did not exist. Two files stub renderVideoClip and they
       DISAGREE on return type (TubiRenderResult vs std::expected<T,R>);
       build-graph membership decided which one this header matches. The
       disagreement is recorded, not resolved.

================================================================================
3. DEFECTS REPAIRED IN EXISTING FILES (7 files)
================================================================================
  src/build/BuildIntelligence.cpp            C2065 'out' undeclared (line 223).
                                            The stream is 'ofs'. Blocked RawrXD_Gold.
  src/diagnostics/DiagnosticsEngine.cpp      C2228 x3. `bool initialized_` used
                                            via .store()/.load(). Now atomic<bool>.
  include/PathResolver.h                     C3861/C2065 x5. Used
                                            GetEnvironmentVariableA and MAX_PATH
                                            with no <windows.h>. Added it to the
                                            header, not to call sites.
  src/ai/SpeculativeTreeAttentionBridge.hpp  C2280 x4. Move ops were `= default`
  src/ai/speculative_tree_attention_bridge.cpp   over std::mutex/atomic/condvar.
                                            Now DELETED — moving a class holding
                                            a live thread pool is a shutdown race.
  src/core/gold_link_closure.cpp             C4430/C2825 cascade + C2511.
                                            (i) #include "modules/vscode_
                                            extension_api.h" resolved to a
                                            313-byte RAWRXD_GRAPH_RESTORED_001
                                            stub declaring RawrXD::Modules::
                                            VSCodeExtensionAPI — a different class
                                            in a different namespace. The real
                                            80,223-byte header is include/
                                            vscode_extension_api.h.
                                            (ii) executeCommand was defined with
                                            2 params; no such overload exists.
                                            Reduced to the declared 1-param form
                                            (the only caller passes 1 arg).
  src/unresolved_asm_stubs.asm               A2008 x3. Opened with .686P/.XMM/
                                            .model — 32-bit MASM boilerplate in an
                                            x64 ml64 target. Now matches every
                                            other .asm in the target.
  inference_authority_ladder.cpp             The RAWRXD_LADDER_EMIT block was
                                            present TWICE, identically. Verified
                                            fixed by execution, not inspection.

================================================================================
4. MEASURED RESULT ON RawrXD_Gold
================================================================================
  BEFORE first repair   95 error lines,  5 distinct failing translation units
  AFTER all repairs     27 error lines,  2 distinct failing translation units

  Fixed TUs (verified compiling):
    support_tier.cpp  gold_inference_profiler_minimal.cpp  gold_link_closure.cpp
    sqlite_wrapper.cpp  reasoning_pipeline_orchestrator.cpp  reasoning_cot_bridge.cpp
    DiagnosticsEngine.cpp  BuildIntelligence.cpp  PathResolver.h consumers
    speculative_tree_attention_bridge.cpp  unresolved_asm_stubs.asm

  STILL FAILING — and this is NOT a missing file:
    src/core/ssot_handlers_ext.cpp   26 errors
    src/core/gold_link_closure.cpp    1 error (the missing header below)

  Both remaining blockers are API DRIFT, not absence:
    ssot_handlers_ext.cpp (5000+ lines) needs AgentOllamaClient::GetConfig,
      SetConfig, FIMSync, a 1-arg ChatSync, and InferenceResult::response.
      The header on disk declares ChatSync(messages, options) and
      InferenceResult{success, content, error, tokensGenerated, tokensPrompt}.
    The 1542-byte src/agentic/AgentOllamaClient.h in the working tree is
      byte-for-byte the same document as git HEAD, and the same 1542 bytes in
      BOTH worktrees (festive-wakeboard). No richer version exists in git
      history at HEAD..HEAD~3 or in either worktree.

  => ssot_handlers_ext.cpp was written against an AgentOllamaClient that never
     existed in this repository. Authoring those 26 members would be DESIGNING a
     public agent API to satisfy one consumer, not recovering a lost one. Not
     done, deliberately.

  MISSING AND STILL MISSING: agentic/SovereignInferenceClient.h
    (gold_link_closure.cpp:878 C1083). Recoverable, but it additionally requires
    InferenceResult::error(...) to be ADDED to AgentOllamaClient.h — an API
    addition, not a transcription. Deferred with the drift above because both
    consumers are chasing the same richer class and neither answer is decided.

================================================================================
5. END-TO-END TEST — MEASURED, RUNNING
================================================================================
Target: inference_authority_ladder   (the repo's only G1-G9 E2E harness)

  BUILD   inference_authority_ladder.vcxproj   EXIT=0   exe 1,410,048 B
          F:\~dev\rawrxd\build\bin\Release\inference_authority_ladder.exe

  RUN, CPU ROUTE, real model G:\~dev\rawrxd\models\
      tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf, 12 tokens/prompt

    G1 MODEL_LOAD             PASS
    G2 TOKENIZATION           PASS
    G3 FORWARD_EXECUTION      PASS
    G4 NUMERICAL_CORRECTNESS  PASS
    G5 SAMPLING_CORRECTNESS   PASS
    G6 TOKEN_STREAMING        PASS
    G7 IDE_DELIVERY           PASS
    G8 PERFORMANCE            PASS   0.85-0.91 tok/s decode, 12/12 tokens
                                        on all 8 generations
    G9 CROSS_ROUTE_PARITY     FAIL   no reference supplied — fails closed by
                                        design, not a skip

    ROUTE=CPU  GATES_FAILED=1  GPU_FALLBACK=0
    emitted_greedy_tokens lines printed = 1   (was 2 before the harness fix)

  RUN, VULKAN ROUTE, same model, compared against the CPU reference

    G1 PASS  G2 PASS
    G3-G9 FAIL. 0 tokens produced.

    BATCH9_VULKAN_INIT=DEVICE_BACKED devices=2 plan_active=0
    [DualRowStrict] DUAL_ROW_HOST_LANE_REFUSED strict=1 residentFirst=0
                    forceLayerSplit=0 devices=2 isMoE=0 useMLA=0

    This refusal is CORRECT and is doing its job. See the comment at
    Deep2Engine.cpp:7262-7279: the dual-row path would execute the whole model
    on the CPU host lane and then report ExecutionRoute::VulkanDualRow — a GPU
    PASS for CPU work. Under strict authority it fails closed instead.
    plan_active=0 is the underlying fact: Vulkan initialises device-backed but
    no weight-residency plan is active for a 1.1B dense model.

  VERDICT = PARTIAL.
    The inference end-to-end path is closed and passing on CPU: the target
    builds, runs, and produces correct tokens for all 7 substantive gates.
    Cross-route parity cannot pass because the GPU route produces no tokens,
    and that is a residency-capability gap, not a missing source file. Adding
    files does not change it.

================================================================================
6. FINDING WORTH RAISING SEPARATELY — SOURCE EXCLUDED FROM VERSION CONTROL
================================================================================
.gitignore:44  /rawrxd/src/build/

That rule git-ignores an entire SOURCE directory. Measured:

    rawrxd/src/build/BuildIntelligence.cpp   15,421 B   UNTRACKED
    rawrxd/src/build/BuildIntelligence.hpp    5,175 B   UNTRACKED
    tracked files under rawrxd/src/build/          = 0

Consequences:
  - The BuildIntelligence.cpp C2065 repair in section 3 exists ONLY on disk.
    There is no version-control copy. That is exactly the situation
    AGENTS.md 7a.3 describes, and it is a standing condition rather than an
    incident.
  - Any `git clean -xdf`, or any checkout performed by another session, can
    delete live source with no warning and no recovery path.
  - The same pattern at .gitignore:45 (/rawrxd/src/deep2/build/) is harmless —
    that directory holds only a .receipt.txt and a .sha256.

RECOMMENDATION: remove .gitignore:44, or negate it with `!/rawrxd/src/build/`
followed by explicit re-add of the 2 source files. NOT DONE HERE — amending
.gitignore and staging files that other sessions are also touching is not a
change to make unilaterally in a tree with concurrent writers.

================================================================================
7. OBSERVED CONCURRENCY (recorded, not attributed)
================================================================================
Per AGENTS.md 7a.1, no writer, process or session is named for any of these.
Only the observations:

  - Two Agent Manager worktrees exist under F:\~dev\.kilo\worktrees\
    (festive-wakeboard, sable-manager). Their last directory writes were
    02:33 and 01:22 today.
  - CMakeLists.txt changed under the build between successive configures:
    GRAPH_SOURCES_REFERENCED went 1415 -> 1419 -> 1415, and CMakeLists.txt:16186
    shifted to :16207 and back within minutes.
  - Two consecutive configures failed with
    "Cannot find source file: src/deep2/Deep2Engine.cpp" while that file was
    stably present (4 samples 3 s apart: 445,672 B, mtime unchanged,
    and a direct `cmake -P` if(EXISTS) probe returned YES). The next configure
    succeeded, exit 0.
  - src/unresolved_asm_stubs.asm appeared mid-session (mtime 11:42:27,
    untracked) carrying 32-bit MASM boilerplate that cannot assemble in this
    x64 target. It was snapshotted before repair:
      rawrxd/src/unresolved_asm_stubs.asm.pre_masm_fix.bak
      SHA256 EBB2410EFEABF5DDF806F2A5D528E70095F5C33D7718C1DA0C7AA6970C828DAF
  - MSBuild processes were reaped twice mid-build with no cl.exe error and no
    memory pressure (39.7 GB of 64.6 GB free). Cause not established.

Practical consequence recorded so it is not rediscovered: in this tree a
configure failure naming a "missing" source should be re-checked with
`cmake -P` and Test-Path BEFORE concluding the file is absent. Both of mine were.

================================================================================
8. TWO INSTRUMENT DEFECTS FOUND IN MY OWN WORK THIS SESSION
================================================================================
Both produced confident, specific, wrong intermediate conclusions and both were
caught only by cross-checking the instrument against the thing it measures.

  A) Symbol census truncated names.
     Matching sqlite symbols with \bsqlite3_[A-Za-z_]+ excludes digits, so
     sqlite3_bind_int64 read as sqlite3_bind_int and sqlite3_open_v2 as
     sqlite3_open. The header faithfully declared the truncated names and the
     build reported
       sqlite_wrapper.cpp(68,14): error C3861: 'sqlite3_bind_int64':
                                      identifier not found
     which names a real SQLite function at a real call site, and reads as "the
     wrapper calls something that does not exist" when in fact the census had
     never seen the name. Re-run with [A-Za-z0-9_]+: 25 entry points, 3 of
     which carry a digit.

  B) A nested comment terminator in the header I wrote.
     src/core/sqlite3.h quoted sqlite3.c's commented-out include directive
     inside a /* ... */ block, so the */ closed the comment early and the whole
     declaration block became comment text:
       sqlite3.h(62,50): error C2018: unknown character '0x60'
       sqlite3.h(71,12): error C2143: syntax error: missing ';' before '{'
     followed by ~40 downstream C3861s for sqlite3_step, sqlite3_errmsg,
     sqlite3_column_text and the rest. All 40 pointed at call sites and named
     real functions; the fault was 9 lines earlier in the same file.

================================================================================
9. NOT DONE, AND WHY
================================================================================
  ssot_handlers_ext.cpp API drift (26 errors)  — needs a richer
      AgentOllamaClient than exists anywhere. See section 4.
  agentic/SovereignInferenceClient.h          — needs an API addition to
      AgentOllamaClient.h first. See section 4.
  vram_probe.h                                — context_config.cpp includes it
      and it is absent, but context_config.cpp is in NO target in this build
      tree (verified against every .vcxproj), so it blocks nothing. Inventing a
      VRAM probe interface with no implementation behind it would add
      unverifiable surface.
  .gitignore:44 amendment                     — see section 6.
  251 one-line // STUB: translation units in src/deep2 — CMake already removes
      these from most lists ("AUTO-REMOVED: stub file") and they export no
      symbol. Writing bodies for them would not change any verdict above.

  The Vulkan route's 0 tokens. Not a file problem: plan_active=0 and a strict
  authority correctly refusing to label CPU execution as a GPU run.

================================================================================
10. SUMMARY
================================================================================
  MISSING_FILES_FOUND_BY_INCLUDE_SCAN      7
  MISSING_FILES_AUTHORED                   7
  EXISTING_DEFECTS_REPAIRED                 7 files
  RAWRXD_GOLD_ERROR_LINES                  95 -> 27
  RAWRXD_GOLD_FAILING_TRANSLATION_UNITS     5 -> 2
  CONFIGURE_EXIT                           0
  E2E_LADDER_BUILD_EXIT                    0
  E2E_CPU_GATES_PASS                       7 of 8 substantive (G1-G8)
  E2E_CPU_TOKENS_PER_GENERATION            12 of 12, all 8 generations
  E2E_VULKAN_TOKENS                        0   (dual_row_host_lane_refused)
  E2E_G9_CROSS_ROUTE_PARITY                FAIL  (no second route produces tokens)
  DUPLICATE_EMIT_LINES                     2 -> 1   (verified by execution)
  UNTRACKED_SOURCE_FILES_DISCOVERED        2   (see section 6)

  VERDICT = PARTIAL

  The inference end-to-end test builds and runs and passes G1-G8 on real
  weights with real tokens. RawrXD_Gold's two remaining failures are API drift
  against a class that does not exist, and authoring it would be invention
  rather than recovery. Two source files are excluded from version control by
  a build-output ignore rule and should be tracked before anything else.

================================================================================
PART 2 — CONTINUED. RawrXD_Gold now COMPILES. 95 -> 0 compile errors.
================================================================================

PART 1 section 4 concluded that ssot_handlers_ext.cpp's 26 errors were
unrecoverable API drift. THAT CONCLUSION WAS WRONG, and the way it was wrong is
worth recording.

I had searched for the class name, found only the trimmed header, and checked
git HEAD..HEAD~3 plus both worktrees for a richer copy. All four agreed, so I
concluded the consumer was written against a class that never existed.

What I did not do was read the sentence at the top of the trimmed header:

    // AgentOllamaClient.h -- Ollama LLM client for agent subsystem
    // Extracted from unlinked_symbols_batch_018.cpp / link_stubs_production.cpp

It names the files it was extracted FROM. Both exist in this tree, and both
carry a fuller AgentOllamaClient and InferenceResult:

    src/core/unlinked_symbols_batch_018.cpp:47,68   InferenceResult + AgentOllamaClient
    src/core/link_stubs_production.cpp:271,273      InferenceResult{...response...} + client

So the extraction was LOSSY, not the consumer fictional. The richer definition
was in the repository the whole time; the search looked for a class name and did
not follow the header's own provenance note. A symbol search answers "does this
name exist", not "was this thing derived from something that does".

--------------------------------------------------------------------------------
11. FILES ADDED IN PART 2 (1)
--------------------------------------------------------------------------------
  NEW  src/agentic/SovereignInferenceClient.h
       Missing: gold_link_closure.cpp:878 C1083. Derives SovereignModelConfig
       from core/sovereign_gguf_loader.h (used by value, so it needs the
       complete type) and ChatMessage/InferenceResult from AgentOllamaClient.h.
       The four streaming callback typedefs are flagged in the header as having
       NO use site: gold_link_closure.cpp discards on_token / on_tool_call /
       on_done with (void) and calls only on_error. Their shapes are taken from
       the pinned ChatStream/FIMStream callbacks in unlinked_symbols_batch_018.

--------------------------------------------------------------------------------
12. LOST API RESTORED (src/agentic/AgentOllamaClient.{h,cpp})
--------------------------------------------------------------------------------
  InferenceResult.response      added. Invariant documented and enforced by
                                every producer: response == content on success,
                                both empty on failure. Not a reference member --
                                that would make the type non-assignable, and the
                                tree assigns it by value everywhere.
  OllamaConfig.chat_model       added. Empty means fall back to defaultModel.
  OllamaConfig.fim_model        added. Same.
  ChatSync(messages)            1-arg overload added; forwards with an empty
                                options object to the original 2-arg form.
  FIMSync(prefix, suffix,       added. requestId defaulted to "" so the
           requestId = "")     three-arg form that existed pre-extraction also
                                compiles. Real POST /api/generate with prompt
                                and suffix, parsed through the existing HttpCall.
  GetConfig() / SetConfig()     added. Both were required together by a
                                read-modify-write in ssot_handlers_ext.cpp.

  AND ONE CHANGE THAT MAKES THE RESTORATION MEAN SOMETHING: the 2-arg ChatSync
  previously resolved its model as options.value("model", config_.defaultModel).
  With chat_model added but unwired, ssot_handlers_ext.cpp's
  `cfg.chat_model = model; client.SetConfig(cfg);` would have been a write that
  changed nothing -- an accepted-looking call with no effect. Model resolution
  now prefers chat_model over defaultModel.

--------------------------------------------------------------------------------
13. FOUR MORE MISSING DEFINITIONS (src/core/support_tier.cpp)
--------------------------------------------------------------------------------
support_tier.cpp is 340 lines of finished method bodies that CALL
SupportResult::ok / ::error on eleven paths and construct a SupportTierManager
in Instance(), yet defines neither the two factories nor the ctor/dtor. Four
LNK2019s. Added, plus the three callback setters the header declares and nothing
calls (a declared-but-undefined member is a latent link error the moment a
caller appears).

The constructor's placement is not a default-initialise-everything. A
default-constructed SLAConfig leaves `description` null, and
GenerateStatusReport() streams that member directly -- so a client querying the
tier before Initialize() would have streamed a null char*. It seeds from
s_slaConfigs[0] instead, which is the same row Initialize() assigns when the
Enterprise gate fails (line 66). m_nextId starts at 1 so the first ticket is id
1, not 0.

--------------------------------------------------------------------------------
14. TWO MORE DEFECTS IN EXISTING FILES
--------------------------------------------------------------------------------
  include/enterprise/support_tier.h   I declared GetLevelName static; the .cpp
                                     defines it as an ordinary const member
                                     (support_tier.cpp:111). The .cpp is the
                                     authority -- it was there first and never
                                     moved. C2511. Changed the declaration, not
                                     the definition.
  include/PathResolver.h              getPluginsPath restored (ssot calls it at
                                     6800 and 6902). Returns EMPTY when nothing
                                     is configured rather than a guessed default
                                     -- both callers test !pluginDir.empty(), so
                                     empty is a meaningful state. getModelsPath
                                     can fall back because Ollama model
                                     locations are genuinely conventional; a
                                     plugins directory has no such convention.

--------------------------------------------------------------------------------
15. RawrXD_Gold's SOURCE LIST WAS INCOMPLETE -- 32 EXISTING FILES OMITTED
--------------------------------------------------------------------------------
The target's own header at CMakeLists.txt:4322 states its goal: "All MASM
modules linked, ZERO UNRESOLVED EXTERNALS, static CRT". It did not meet that.
After every compile error was repaired, the link reported LNK1120: 195 unresolved
externals -- and every one of them was satisfied by a file that already existed
in the repository and was already compiled by InferenceEngine or
RawrXD-Win32IDE. They were absent from RawrXD_Gold's source list, not absent
from the tree.

Three measured closure rounds, each an APPEND placed after every
list(REMOVE_ITEM) and list(FILTER) and BEFORE rawrxd_filter_missing_sources, so
none can undo the append and a file that later disappears is dropped rather than
becoming a fatal "Cannot find source file":

  ROUND 1  23 files   195 -> 124 unresolved
           compute/BowRainComputeAuthority.cpp (all 14 rawrxd::compute symbols),
           agentic/AgentOllamaClient.cpp, ceo/CEOAgent.cpp, ceo/ProjectState.cpp,
           core/adaptive_pipeline_parallel.cpp, deep2/VramStreamingController.cpp
           (18), deep2/GpuScheduler.cpp, deep2/TensorResidencyCache.cpp,
           deep2/TimeReverseDigest.cpp, deep2/vulkan_compute.cpp,
           deep2/Deep2Engine_GpuMoEMLA.cpp, deep2/Deep2Engine_GpuForward.cpp,
           deep2/Deep2Engine_VulkanRuntime.cpp, deep2/Deep2PredictiveRouter.cpp,
           deep2/Deep2B66RuntimeMeta.cpp, deep2/ReverseLayer.cpp,
           deep2/Beaconism.cpp, deep2/deep2_cpu_mla.cpp,
           deep2/expert_cache/ExpertCache.cpp,
           deep2/expert_cache/VulkanExpertTransport.cpp,
           deep2/streaming/ContinuousExecution.cpp, win32app/IDELogger.cpp

           ceo/CEOAgent.cpp and ceo/ProjectState.cpp are a second class of
           omission: they are not referenced anywhere in CMakeLists.txt at all,
           so no target compiled them and the build-graph census could not
           report them -- it only sees what CMakeLists.txt declares.

  ROUND 2   7 files   124 -> 108 unresolved
           Adding CEOAgent.cpp for the first time revealed its own dependencies.
           Ordinary transitive closure: agentic/AgentToolRegistry.cpp,
           agentic/GitSafetyAuthority.cpp, ceo/AutonomousBuildLoop.cpp,
           ceo/ContextEngine.cpp, ceo/ModelRouter.cpp,
           deep2/expert_cache/HostStagingRing.cpp, deep2/streaming/EventLedger.cpp

  ROUND 3   1 file    108 -> 107 unresolved, and removed a duplicate
           deep2 quant kernels: core/kquant_dequantize_q4k.cpp.
           core/kquant_nonmsvc.cpp was added FIRST and produced
             kquant_dequantize_q4k.obj : error LNK2005: KQuant_DequantizeQ4_K
                                         already defined in kquant_nonmsvc.obj
           Both files define KQuant_DequantizeQ4_K. Measured to choose between
           them rather than guess: kquant_dequantize_q4k.cpp is 13,104 bytes with
           50 MSVC intrinsics; kquant_nonmsvc.cpp is 4,431 bytes with ZERO. This
           is an MSVC build, so the intrinsic one is correct and the portable
           fallback must not be linked. Backing it out traded 102-plus-a-duplicate
           for 107 clean, because a duplicate symbol cannot be resolved by adding
           anything while a missing one can. Nothing in the tree prevents a future
           edit from appending both and reintroducing the collision.

  CMakeLists.txt.pre_gold_sources.bak
    SHA256 280A0390E69EB867149FB574F1A02590A30A7DCF8BDC925A90E08951689677FA
    verified byte-identical to the file before the first append.

--------------------------------------------------------------------------------
16. RawrXD_Gold STATE, MEASURED
--------------------------------------------------------------------------------
  compile errors        95  ->  0        (7 headers authored, 9 defects repaired)
  unresolved externals  208 ->  107       (32 existing files added to the target)
  duplicate symbols       1  ->  0        (kquant provider conflict resolved)
  configure exit          -  ->  0
  RAWRXD_DROPPED_SOURCE_TOTAL 0
  RAWRXD_SOURCE_CLOSURE  COMPLETE   "no referenced source file is missing"
  configure VERDICT      PASS

  The configure-time source-closure gate now passes. It did not at any point
  before this work.

  STILL FAILING: fatal error LNK1120: 107 unresolved externals. The tail is now
  107 symbols of one or two occurrences each -- Deep2 dual-GPU row/column split
  kernels (Deep2RunDualGpuRowSplit, ...Batch4, ...BatchGroupQ4K, ...BatchTop1,
  DualStickAcquire, DualStickResolve, Deep2BuildGpuWeightView),
  rawrxd::agentic::IsGitSafetyBound and CommandExecutor::Run,
  rawrxd::ckpt::sha256Hex, and the globals g_800B_Unlocked and
  g_strictGpuViolations. Each needs individual locating. This is long-tail link
  closure work, not authoring, and it stopped being a single decision here.

--------------------------------------------------------------------------------
17. END-TO-END TEST, RE-VERIFIED AFTER THE CMAKE CHANGES
--------------------------------------------------------------------------------
  inference_authority_ladder build           EXIT=0
  CPU route, tinyllama-1.1b-chat Q4_K_M, 12 tokens
    G1 MODEL_LOAD / G2 TOKENIZATION / G3 FORWARD_EXECUTION /
    G4 NUMERICAL_CORRECTNESS / G5 SAMPLING_CORRECTNESS /
    G6 TOKEN_STREAMING / G7 IDE_DELIVERY / G8 PERFORMANCE      all PASS
    G9 CROSS_ROUTE_PARITY                                    FAIL by design
    ROUTE=CPU GATES_FAILED=1 GPU_FALLBACK=0
    emitted_greedy_tokens lines = 1
  No regression from the 32 added files or the CMake edits.

--------------------------------------------------------------------------------
18. CORRECTED TOTALS
--------------------------------------------------------------------------------
  MISSING_FILES_FOUND                       7  (part 1)
  MISSING_FILES_FOUND                       1  (part 2)          = 8
  MISSING_FILES_AUTHORED                    8
  LOST_API_RESTORED                         9 members across AgentOllamaClient
  MISSING_DEFINITIONS_ADDED                 4  (+3 latent setters)
  EXISTING_DEFECTS_REPAIRED                13 files
  EXISTING_FILES_ADDED_TO_GOLD_SOURCE_LIST 32
  RAWRXD_GOLD_COMPILE_ERRORS               95 -> 0
  RAWRXD_GOLD_UNRESOLVED_EXTERNALS        208 -> 107
  CONFIGURE_VERDICT                    FAIL_DROPPED_SOURCE -> PASS
  E2E_CPU_GATES_PASS                       7 of 8 substantive, unchanged
  E2E_VULKAN_TOKENS                        0, unchanged (plan_active=0)

  VERDICT = PARTIAL

  Unchanged from part 1 and not improved by anything in part 2: the Vulkan route
  produces no tokens because no weight-residency plan is active
  (plan_active=0), and the strict authority correctly refuses to label CPU
  execution as a GPU run. Cross-route parity cannot pass while the second route
  is empty, and that is a residency capability gap rather than a missing file.

  Unchanged and still the most urgent item in this receipt: two live source
  files, rawrxd/src/build/BuildIntelligence.cpp and .hpp, are git-ignored by
  .gitignore:44 and have zero tracked copies.

================================================================================
PART 3 — SOURCE DURABILITY CLOSED. Q4_K GUARD ADDED AND FALSIFIED.
          LINK 107 -> 75. A REAL CAUSE FIXED, NOT A QUIETER INSTRUMENT.
================================================================================

--------------------------------------------------------------------------------
19. BuildIntelligence — SOURCE DURABILITY FAILURE, CLOSED
--------------------------------------------------------------------------------
The acceptance block, all measured:

    BUILDINTELLIGENCE_CPP_EXISTS      = 1     15,421 bytes on disk
    BUILDINTELLIGENCE_HPP_EXISTS      = 1      5,175 bytes on disk
    GIT_CHECK_IGNORE_CPP              = NOT_IGNORED
    GIT_CHECK_IGNORE_HPP             = NOT_IGNORED
    GIT_LS_FILES_CPP                  = 1
    GIT_LS_FILES_HPP                 = 1
    CLEAN_CHECKOUT_FILES_PRESENT      = 1
      index blob   rawrxd/src/build/BuildIntelligence.cpp = 9f38135113, 15036 bytes
      index blob   rawrxd/src/build/BuildIntelligence.hpp = 4b6effaa84,  5065 bytes
      worktree blob == index blob, both files, MATCH=True
      git cat-file -t <blob> = blob for both, so the objects are in the store
      and a clean checkout can materialise them.
    RAW_RXD_GOLD_COMPILE              = PASS   0 compile errors

The .gitignore rule was REMOVED, not negated. That follows the policy the file
states for itself at line 24 -- "Git cannot re-include a file whose parent
directory is excluded, so the fix is to stop excluding the directory rather than
to negate files inside it" -- and it is the same remedy already applied to the
B012-B015 source directories at line 37. A negated rule would have left the
directory excluded and the intent unexplained; the reason is now written into
the file at the position the rule occupied.

NO REGRESSION IN THE GENERATED NEIGHBOURS, each re-checked after the change:
    rawrxd/src/deep2/build/authority_test.receipt.txt   still ignored (correct)
    rawrxd/win32ide_strict/build/CMakeCache.txt          still ignored (correct)
    rawrxd/src/remote64/build/aead.obj                  still ignored (correct)

--------------------------------------------------------------------------------
20. IGNORED_REQUIRED_SOURCES = 0, MEASURED REPO-WIDE
--------------------------------------------------------------------------------
5,595 source-shaped files are ignored and untracked repository-wide. Broken down,
because the headline number is meaningless without it:

    4,497   rawrxd copy/            an explicit duplicate tree, .gitignore:172,
                                    24,889 files. Not source of record.
      472   rawrxd/build_*/ and rawrxd/win32ide_strict/   generated CMake trees
       34   .venv/                  third-party Python packages
    ------
    5,003   accounted for, none of it project source of record

    Filtered to real source directories -- ^rawrxd/(src|include|tools|tests|
    certs|examples)/, excluding /build*/ and the duplicate tree:

    IGNORED_REQUIRED_SOURCES = 0

--------------------------------------------------------------------------------
21. A CENSUS THAT WAS WRONG TWICE, RECORDED BECAUSE IT CHANGED THE PRIORITY
--------------------------------------------------------------------------------
Part 1 and part 2 both reported this defect as exactly 2 files. Correct.

During part 3 the same census was re-run with
`Get-ChildItem -Recurse -File -Include *.cpp,*.h,*.hpp,*.c` and reported:

    IGNORED_REQUIRED_SOURCES = 308
    rawrxd/src/remote64/build            64 files ignored
    rawrxd/win32ide_strict/build        235 files ignored
    rawrxd/src/masm/build                7 files ignored

That would have made source durability a 308-file crisis and would have required
un-ignoring three generated build trees.

It was wrong. `-Include` is silently ignored when the path is given with
`-LiteralPath`; the enumeration returned .obj, .exe, .vcxproj and CMakeCache.txt
files. Re-run with a per-extension `-Filter` over a wildcard path:

    rawrxd/src/build                   REAL_SRC=2    IGNORED=2   TRACKED=0
    rawrxd/src/masm/build             REAL_SRC=0    IGNORED=0   TRACKED=0
    rawrxd/src/remote64/build         REAL_SRC=0    IGNORED=0   TRACKED=0
    rawrxd/win32ide_strict/build       REAL_SRC=1    IGNORED=1   TRACKED=0
                                      (CMakeCXXCompilerId.cpp, CMake-generated)
    rawrxd/src/sovereign/build        REAL_SRC=1    IGNORED=0   TRACKED=1
    rawrxd/B012..B015/build           REAL_SRC=9    IGNORED=0   TRACKED=9

Only src/build was ever a defect. This is the third instrument defect of this
kind in this session, after the digit-truncating sqlite census (part 1, section
8) and the namespace-qualified definition search (part 2, section 16). All three
produced a confident, specific, wrong count, and all three were caught only by
re-deriving the answer by a different method. An over-counting census is the
mirror of the under-counting census the ledger warns about and is just as
dangerous: it would have pointed three of the highest-value fixes at files that
need nothing.

--------------------------------------------------------------------------------
22. Q4_K MUTUAL-EXCLUSION GUARD — AND A GATE THAT COULD NOT FAIL
--------------------------------------------------------------------------------
    Q4K_IMPL_SELECTED         = src/core/kquant_dequantize_q4k.cpp
    Q4K_ALT_IMPL              = src/core/kquant_nonmsvc.cpp
    SIMULTANEOUS_LINK_ALLOWED = 0

Implemented as a configure-time check over every target in the directory, placed
at the end of CMakeLists.txt so it sees targets added later, naming both the
offending targets and the remedy in a FATAL_ERROR.

THE FIRST VERSION OF THIS GUARD COULD NOT FAIL. It compared each target's source
entry against an absolute path, but add_executable stores entries in the form
they were written -- `src/core/kquant_dequantize_q4k.cpp`, relative to
CMAKE_CURRENT_SOURCE_DIR -- so nothing ever matched. With BOTH files deliberately
present in GOLD_UNDERSCORE_SOURCES it printed:

    [RAWRXD_Q4K_MUTUAL_EXCLUSION_001] OK ... violations=0 ... SIMULTANEOUS_LINK_ALLOWED=0

A PASS, in exactly the situation the gate exists to reject. The positive case had
already been observed passing, so the happy path could not distinguish "works"
from "prints OK". Only deliberately breaking it could.

Fixed by resolving each entry with get_filename_component(... ABSOLUTE
BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}) before comparing. Re-falsified:

    both files present   ->  CFG_EXIT=1
                             "target(s) [RawrXD_Gold] list BOTH ..."
    violation removed    ->  CFG_EXIT=0, violations=0, 165 targets scanned

--------------------------------------------------------------------------------
23. THE STACK OVERFLOW -- CAUSE FIXED, SYMPTOM NOT MASKED
--------------------------------------------------------------------------------
Adding a 4th batch of 7 files to GOLD_UNDERSCORE_SOURCES made configure fail
reproducibly:

    cmake -S rawrxd -B build   ->   exit 0xC00000FD   STACK_OVERFLOW
    same configure with those 7 removed          ->   exit 0

None of the 7 is large -- the largest is runtime_symbol_bridge.cpp at 65,074
bytes, and two files already in the target are far bigger (ssot_handlers_ext.cpp
1,007,337; sqlite3.c 9,455,951). So the trigger was not the size of any input.

This is the class of defect RAWRXD_CMAKE_INCREMENTAL_CONFIG_001 in this
repository's own ledger records as fixed, with `file(READ ... LIMIT 65536)`
applied at this exact call site. The LIMIT is present and the crash still
returned. The LIMIT was never the cause.

The cause is at the next line:

    string(REGEX REPLACE "/\\*([^*]|\\*[^/])*\\*/" " " _stub_body "${_stub_body}")

`([^*]|\*[^/])*` is a nested-quantifier alternation -- the catastrophic
backtracking shape. CMake's regex engine evaluates it recursively, so both cost
and STACK DEPTH scale with the input, and the enclosing while loop re-runs the
region up to 64 times per file. A LIMIT bounds the bytes read; it does not bound
the recursion performed on those bytes. The earlier fix reduced the symptom and
left the cause.

FIRST ATTEMPT, REJECTED BY ITS OWN FALSIFICATION. The read was reduced to 4096
bytes and configure went green with the 7 files present. The gate's output then
changed materially:

    metric                                   65536    4096
    declared-unimplemented loaded               308     308
    RAWR_ENGINE_SOURCES                   55 decl     1 unlisted
    GOLD_UNDERSCORE_SOURCES                50 decl     1 unlisted
    INFERENCE_ENGINE_LIBRARY_SOURCES       22 decl    22 decl
    WIN32IDE_SOURCES                       5 unlisted  6 unlisted

A green configure obtained by reading less is a quieter instrument, not a fix.
The 4096 change was reverted and the criterion recorded in the source comment
before it was tried, so that a later reader could not accept the green build as
evidence.

WHAT WAS DONE INSTEAD. The regex was replaced with the standard unrolled-loop
form of the same language -- `/\\*[^*]*\\*+([^/*][^*]*\\*+)*/` -- which matches
the same set with no ambiguity for the engine to backtrack through. The read
stays at 65536.

    metric                                   before        after
    declared-unimplemented loaded               308          308
    RAWR_ENGINE_SOURCES                   55 decl      55 decl
    GOLD_UNDERSCORE_SOURCES                50 decl      50 decl
    INFERENCE_ENGINE_LIBRARY_SOURCES       22 decl      22 decl
    WIN32IDE_SOURCES                       5 unlisted   5 unlisted
    configure exit                        0             0
    configure with the 7 extra files       CRASH         0

Identical gate output, crash removed, cause addressed rather than input reduced.
The stub gate reads no less of any file than it did before.

--------------------------------------------------------------------------------
24. LINK 107 -> 75, AND TWO FILES THAT WERE WRONG TO ADD
--------------------------------------------------------------------------------
Grouping the 107 remaining symbols by definition file (rather than one at a
time) attributed 13 to inference_link_production.cpp and 2 to
enterprise_devunlink_bridge.cpp. Adding both produced:

    enterprise_devunlock_bridge.obj : error LNK2005: Enterprise_DevUnlock
        already defined in gold_enterprise_devunlock_impl.obj
    inference_link_production.obj : error LNK2005: g_kv_aperture_hits already
        defined in link_symbols_impl.obj
    inference_link_production.obj : error LNK2005: g_kv_pages_flushed already
        defined in link_symbols_impl.obj

Both duplicate symbols that already have a canonical owner inside this target.
They were excluded. That is the same defect this file has already recorded four
times for the unlinked_symbols batches at lines 4337-4349, and the comment at the
list says so in advance: a grep that finds a symbol's name in a file has not
found the file that owns the symbol.

The exclusion is not free, and the cost is recorded rather than hidden:

    with the two files     62 unresolved +  3 duplicate-definition errors
    without them           75 unresolved +  0 duplicate-definition errors

15 symbols are only reachable through files that cannot be linked without
colliding. Neither state links. The duplicate-free state was kept, because
DUPLICATE_IMPL_COLLISIONS=0 is a categorical property -- a duplicate means the
binary is malformed, while a missing symbol means it is incomplete -- and because
a duplicate cannot be resolved by adding anything further.

Two further candidates were rejected on direct measurement rather than on the
grouping:

    src/core/enterprise_camellia_nonmsvc.cpp   #if=0  #endif=1
    src/core/native_speed_kernels_nonmsvc.cpp  #if=0  #endif=1
        error C1020: unexpected #endif at 478 and 271 respectively

They define 19 of the remaining symbols and neither compiles. Closing a
preprocessor imbalance in a file outside this closure is separate work, and
guessing where the missing #if belonged would change which code compiles.

--------------------------------------------------------------------------------
25. STATE AFTER PART 3
--------------------------------------------------------------------------------
    RAWRXD_GOLD_COMPILE_ERRORS                0
    RAWRXD_GOLD_UNRESOLVED_EXTERNALS        107 -> 75
    DUPLICATE_IMPL_COLLISIONS                 0
    CONFIGURE_EXIT                            0
    RAWRXD_DROPPED_SOURCE_TOTAL               0
    RAWRXD_SOURCE_CLOSURE                     COMPLETE
    CONFIGURE_VERDICT                         PASS
    STUB_GATE_COUNTS                          identical to pre-change baseline
    Q4K_GUARD                                 present, and falsified
    IGNORED_REQUIRED_SOURCES                  0
    UNTRACKED_REQUIRED_SOURCES               0
    BUILDINTELLIGENCE_TRACKED                 2 of 2, blobs in object store
    E2E_LADDER_BUILD                          EXIT 0
    E2E_CPU_G1_G8                             PASS
    E2E_REGRESSION                            0

    VERDICT = PARTIAL

    NOT REACHED, and stated rather than implied: RAWRXD_GOLD_LINK_ERRORS=0.
    75 symbols remain. The 19 from the two malformed *_nonmsvc.cpp files are the
    largest single group and need the preprocessor imbalance closed first, which
    is a deliberate exclusion rather than an oversight. VERDICT=PASS_GOLD_SOURCE_
    AND_LINK_CLOSURE is NOT claimed: source durability and compile closure are
    PASS, link closure is not.

    Unchanged and still the binding constraint on G9: the Vulkan route produces
    0 tokens with plan_active=0, and the strict authority correctly refuses to
    label CPU execution as a GPU run.

--------------------------------------------------------------------------------
26. NOT DONE, AND WHY
--------------------------------------------------------------------------------
  75 remaining link symbols. Long-tail, and now the only thing between this
      receipt and a linked RawrXD_Gold.
  The 2 malformed *_nonmsvc.cpp files (19 symbols). Separate repair.
  A clean checkout -> configure -> Gold build -> ladder run. The durability half
      is proven at blob level and IGNORED_REQUIRED_SOURCES=0; a real clone was
      not performed because this tree has other writers and materialising one
      would be disruptive to them.
  The .gitignore change is on disk and the two files are staged, but NOT
      committed. Committing was not requested and this tree has concurrent
      writers.

================================================================================
PART 4 — THE 19-SYMBOL LEAD WAS WRONG. LINK 75 -> 60, DUPLICATES 0.
================================================================================

--------------------------------------------------------------------------------
27. THE TWO non-MSVC TUs: PROVENANCE FOUND, AND IT INVALIDATES THE LEAD
--------------------------------------------------------------------------------
Acceptance as specified, all measured:

    CAMELLIA_NONMSVC_PREPROCESSOR_BALANCED   = 1   cl exit 0, 0 errors
    CAMELLIA_NONMSVC_COMPILE                 = PASS
    NATIVE_SPEED_NONMSVC_PREPROCESSOR_BALANCED = 1  cl exit 0, 0 errors
    NATIVE_SPEED_NONMSVC_COMPILE             = PASS
    GOLD_DUPLICATES                          = 0
    GOLD_UNRESOLVED_BEFORE                   = 75
    GOLD_UNRESOLVED_AFTER                    = 60

The instruction not to assume 75 - 19 = 56 was correct, and the reason is
stronger than "may introduce dependencies of their own".

PROVENANCE, from the files themselves rather than inferred from the error:

    enterprise_camellia_nonmsvc.cpp        15,346 bytes  478 lines  TRACKED
    native_speed_kernels_nonmsvc.cpp         9,233 bytes  271 lines  TRACKED

Both have exactly one conditional directive -- a trailing
`#endif  // !defined(_MSC_VER)` -- and no `#if` anywhere:

    #if count = 0      #endif count = 1

Measured across every revision in reachable history:

    HEAD      #if=0  #endif=1        HEAD~3    #if=0  #endif=1
    HEAD~1    #if=0  #endif=1        HEAD~5    #if=0  #endif=1

So the imbalance was committed that way and is not a regression from a later
edit. That settles the question posed -- was the opening conditional removed, or
is the closing one obsolete? -- from evidence: the trailing comment preserves the
lost pairing and names the condition, so the opening conditional was lost and the
closing directive is not obsolete.

THE REPAIR WAS THEREFORE THE FAITHFUL ONE: `#if !defined(_MSC_VER)` restored
after the includes. Deleting the `#endif` would also have silenced C1020 while
compiling a "non-MSVC fallback" unconditionally into every MSVC build,
contradicting what the filename says the file is for.

CONSEQUENCE, AND IT IS THE ACTUAL FINDING. This is an MSVC build, so _MSC_VER IS
defined and the entire body of both files is excluded. Proven by inspecting the
objects the repaired sources produce, not inferred:

    camellia.obj       1,022 bytes   0 project symbols exported
    nativespeed.obj      980 bytes   0 project symbols exported
    (the single "External" record in each is _Avx2WmemEnabledWeakValue, an
     MSVC CRT-internal data reference injected by the compiler)

So the correct subtraction from the unresolved total is ZERO, not 19. The
earlier attribution of 11 and 8 symbols to these files was a grep reading names
inside a preprocessor-excluded block. Those 19 symbols have no owner here at all
on this toolchain, and adding either file to any target cannot close one of them.

Both files are in NO target and are referenced by CMakeLists.txt only in
non-building positions, so the repair changes no build. Its value is that a
C1020 no longer waits in the tree for the first target that reaches these files,
and that a 19-symbol phantom is no longer carried in any inventory.

    POST-REPAIR IDENTITY (tracked in git, so HEAD is the snapshot)
    enterprise_camellia_nonmsvc.cpp    SHA256 DD9DE3D32724968FC8EB8A4B8DAE438CC47996CB849FCCDC6F4271CD733C7AE0
    native_speed_kernels_nonmsvc.cpp   SHA256 21CDA15D6E6654FB036157FC09EBFDC3E3741492CEA3C5F5A8FE70FB31CC2E8E
    git diff --stat: 2 files changed, 61 insertions(+)  -- comments and one
    #if each; no executable line altered.

--------------------------------------------------------------------------------
28. CENSUS REGENERATED FROM SCRATCH, AND THE METHOD CORRECTED
--------------------------------------------------------------------------------
The 75-symbol inventory was discarded and rebuilt from a fresh link, because a
linker census goes stale the moment a TU is added. The attribution method was
corrected at the same time to reject any candidate whose definition is gated
behind a _MSC_VER guard before offering it as an owner.

Measured grouping of the 75, by owning translation unit:

    37  no reachable definition anywhere in the tree
    13  src/core/inference_link_production.cpp     excluded: 3 duplicate defs
     7  src/core/win32ide_debugger_bridge.cpp      added, no duplicate
     6  src/core/win32ide_link_stubs.cpp            excluded: 69 duplicate defs
     3  src/core/convergence_stress_harness.cpp    excluded: stress harness
     3  src/win32app/main_win32.cpp                excluded: IDE main
     2  src/core/win32ide_quadbuffer_bridge.cpp    added, no duplicate
     2  src/core/kquant_nonmsvc.cpp                blocked by Q4K guard
     1  certs/http_template_format_sweep_001.cpp   excluded: cert driver
     1  src/win32app/Win32IDE_EditorEngine.cpp     excluded: IDE GUI
    16  already satisfied by a TU inside this target, excluded as owners

75 symbols collapse to 9 candidate TUs, and only 2 of the 9 are safe to add.
That is the ratio the instruction was aiming at: the work is in owning TUs, not
in symbol names.

win32ide_link_stubs.cpp is the clearest single result of the round. Its name was
treated as a duplicate-risk signal rather than a finding, the batch was run as a
measurement, and the measurement returned 69 duplicate definitions, every one of
the form

    win32ide_link_stubs.obj : error LNK2005: asm_camellia256_* already defined
                                in runtime_symbol_bridge.obj

It is a wholesale second copy of symbols runtime_symbol_bridge.cpp already owns
inside this target. Excluded. Had the name been trusted instead of tested, 69
overlapping definitions would have entered the target.

--------------------------------------------------------------------------------
29. STATE AFTER PART 4
--------------------------------------------------------------------------------
    RAWRXD_GOLD_COMPILE_ERRORS                0
    RAWRXD_GOLD_UNRESOLVED_EXTERNALS      107 -> 75 -> 60
    DUPLICATE_IMPL_COLLISIONS                 0
    CONFIGURE_EXIT                            0
    RAWRXD_DROPPED_SOURCE_TOTAL               0
    RAWRXD_SOURCE_CLOSURE                     COMPLETE
    STUB_GATE_COUNTS                          308 / 55 / 50 / 22 / 5 -- IDENTICAL
                                              to the pre-PART-3 baseline
    Q4K_GUARD                                 violations=0 over 165 targets,
                                              falsified
    IGNORED_REQUIRED_SOURCES                  0
    BUILDINTELLIGENCE_TRACKED                 2 of 2, blobs in object store
    NONMSVC_TUS_COMPILE                      2 of 2, zero symbols exported
    E2E_LADDER_BUILD                          EXIT 0
    E2E_CPU_G1_G8                             PASS
    E2E_REGRESSION                            0

    UNRESOLVED_REDUCTION_THIS_ENGAGEMENT   208 -> 60, i.e. 148 removed, with
                                            duplicate definitions held at 0
                                            throughout.

    VERDICT = PARTIAL

    LINK_CLOSURE=OPEN. Not claimed: VERDICT=PASS_GOLD_SOURCE_AND_LINK_CLOSURE.
    60 symbols remain. The largest single class is now the 37 with no reachable
    definition anywhere -- those are missing implementations, not wiring, and no
    amount of source-list work will move them.

--------------------------------------------------------------------------------
30. WHAT THE REMAINING 60 ARE, AND WHAT THEY ARE NOT
--------------------------------------------------------------------------------
    37  no reachable definition anywhere. Genuinely absent code.
    13  inference_link_production.cpp      -- 3 symbols duplicate symbols that
                                              link_symbols_impl.cpp already owns.
                                              Adding the file trades 3 duplicates
                                              for 13 definitions; measured both
                                              ways and kept the duplicate-free
                                              state.
     6  win32ide_link_stubs.cpp             -- 69 duplicate definitions. Rejected.
     4  IDE GUI / cert drivers / stress harness / Q4_K alternate -- excluded by
        category, each with the reason recorded at the list in CMakeLists.txt.

The honest shape of the remaining work: of 60 symbols, 37 need code that does
not exist, 13 need a decision about which of two competing implementations owns
three symbols, and the rest are category exclusions. Only the first group is
open-ended implementation work, and it should be attacked as 37 symbols mapped
to however many TUs own them, using the same census as this round.

--------------------------------------------------------------------------------
31. STANDING RECOMMENDATION, RECORDED BECAUSE IT IS NOW PAID FOR TWICE
--------------------------------------------------------------------------------
Four instrument defects this engagement, all producing confident specific wrong
numbers, all caught only by re-deriving the answer by a different method:

  1  PowerShell -Include silently ignored under -LiteralPath; reported 308
     ignored source files where the true count was 2.
  2  A symbol census matching \bsqlite3_[A-Za-z_]+\b truncated three SQLite
     identifiers at their first digit.
  3  A definition search using fully-qualified names missed definitions written
     unqualified inside their own namespace.
  4  A linker grouping that counted symbols textually present inside a
     preprocessor-excluded block, inventing a 19-symbol owner that exports
     nothing.

Defect 4 is the most expensive form, and the rule that catches it is the one the
Q4_K guard already demonstrates:

    A CANDIDATE OWNER MUST BE PROVEN TO EXPORT THE SYMBOL ON THIS TOOLCHAIN.
    Textual presence is not ownership.

    For gates that report on the tree rather than on themselves, the standard this
    engagement applied and should be kept is POSITIVE_CONTROL + NEGATIVE_CONTROL +
    FALSIFICATION_TEST, with the additional requirement that any change which makes a
    gate green must be shown not to have changed the gate's own measurements. The
    stub-gate stack overflow is the worked example: reading less produced a green
    configure and altered the counts, and was rejected in favour of fixing the regex
    at the original read.

================================================================================
PART 5 — LINK 60 -> 47. OWNERSHIP COLLISION RESOLVED. OWNER_PROOF_001 BUILT,
          AND ITS OWN STAGE 3/4 DISQUALIFIED BY ITS OWN POSITIVE CONTROL.
================================================================================

--------------------------------------------------------------------------------
32. THE COLLISION RESOLVED BY PROVENANCE, NOT BY EXCLUSION
--------------------------------------------------------------------------------
    INFERENCE_LINK_UNIQUE_SYMBOLS           = 13
    INFERENCE_LINK_COLLISIONS                3   -> 0
    UNIQUE_DEFINITIONS_RETAINED             = 13
    DUPLICATE_DEFINITIONS                    0
    GOLD_UNRESOLVED_BEFORE                  = 60
    GOLD_UNRESOLVED_AFTER                   = 47

Both sides of each collision are extern "C", so neither type nor signature
participates in the symbol name and the linker cannot arbitrate. That is what made
these a decision rather than a lookup.

THE TWO g_kv_* COLLISIONS -- resolved:

    inference_link_production.cpp:27,28   int     g_kv_aperture_hits, g_kv_pages_flushed
    link_symbols_impl.cpp:212,214         uint64_t (same two names)

  - link_symbols_impl.cpp is the INCUMBENT. Its pair sits under a
    `// Global Symbols [STUB: ZERO-INITIALIZED]` banner and each variable is
    annotated `// STUB: ... (always 0)`.
  - The two sides disagree on type, and a THIRD definition exists as
    `std::atomic<uint64_t>` at gold_link_closure_v2.cpp:366-367. Three types for
    one name is not a duplicate with a winner; it is a name nobody agreed on.
  - No header anywhere declares either name, and no code reads or writes either.
    Measured against the live link: 0 occurrences of "g_kv_" in _gold_build27.txt.

So there is no contract to preserve, the incumbent owns the names, and the
redundant pair was DELETED from inference_link_production.cpp. Its other 13
definitions are referenced and are unaffected, so the file was then added.

Deleting the definitions rather than the file is what recovered the 13. Excluding
the whole file -- which is what happened in PART 4 -- cost those 13 as well.

THE Enterprise_DevUnlock COLLISION -- recorded, deliberately NOT flipped:

    src/core/enterprise_devunlock_bridge.cpp:105
        "Enterprise_DevUnlock -- Always compiled, regardless of RAWR_HAS_MASM"
                                                                    <- PRIMARY
    src/core/gold_enterprise_devunlock_impl.cpp:1
        "Satisfies enterprise_feature_manager / license.h when RawrXD_Gold does
         not link MASM enterprise objects that define Enterprise_DevUnlock"
                                                                 <- FALLBACK

The PRIMARY is the file that is NOT in the target; the FALLBACK is the one that
is. Adding the primary duplicates; dropping the fallback changes what RawrXD_Gold
does, from "returns 0" to a real unlock path. That is a behavioural decision, not
a wiring one, and it is not made here.

--------------------------------------------------------------------------------
33. ONE ADD WITHHELD ON AN EXTERNAL EDIT, THEN RE-ATTEMPTED ON EVIDENCE
--------------------------------------------------------------------------------
The first attempt to add the collision-resolved TU produced

    src\deep2\Deep2Engine.h(921,63): error C2065: 'routeReceipt_': undeclared identifier

in a header that had compiled cleanly in the immediately preceding build.
Deep2Engine.h had been modified 9 seconds before that read and its in-flight state
carried two defects of its own: routeReceipt_ used at line 921 with its first
declaration 700 lines later at 1637, and routeReceipt_{} declared TWICE at 1637
and 1660.

Per RAWRXD_SOURCE_INTEGRITY the state is recorded, not attributed and not edited.
Touching it would collide with an active edit, and "fixing" a duplicate member
declaration in a header someone is currently rewriting is how two writers produce
one file that satisfies neither.

The append was commented out with an explicit re-attempt condition, the measured
fallback state recorded (COMPILE_ERRORS=0, DUPLICATES=0, UNRESOLVED=60), and the
condition then re-tested rather than assumed:

    routeReceipt_ declarations in Deep2Engine.h    2 -> 1
    Deep2Engine.h(921) C2065                      present -> absent

Condition met, append restored, and the measurement is the one above. Had the
condition been assumed instead of tested, the +13 would have been reported on top
of another writer's half-finished header.

--------------------------------------------------------------------------------
34. OWNER_PROOF_001 -- rawrxd/tools/owner_proof_001.ps1
--------------------------------------------------------------------------------
Four stages, and only the last one makes an owner:

    1  TEXTUAL_CANDIDATE    a file mentions the symbol name
    2  ACTIVE_ON_TOOLCHAIN  the mention is not inside a preprocessor region this
                            compiler excludes
    3  OBJECT_COMPILES      the file compiles on the active toolchain
    4  OBJECT_EXPORTS       the compiled object actually exports the symbol

Per-symbol record, per the specified schema:

    SYMBOL, CANDIDATE_TU, TEXTUAL_DEFINITION, ACTIVE_ON_TOOLCHAIN,
    OBJECT_COMPILES, OBJECT_EXPORTS_SYMBOL, OWNER_VERDICT, REJECTION_REASON

    OWNER_VERDICT in {PROVEN, PROVISIONAL, REJECTED, UNPROVEN_PROBE_UNRELIABLE}

Target summary:

    UNRESOLVED_TOTAL, TEXTUAL_CANDIDATES, PREPROCESSOR_REJECTED, COMPILE_REJECTED,
    NONEXPORTING_OBJECTS, ALREADY_IN_TARGET_REJECTED, KNOWN_NON_OWNER_REJECTED,
    NO_TEXTUAL_CANDIDATE, STAGE4_NOT_RUN, PROVEN_OWNER_TUS,
    UNPROVEN_PROBE_UNRELIABLE, PROVISIONAL_OWNER_TUS, MULTI_OWNER_COUNT,
    ZERO_OWNER_COUNT, SINGLE_OWNER_COUNT, MULTI_OWNER_COUNT_DUPLICATES

Gold closure is then literally ZERO_OWNER_COUNT=0 and MULTI_OWNER_COUNT=0.

A machine-readable non-owner list ships in the script so future closure does not
re-derive a judgement already made once: STUB_ZEROS_INCUMBENT,
DUPLICATE_PROVIDER_69, DUPLICATE_PROVIDER_3, STRESS_HARNESS_NOT_LIBRARY,
CERT_DRIVER_NOT_LIBRARY, IDE_MAIN_ENTRYPOINT, IDE_GUI_IMPLEMENTATION,
Q4K_ALTERNATE_BLOCKED_BY_GUARD.

Exit codes: 0 census produced with MULTI_OWNER_COUNT=0; 3 multi-owner present;
4 stage 3/4 rejected something; 5 bad input.

--------------------------------------------------------------------------------
35. FIVE DEFECTS FOUND IN OWNER_PROOF_001 WHILE BUILDING IT
--------------------------------------------------------------------------------
Recorded because the tool is the permanent artifact and its credibility is the
whole point. Each was found by running it, not by reading it.

  1  SYMBOL EXTRACTION MISSED A THIRD OF THE LINK LOG. The pattern required
     "referenced in function", which LNK2001 lines and every undecorated global
     variable do not carry. NO_TEXTUAL_CANDIDATE was 22 when the true figure was
     0. The same block also unwrapped quoted demangled forms with a regex
     anchored at ^" that fails mid-token, leaving a trailing quote on the needle.

  2  ALREADY_IN_TARGET NEVER MATCHED. Candidate paths are repo-relative; the
     vcxproj stores absolute. The guard's key never matched, so nine symbols
     "owned" by deep2_openai_server.cpp -- which IS in the target -- were offered
     as candidates. A guard whose key never matches is worse than no guard.

  3  THE REJECTION HISTOGRAM WAS INCOMPLETE. The summary counted only
     OBJECT_DOES_NOT_EXPORT_SYMBOL, so 22 OBJECT_DOES_NOT_COMPILE rejections were
     produced, correctly, and then reported nowhere: COMPILE_REJECTED=0 while 22
     candidates had failed to compile. Every reason is now tallied.

  4  STAGE 3 REPORTED DEFECTS THAT DID NOT EXIST. The probe compiled candidates
     with a hand-built include set and no preprocessor definitions, and reported
     OBJECT_DOES_NOT_COMPILE for 41 of 47 symbols -- including
     src/deep2/deep2_openai_server.cpp, which compiles with ZERO errors when
     built by hand using the target's own AdditionalIncludeDirectories,
     PreprocessorDefinitions and AdditionalOptions. A stage that decides "not an
     owner" by failing to compile is only making that claim if the probe can
     compile things that do compile. The target's flags are now extracted from
     the vcxproj.

  5  NULL METHOD CALL INSIDE THE TOOL. `echo %ERRORLEVEL%>` in a generated batch
     left a zero-byte stamp, Get-Content -Raw returns $null for a zero-byte file,
     and .Trim() on that $null is exactly the "method on a null-valued
     expression" class this tool exists to catch -- present in the tool. Fixed on
     both sides: the batch writes via `if errorlevel 1`, and the read tolerates
     $null.

--------------------------------------------------------------------------------
36. THE POSITIVE CONTROL, AND WHAT IT SETTLED
--------------------------------------------------------------------------------
Because of defect 4, stage 3/4 now runs a positive control before it is allowed to
reject anything: it compiles a file that is demonstrably in the target and
demonstrably builds there. If the control fails, stages 3 and 4 are marked
UNRELIABLE and are not permitted to reject a single candidate.

    STAGE3_4_POSITIVE_CONTROL   = False
    STAGE3_4_CONTROL_DETAIL     = CONTROL_FAILED_TO_COMPILE=fp16_census.cpp

The control FAILS. So the honest output of this run is:

    UNRESOLVED_TOTAL                 = 47
    TEXTUAL_CANDIDATES               = 47   (extraction now complete; was 25)
    PREPROCESSOR_REJECTED            = 0
    COMPILE_REJECTED                 = 0    (was 41, all false)
    NONEXPORTING_OBJECTS             = 0
    KNOWN_NON_OWNER_REJECTED         = 6
    PROVEN_OWNER_TUS                 = 0
    UNPROVEN_PROBE_UNRELIABLE        = 41
    MULTI_OWNER_COUNT                = 0
    EXIT                             = 0    (no false failure reported)

THE TOOL IS CORRECT AND THE PROBE IS NOT YET FAITHFUL, and the difference is now
stated in the output instead of being papered over with 41 invented defects. What
this run does establish, from stages 1-2 which do not depend on the probe:

  - All 47 unresolved symbols have at least one textual candidate
    (NO_TEXTUAL_CANDIDATE=0). The PART 4 figure of 22 ownerless-by-text was an
    extraction artifact, not a fact.
  - 6 are excluded by category with machine-readable reasons.
  - MULTI_OWNER_COUNT=0: no symbol has two compiled definitions in the target.
    That half of the closure condition IS satisfied and is measured by the
    linker, not by this tool.
  - STAGE 3/4 remains open work: the probe must reproduce the target's compile
    environment before any owner verdict from it is admissible.

--------------------------------------------------------------------------------
37. STATE AFTER PART 5
--------------------------------------------------------------------------------
    RAWRXD_GOLD_COMPILE_ERRORS                0
    RAWRXD_GOLD_UNRESOLVED_EXTERNALS      208 -> 107 -> 75 -> 60 -> 47
    DUPLICATE_IMPL_COLLISIONS                 0
    MULTI_OWNER_COUNT                        0   (measured by the linker)
    CONFIGURE_EXIT                            0
    RAWRXD_DROPPED_SOURCE_TOTAL               0
    RAWRXD_SOURCE_CLOSURE                     COMPLETE
    STUB_GATE_COUNTS                          308 / 55 / 50 / 22 / 5 -- IDENTICAL
    Q4K_GUARD                                 violations=0, falsified
    IGNORED_REQUIRED_SOURCES                  0
    BUILDINTELLIGENCE_TRACKED                 2 of 2
    NONMSVC_TUS_COMPILE                      2 of 2, zero symbols exported
    OWNER_PROOF_001                           built; stages 1-2 sound
    OWNER_PROOF_001_STAGE3_4                  OPEN -- positive control fails
    E2E_CPU_G1_G8                             PASS
    E2E_REGRESSION                            0

    UNRESOLVED_CLOSED_THIS_ENGAGEMENT = 161 of 208, duplicates held at 0 throughout.

    VERDICT = PARTIAL

    LINK_CLOSURE=OPEN. VERDICT=PASS_GOLD_SOURCE_AND_LINK_CLOSURE still not claimed.
    47 symbols remain. What is now established about them, and what is not:
      - NONE has a proven owner. PROVEN_OWNER_TUS=0.
      - 6 are excluded by category with recorded reasons.
      - 41 are UNPROVEN because the probe cannot yet be trusted, NOT because they
        have no owner. It would be exactly the error this engagement has now paid
        for five times to report those 41 as ownerless.

--------------------------------------------------------------------------------
38. NEXT EXECUTABLE ACTION
--------------------------------------------------------------------------------
Make OWNER_PROOF_001 stage 3 faithful, in this order:

  1. Extract the FULL compile environment from RawrXD_Gold.vcxproj, not just the
     first <AdditionalIncludeDirectories> / <PreprocessorDefinitions> /
     <AdditionalOptions> nodes -- MSBuild emits one set per ItemDefinitionGroup per
     configuration, and taking index 0 picks whichever the generator emitted
     first. The control failure is consistent with that.
  2. Re-run. STAGE3_4_POSITIVE_CONTROL must become True before any verdict from
     stage 3 or 4 is admissible. That is the gate's own acceptance condition.
  3. Only then regenerate the 41, and separate the genuinely ownerless from the
     merely unproven.

Then, for what is genuinely ownerless, contract recoverability per symbol:
declaration + callers + comments + older revisions + sibling architecture + tests,
classified CONTRACT_RECOVERABLE=1 or 0. SAFE_SYNTHESIS is not an option and no
symbol will be closed by writing a stub that satisfies the linker.

================================================================================
PART 6 — OWNER_PROOF_ENVIRONMENT_001. THE PROBE IS NOW FAITHFUL, PROVEN BY
          EXECUTION. THE REMAINING DEFECT IS IN CONTROL SELECTION.
================================================================================

--------------------------------------------------------------------------------
39. THE AUTHORITATIVE COMMAND, CAPTURED FROM MSBUILD'S OWN RECORD
--------------------------------------------------------------------------------
Not reconstructed from XML. MSBuild writes the exact argument string it issued to

    build\RawrXD_Gold.dir\Release\RawrXD_Gold.tlog\CL.command.1.tlog

as UTF-16 lines alternating `^<absolute source path>` then the full cl.exe
command. 570 lines. Every entry differs only in the source path and /Fo, so the
first entry is an exact template for the shipping configuration. Captured
template:

    /c /I<28 project dirs> /IC:\VulkanSDK\1.4.357.0\Include /I<3rdparty/quickjs>
       /nologo /W0 /WX- /diagnostics:column /sdl- /O2 /Ob2
       /D _MBCS /D WIN32 /D _WINDOWS /D NDEBUG
       /D RAWRXD_STRICT_PRODUCTION_PROFILE=0 /D RAWRXD_GOLD_BUILD=1
       /D RAWR_AUTO_FEATURE_REGISTRY_PROVIDES_HANDLERS=1
       /D RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=0 /D RAWR_HAS_MASM=1
       /D RAWRXD_LINK_*_ASM=<0|1>  (14 flags)
       /D RAWRXD_OMEGA1_ENABLED=1 /D HAS_BRUTAL_GZIP_MASM=1 /D RAWR_HAS_NANOQUANT=1
       /D RAWR_HAS_VULKAN=1 /D RAWR_ENABLE_VULKAN=1
       /D VULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1
       /D _CRT_SECURE_NO_WARNINGS /D NOMINMAX /D WIN32_LEAN_AND_MEAN
       /D RAWR_INTENT_* /D RAWR_PATCH_* /D RAWR_CAPABILITY_TOKENS_ENABLED=1
       /D RAWR_HOTPATCH_JOURNAL_ENABLED=1 /D RAWR_PATCH_FIREWALL_ENABLED=1
       /D RAWR_REFLECTOR_AGENT_ENABLED=1 /D RAWR_ATOMIC_ACTIVATION_ENABLED=1
       /D RAWR_ROLLBACK_FIRST_CLASS_ENABLED=1 /D RAWR_MODEL_ADAPTER_ENABLED=1
       /D RAWR_INTENT_EMERGENCY_BYPASS=0 /D "CMAKE_INTDIR=\"Release\""
       /EHsc /MT /GS- /arch:AVX512 /std:c++20
       /external:W0 /TP /external:I <6 SDK+webview+vulkan dirs>

WHAT THE PART 5 PROBE WAS MISSING, and why each omission mattered:

    /MT                static CRT. The target is a static-CRT build; the probe
                       used the default /MD.
    /arch:AVX512       target-wide, and selects intrinsics in headers.
    NOMINMAX           together with WIN32_LEAN_AND_MEAN this decides whether
    WIN32_LEAN_AND_MEAN  <windows.h> collides with <algorithm>. Either one
                       missing changes which headers parse.
    RAWRXD_GOLD_BUILD=1  selects which source paths exist at all under Gold.
    RAWR_HAS_VULKAN / RAWR_ENABLE_VULKAN / VULKAN_HPP_DISPATCH_LOADER_DYNAMIC
                       gate the entire Vulkan compilation surface.
    RAWRXD_LINK_*_ASM   14 flags, each 0 or 1, each changing which definitions
                       are emitted from the same source.

So the PART 5 probe was not "nearly right". It differed from the shipping
configuration in the flags that decide whether the code compiles at all, which is
why it rejected 41 of 47 symbols.

--------------------------------------------------------------------------------
40. THE PROBE IS PROVEN FAITHFUL, BY RUNNING IT
--------------------------------------------------------------------------------
CORRECTION, ISSUED IN PART 7. This section originally read:

    "The template was extracted and executed directly against a Gold source:
         template source   F:\~DEV\RAWRXD\SRC\CEO\MAIN.CPP   (from the tlog)
         substituted       /Fo -> temp, /Fd -> temp, source -> certification/...
         result            ZERO errors
     That is the acceptance condition OWNER_PROOF_ENVIRONMENT_001 asked for."

THAT CONCLUSION WAS WRONG, AND IT WAS WRONG IN THE MOST DANGEROUS SHAPE AVAILABLE.

The tlog records the ARGUMENT STRING ONLY. It contains no compiler executable:
the captured command begins with "/c /I..." and there is no cl.exe token anywhere
in it. Both the probe and the manual re-run submitted it as-is, cmd reported

    '/c' is not recognized as an internal or external command

and produced NO COMPILER OUTPUT AND NO OBJECT FILE. The manual run printed zero
error lines, and "zero error lines" and "no output lines" are indistinguishable in
a filtered view. The compiler was never launched.

So PART 6's

    PROBE_ENVIRONMENT_FAITHFUL = PROVEN_BY_EXECUTION
    TEMPLATE_RESULT            = ZERO errors on a Gold source

described a process that did not run. A positive control that passes because the
process it should have launched was never launched is worse than a control that
fails, because it converts a broken instrument into an authoritative PASS. The
PART 5 controls at least failed closed; this one would have opened the gate.

THE TEMPLATE IS NEVERTHELESS FAITHFUL, AND THAT IS NOW PROVEN. With the compiler
executable restored -- vcvars64.bat puts cl.exe on PATH, so the invocation is
"cl " plus the recorded arguments -- the captured template compiles a Gold source
and produces a real object:

    cl <3239 recorded characters from CL.command.1.tlog>
       /Fo -> temp   /Fd -> temp   source -> F:\~DEV\RAWRXD\SRC\CEO\MAIN.CPP

    compiler output: MAIN.CPP
    object produced: c.obj, 860,380 bytes

That is the acceptance condition OWNER_PROOF_ENVIRONMENT_001 asked for, met by
execution rather than by inspection, with the object size as evidence that
something was actually emitted rather than merely attempted.

WHAT THIS DOES AND DOES NOT CHANGE:

    UNCHANGED   the environment capture. The flag set is real, it came from
                MSBuild's own record, and it is exactly what Gold compiles with.
    UNCHANGED   PART 5's 41 rejections remain wrong and remain withdrawn.
    CORRECTED   "proven by execution" was false and is now actually true.
    NEW         one defect class that no control could catch, because the
                compiler was absent: a probe that submits a non-executable
                command line and reports the absence of errors as success.
                Every future stage in this tool must assert that a PROCESS
                produced an ARTEFACT, not merely that no error was printed.

--------------------------------------------------------------------------------
40a. WHAT THE FIX WAS, AND WHY IT WAS MISSED
--------------------------------------------------------------------------------
    $cmdLine = 'cl ' + $cmdTemplate

The compiler path is taken from the vcvars environment rather than hardcoded, so
a different MSVC version does not silently break the probe. The tlog cannot supply
it, because the tlog does not contain it -- that is a property of the artefact,
not a defect in the parser, and the only correct sources are the vcvars
environment or MSBuild itself.


--------------------------------------------------------------------------------
41. WHAT IS STILL BROKEN -- LOCATED PRECISELY, NOT GUESSED
--------------------------------------------------------------------------------
The tool still reports STAGE3_4_POSITIVE_CONTROL=False, and the control detail
has now been observed to name FOUR different files in four runs:

    certification/certification_harness.cpp
    kquant_parity_check.cpp
    kquant_bench.cpp
    fp16_census.cpp
    full_model_inference.cpp

Every one is a BARE FILENAME. RawrXD_Gold.vcxproj mixes absolute ClCompile
entries with bare relative ones, and the tlog-derived membership list inherits
that form. The control selector joins such a key to the repo root, producing a
path that does not exist, and the compiler correctly fails on a missing source.
The tool then reports CONTROL_FAILED_TO_COMPILE for a file it never attempted to
compile.

This is a control-SELECTION path defect, not probe infidelity. The distinction
matters and is the substantive result of this part:

    PART 5:  the probe was wrong and would have reported 41 defects
    PART 6:  the probe is right, and the control cannot yet be pointed at a
             file that exists

NOT DONE, and named so the next pass starts here rather than re-deriving it:
the control selector must take its path from the tlog's `^source` lines
directly, unnormalised, and Test-Path it before use. It must never Join-Path a
key from the comparison set. The three lines to change are the control-selection
loop, and the verification is that STAGE3_4_CONTROL_DETAIL names an absolute path
and STAGE3_4_POSITIVE_CONTROL becomes True.

Until that is done the tool correctly refuses to emit stage 3/4 verdicts, which is
the behaviour that matters: it is reporting UNPROVEN rather than inventing 41
ownerless symbols.

--------------------------------------------------------------------------------
42. FOUR MORE TOOL DEFECTS FOUND BY RUNNING IT AGAINST THE REAL TLOC
--------------------------------------------------------------------------------
  6  UTF-8 BOM. The tlog begins with U+FEFF, so the first line's first character
     is not '^' and every StartsWith('^') test failed on the first entry.
     Template discovery found nothing and the tool exited 5.
  7  /c REGEX. Written as \s/c(\s|$), which requires whitespace before /c.
     MSBuild emits /c as the FIRST token, so the test never matched. Correct
     form is (^|\s)/c(\s|$).
  8  TARGET MEMBERSHIP FROM XML IS UNRELIABLE. RawrXD_Gold.vcxproj contains both
     absolute entries and bare relative ones. Normalising both against the repo
     root leaves the relative ones unresolvable. The tlog's ^source lines are
     the authority for membership instead: they are exactly what MSBuild
     compiled, absolute and existence-verified.
  9  CONTROL DRAWN FROM THE COMPARISON KEY SET. The selector iterated
     $inTarget.Keys -- keys built for path comparison, some unresolvable --
     rather than the verified source list. Observed as four different bogus
     controls across four runs.

Defects 6-9 are all the same shape as the five in PART 5 and the four earlier in
this engagement: an instrument that reported a confident, specific, wrong result
and was caught only by executing it against the real artefact. Nine instrument
defects in total, and every one was found by running, none by reading.

--------------------------------------------------------------------------------
43. STATE AFTER PART 6
--------------------------------------------------------------------------------
    OWNER_PROOF_ENVIRONMENT_001
      AUTHORITY                 MSBuild tlog CL.command.1.tlog, not vcxproj XML
      TEMPLATE_CAPTURED         1
      TEMPLATE_EXECUTED         1
      TEMPLATE_RESULT           ZERO errors on a Gold source
      PROBE_FAITHFUL            PROVEN_BY_EXECUTION
      OMITTED_BEFORE            /MT /arch:AVX512 NOMINMAX WIN32_LEAN_AND_MEAN
                               RAWRXD_GOLD_BUILD=1 RAWR_HAS_VULKAN
                               VULKAN_HPP_DISPATCH_LOADER_DYNAMIC + 14
                               RAWRXD_LINK_*_ASM flags

    OWNER_PROOF_001
      STAGE3_4_POSITIVE_CONTROL  False   (control SELECTION defect, sec. 41)
      COMPILE_REJECTED           0
      PROVEN_OWNER_TUS           0
      UNPROVEN_PROBE_UNRELIABLE  41
      MULTI_OWNER_COUNT          0
      EXIT                       0       (fails closed)

    UNCHANGED FROM PART 5
      RAWRXD_GOLD_COMPILE_ERRORS           0
      RAWRXD_GOLD_UNRESOLVED_EXTERNALS     47
      DUPLICATE_IMPL_COLLISIONS            0
      CONFIGURE_EXIT                       0
      STUB_GATE_COUNTS                     308 / 55 / 50 / 22 / 5  IDENTICAL
      Q4K_GUARD                            violations=0, falsified
      IGNORED_REQUIRED_SOURCES             0
      E2E_CPU_G1_G8                        PASS
      E2E_REGRESSION                       0

    VERDICT = PARTIAL

    The Gold ledger is unchanged: 47 unresolved, MULTI_OWNER_COUNT=0,
    LINK_CLOSURE=OPEN. This part did not move the linker and does not claim to.

    What it did do is remove the instrument defect that was hiding the answer.
    The ownership question is no longer blocked on "is the probe real" -- it is
    proven real -- and is now blocked only on a control selector that points at a
    path which does not exist.

--------------------------------------------------------------------------------
44. NEXT EXECUTABLE ACTION, PRECISELY
--------------------------------------------------------------------------------
  1. Control selection: take the path from the tlog's ^source lines, unnormalised,
     Test-Path before use, never Join-Path a comparison key. Acceptance:
     STAGE3_4_CONTROL_DETAIL names an ABSOLUTE path AND
     STAGE3_4_POSITIVE_CONTROL=True.
  2. Upgrade to three controls as specified -- a simple TU, an ordinary Gold TU,
     and a Deep2-heavy Gold TU (src/deep2/Deep2Engine.cpp is the natural third) --
     with CONTROL_PASS=3/3 required before any stage 3/4 verdict is admissible.
  3. Then the census becomes admissible and the SAFE_TO_ADD predicate can be
     evaluated over the 41 with real compile and export evidence:
        SAFE_TO_ADD = TEXTUAL_CANDIDATE && ACTIVE_ON_TOOLCHAIN && COMPILE_PASS
                   && OBJECT_EXPORTS_SYMBOL && !ALREADY_IN_TARGET
                   && !DUPLICATE_IF_ADDED && !CATEGORY_EXCLUDED
  4. Add CLASSIFICATION_TOTAL with CLASSIFICATION_DELTA=0 so no symbol can leave
     the accounting.
  5. Enterprise_DevUnlock stays BEHAVIORAL_DECISION and out of automated closure.

================================================================================
PART 7 — CONTROLS UPGRADED TO 3 + STAGE 4 POSITIVE/NEGATIVE + CONSERVATION.
          AND A CORRECTION THAT INVALIDATED PART 6's CENTRAL CLAIM.
================================================================================

--------------------------------------------------------------------------------
45. THREE CONTROLS, ALL ORIGINATING FROM THE GOLD TLOG
--------------------------------------------------------------------------------
Measured on the tlog first, because the control design depends on it:

    ^source entries      285
    ABSOLUTE             285
    RELATIVE               0
    all exist on disk    285

So no working-directory provenance question arises for any control, and no
control may be taken from the vcxproj, which mixes absolute entries with bare
relative ones. Four successive runs named four different bogus controls --
certification_harness.cpp, kquant_parity_check.cpp, kquant_bench.cpp,
full_model_inference.cpp -- every one a bare filename resolved against the repo
root into a path that does not exist, each producing CONTROL_FAILED_TO_COMPILE
for a file the probe had never tried to compile.

Controls are now selected by SHAPE from the tlog source list, so membership is
proven by construction rather than by a file happening to exist:

    CONTROL_SIMPLE      F:\~DEV\RAWRXD\SRC\CEO\MAIN.CPP
                        (smallest Gold source)
    CONTROL_ORDINARY    F:\~DEV\RAWRXD\SRC\RAWRXD_MODEL_LOADER.CPP
                        (mid-sized Gold source)
    CONTROL_DEEP2       F:\~DEV\RAWRXD\SRC\DEEP2\DEEP2ENGINE.CPP
                        (selected FROM THE TLOG, not from the source tree --
                         "it exists in src" is not evidence Gold compiles it)

    CONTROL_SOURCE_ORIGIN=TLOG
    CONTROL_SIMPLE_ACTUALLY_IN_GOLD=1
    CONTROL_ORDINARY_ACTUALLY_IN_GOLD=1
    CONTROL_DEEP2_ACTUALLY_IN_GOLD=1
    CONTROL_TOTAL=3

SOURCE_EXEC_PATH / SOURCE_COMPARE_KEY are now separate fields, per the rule that
ends this class of bug permanently:

    SOURCE_EXEC_PATH     -> Test-Path, cl.exe.  Never reconstructed.
    SOURCE_COMPARE_KEY   -> membership and dedup ONLY. Never fed back into a
                            filesystem operation.

--------------------------------------------------------------------------------
46. STAGE 4 POSITIVE AND NEGATIVE CONTROLS
--------------------------------------------------------------------------------
Three successful compiles prove the compiler probe. They do NOT prove the object
symbol parser. A stage that reports EXPORT_MISS using a parser that matches
everything would pass every compile control and fail every candidate correctly
for the wrong reason.

The positive control is anchored on an object the REAL BUILD produced --
build\RawrXD_Gold.dir\Release\*.obj -- so the symbol is present by construction,
because the linker linked it. It is not a symbol this tool chose, which would
make the control circular and would pass even against a match-everything parser.
The negative control is a sentinel that cannot exist, proving the rejection path.

STAGE4_CONTROL_SOURCE / STAGE4_CONTROL_REQUIRED_SYMBOL /
STAGE4_CONTROL_SYMBOL_FOUND / STAGE4_NEGATIVE_SYMBOL_FOUND are emitted, and both
stage 3 and stage 4 verdicts are gated on all four controls:

    STAGE3_STAGE4_VERDICTS_ADMISSIBLE = (STAGE3_CONTROL_PASS
                                        AND STAGE4_POSITIVE_CONTROL
                                        AND STAGE4_NEGATIVE_CONTROL)

Currently FALSE, so the tool emits no stage 3/4 verdict. The 41 stay
UNPROVEN_PROBE_UNRELIABLE. They are not compile failures, not ownerless symbols,
and not export misses.

--------------------------------------------------------------------------------
47. CONSERVATION, ENFORCED RATHER THAN PRINTED
--------------------------------------------------------------------------------
Nine mutually exclusive classes, summing to UNRESOLVED_TOTAL:

    CLASS_PROVEN_SAFE_TO_ADD / CLASS_ALREADY_IN_TARGET /
    CLASS_CATEGORY_EXCLUDED / CLASS_COMPILE_REJECTED / CLASS_EXPORT_MISS /
    CLASS_DUPLICATE_IF_ADDED / CLASS_BEHAVIORAL_DECISION /
    CLASS_UNPROVEN / CLASS_NO_TEXTUAL_CANDIDATE

    CLASSIFICATION_SUM   printed
    CLASSIFICATION_DELTA = UNRESOLVED_TOTAL - CLASSIFICATION_SUM
    non-zero             ->  exit 6, census declared inadmissible

A symbol that leaves the accounting is worse than one reported wrong, because the
total then looks closed while work remains. This was added as an enforced exit
rather than a printed field because a printed invariant nobody enforces is a
comment.

--------------------------------------------------------------------------------
48. TWO MORE TOOL DEFECTS, BOTH FOUND BY RUNNING
--------------------------------------------------------------------------------
 10  MEMBERSHIP BLOCK ORDERED BEFORE THE DATA IT READS. The block that built
     $inTargetAbs sat ABOVE the assignment of $tlogFound, so its `if ($tlogFound)`
     body never ran, the list stayed empty, and the tool reported
     CONTROL_PASS=0 CONTROL_TOTAL=0. A stage that cannot produce a result printed
     a zero that read as a measurement. The source list is now collected inside
     the tlog parse loop, where the path is known to be valid.
 11  ORDERING OF TEMPLATE ADOPTION. The loop also broke out of the source scan on
     the first usable template, so membership could only ever have seen one entry.
     Membership is now collected for EVERY ^source line and the template is
     adopted independently.

--------------------------------------------------------------------------------
49. THE CORRECTION THAT MATTERS MOST
--------------------------------------------------------------------------------
See section 40. In summary, because it invalidates a claim this receipt previously
made:

    PART 6 asserted  PROBE_ENVIRONMENT_FAITHFUL = PROVEN_BY_EXECUTION
    PART 7 retracts it. The tlog contains NO COMPILER EXECUTABLE -- only the
    argument string, beginning "/c /I...". The probe submitted that as a command,
    cmd reported "'/c' is not recognized", and NOTHING COMPILED. Zero error lines
    were printed because zero lines were printed.

    A control that passes because the process it should have launched never
    launched is the most dangerous instrument defect in this series: it converts
    a broken instrument into an authoritative PASS. PART 5's controls failed
    closed; this one would have opened the gate.

    THE TEMPLATE IS NOW ACTUALLY PROVEN. With "cl " prefixed:
        cl <3239 recorded characters> /Fo temp /Fd temp src\CEO\MAIN.CPP
        compiler output: MAIN.CPP
        object produced: c.obj, 860,380 bytes
    The environment capture was always correct. What was missing was the four
    characters that name the compiler.

    STANDING RULE ADDED: every stage must assert that a PROCESS produced an
    ARTEFACT -- an object with non-zero size -- not merely that no error was
    printed. Absence of diagnostics is not evidence of success.

--------------------------------------------------------------------------------
50. STATE AFTER PART 7
--------------------------------------------------------------------------------
    OWNER_PROOF_ENVIRONMENT_001
      AUTHORITY                MSBuild CL.command.1.tlog
      TEMPLATE_CAPTURED        1
      TEMPLATE_LENGTH          3239 characters
      TEMPLATE_PROVEN_FAITHFUL YES -- object produced, 860,380 bytes
      COMPILER_PREFIX_RESTORED 'cl '   (the tlog contains no executable)
      ENVIRONMENT_FAITHFUL      1

    OWNER_PROOF_001
      CONTROL_SOURCE_ORIGIN     TLOG
      CONTROL_TOTAL             3
      CONTROL_PASS              0   (harness still differs from the working
                                     manual invocation -- not yet isolated)
      STAGE4_POSITIVE_CONTROL   False
      STAGE4_NEGATIVE_CONTROL   False
      STAGE3_STAGE4_VERDICTS_ADMISSIBLE  False
      COMPILE_REJECTED          0
      PROVEN_OWNER_TUS          0
      UNPROVEN_PROBE_UNRELIABLE 41
      MULTI_OWNER_COUNT         0
      EXIT                      0

    UNCHANGED
      RAWRXD_GOLD_COMPILE_ERRORS        0
      RAWRXD_GOLD_UNRESOLVED_EXTERNALS  47
      DUPLICATE_IMPL_COLLISIONS         0
      CONFIGURE_EXIT                    0
      STUB_GATE_COUNTS                  308 / 55 / 50 / 22 / 5  IDENTICAL
      Q4K_GUARD                         violations=0, falsified
      IGNORED_REQUIRED_SOURCES          0
      E2E_CPU_G1_G8                     PASS
      E2E_REGRESSION                    0

    VERDICT = PARTIAL

    The Gold ledger is unchanged at 47 and this part does not claim to move it.
    What changed is the instrument's standing: the environment is genuinely
    proven, the controls are genuinely tlog-sourced, conservation is enforced,
    and the tool still refuses to classify anything it cannot prove.

--------------------------------------------------------------------------------
51. NEXT EXECUTABLE ACTION
--------------------------------------------------------------------------------
  1. Isolate the remaining harness difference. The manual invocation that produced
     an 860,380-byte object and the tool's own invocation of the same template
     differ in batch construction: line endings, the cl.log redirect, and the
     cd /d path form (forward vs backslash slashes). Acceptance:
     CONTROL_PASS=3 CONTROL_TOTAL=3.
  2. Then STAGE4_POSITIVE_CONTROL and STAGE4_NEGATIVE_CONTROL both true, and
     STAGE3_STAGE4_VERDICTS_ADMISSIBLE=1.
  3. Only then classify the 41 with real compile and export evidence and evaluate
     SAFE_TO_ADD. Enterprise_DevUnlock stays BEHAVIORAL_DECISION with
     AUTOMATED_SAFE_TO_ADD=0.