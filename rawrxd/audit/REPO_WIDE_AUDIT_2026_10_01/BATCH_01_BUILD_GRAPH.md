# BATCH 01 — AUTHORITY / BUILD GRAPH AUDIT
# REPO_WIDE_AUDIT_2026_10_01
#
# AUDITED TREE : F:\~dev  (connected working tree, NOT GitHub main)
# HEAD          : 9f67682ffea12a182ae4fd2d41fb3bc524f61d2b
# HEAD SUBJECT  : "P1 item 7: runtime verification PASS, shipping IDE links"
# DIRTY ENTRIES : 185  (working tree is materially newer than HEAD)
# AUDITOR       : fresh repository-wide audit, line 1 -> EOF
# EVIDENCE      : measured from this tree; build logs used only to locate, then
#                 every claim re-verified against on-disk source.

===============================================================================
FINDING B1-001  —  225 IDE SOURCE FILES REFERENCED BY CMAKE DO NOT EXIST
===============================================================================
SEVERITY: P0 — CONTRACT_VIOLATED (build graph lies about product completeness)

MEASURED
--------
  rawrxd/CMakeLists.txt           : 17929 lines
  distinct src/… paths referenced  : 1365
  present on disk                 : 1012
  MISSING on disk                 : 353

  Of those 353 missing, the build system itself reports only 225, all from
  WIN32IDE_SOURCES:
      [rawrxd_filter_missing_sources] WIN32IDE_SOURCES: dropped=225
      RAWRXD_DROPPED_SOURCE_TOTAL=225
  The remaining 128 missing references belong to other targets and are not
  counted by that accumulator.

GROUND TRUTH: THE IDE'S REFERENCED SURFACE IS MOSTLY NON-EXISTENT
---------------------------------------------------------------
  src/win32app/Win32IDE_*.cpp  referenced by CMake : ~200 distinct names
  src/win32app/Win32IDE_*.cpp  ACTUALLY ON DISK      : 43

  43 real files exist.  The CMake list names roughly 200 more that were never
  written.  Every one of the following is a *referenced-but-absent* IDE
  subsystem, e.g.:
      Win32IDE_Refactor.cpp          Win32IDE_Minimap.cpp
      Win32IDE_PeekView.cpp          Win32IDE_OutlinePanel.cpp
      Win32IDE_ProblemsPanel.cpp     Win32IDE_TestExplorerTree.cpp
      Win32IDE_Debugger.cpp          Win32IDE_PowerShellPanel.cpp
      Win32IDE_SemanticIndex.cpp     Win32IDE_SnippetEngine.cpp
      Win32IDE_Themes.cpp            Win32IDE_VSCodeExtAPI.cpp
      Win32IDE_WebView2.cpp          Win32IDE_Minimap / Minimap
      Win32IDE_GameEnginePanel.cpp   Win32IDE_Collision…
      Win32IDE_CursorParity.cpp      Win32IDE_MultiCursor.cpp
      Win32IDE_ProviderKeyStore.cpp  Win32IDE_DiffView.cpp

  src/win32ide/ (lowercase 'i') : 0 files on disk.  Every
  src/win32ide/*.cpp referenced by CMake is absent.

MECHANISM (rawrxd/CMakeLists.txt:201-292)
-----------------------------------------
  function(rawrxd_filter_missing_sources) removes every nonexistent path and
  emits message(WARNING).  A warning does not fail a build.  The IDE therefore
  configures and links green while carrying 225 fewer translation units than
  its own source list claims.

  The build file *documents this exact hazard* at line 190-195:
      "Applied to WIN32IDE_SOURCES it silently discarded ~225 referenced
       src/win32app/*.cpp files that do not exist, and the IDE target then
       configured and linked successfully with far less code than its own
       source list implies -- a green build proved nothing about IDE
       completeness."

  The hazard was identified, counted, and left permissive.  RAWRXD_STRICT_SOURCES
  defaults OFF (line 187-189), so no default build detects it.

CONTROL TEST — DOES THE DETECTOR FIRE?
-------------------------------------
  Detector exists  : YES (RAWRXD_STRICT_SOURCES=ON -> FATAL_ERROR)
  Detector default : OFF
  Detector exercised in any shipping build : NO
  A green IDE link is therefore compatible with any number of absent sources
  from 0 to 225.  The negative control has never been run against a shipping
  target.

CLASSIFICATION: CONTRACT_VIOLATED
  "built" does not imply "the sources the build claims to contain."

===============================================================================
FINDING B1-002  —  10 EMPTY-BODIED TUs ARE WIRED INTO SHIPPING TARGETS
===============================================================================
SEVERITY: P0 — DEAD/UNBOUND (units compiled, contribute nothing)

VERIFIED BY DIRECT READ (bytes=2, i.e. a CRLF pair, no code at all):
    src/inference/NegativeSpaceProfiler.cpp          2 bytes  stripped=0
    src/logging/Logger.cpp                           2 bytes  stripped=0
    src/runtime/TensorExecutionRouter.cpp             2 bytes  stripped=0
    src/runtime/StreamRouterAdapter.cpp               2 bytes  stripped=0
    src/runtime/memory/ResidencyTracker.cpp           2 bytes  stripped=0
    src/runtime/memory/WorkingSetPredictor.cpp        2 bytes  stripped=0
    src/runtime/memory/TensorPlacementManager.cpp     2 bytes  stripped=0
    src/runtime/memory/PredictiveMemoryManager.cpp    2 bytes  stripped=0
    src/runtime/memory/CapacityManager.cpp            2 bytes  stripped=0
    B014/build/b014_profiler.cpp                      2 bytes  stripped=0

  Also verified:
    tests/b009/b009b_batched_gemm.cpp   28 bytes  stripped="intmainreturn0"
                                        i.e. literally `int main(){return 0;}`

TARGETS CARRYING THEM (from configure output):
    RAWR_ENGINE_SOURCES               : 10 empty TUs
    GOLD_UNDERSCORE_SOURCES           : 12 empty TUs
    INFERENCE_ENGINE_LIBRARY_SOURCES  : 11 empty TUs  (incl. the trivial main)
    WIN32IDE_SOURCES                  : 17 empty TUs

  InferenceEngine is the STATIC LIBRARY that rawr-server and the IDE link.

WHY THIS IS NOT COSMETIC
------------------------
  The named subsystems imply capability that does not exist:
    TensorExecutionRouter   — a compute route router
    ResidencyTracker        — memory residency accounting
    WorkingSetPredictor     — working-set prediction
    TensorPlacementManager  — tensor placement policy
    PredictiveMemoryManager — predictive memory
    CapacityManager         — capacity management
    NegativeSpaceProfiler   — profiling
    Logger                  — logging

  An empty TU compiles and links.  If the linker did not demand their symbols,
  the product links with none of these subsystems present, and the build is
  green.

  NOTE: the empty-TU detector is CONTENT-based and correct (it strips all
  non-[A-Za-z0-9_] characters).  This is not a detector defect — it is a
  detector that correctly reports a product defect which was not repaired.

CLASSIFICATION: CONTRACT_VIOLATED / DEAD-UNBOUND

===============================================================================
FINDING B1-003  —  INFERENCE_ENGINE.LIB HAS TWO main() DEFINITIONS
===============================================================================
SEVERITY: P1 — STRUCTURAL

MEASURED (rawrxd/build_ide_audit/b66_build.log):
    kquant_parity_check.obj : warning LNK4006: main already defined in
                              b009b_batched_gemm.obj; second definition ignored

  A STATIC LIBRARY containing main() is a structural error: whichever object
  wins is a link-order accident, not a decision.  Today the warning is
  suppressed-by-precedence and the linker picks one.  A different link order,
  linker, or /WHOLEARCHIVE would surface it.

  Root cause is B1-002's `int main(){return 0;}` TU being wired into
  INFERENCE_ENGINE_LIBRARY_SOURCES.

CLASSIFICATION: CONTRACT_VIOLATED

===============================================================================
FINDING B1-004  —  rawr-server DOES NOT COMPILE AT HEAD+dirty
===============================================================================
SEVERITY: P0 — BLOCKED

MEASURED (rawrxd/build_ide_audit/gate1_server_build3.log):
    src/agentic/GitSafetyAuthorityTools.h(119,7):
        error C3083: 'RawrXD': the symbol to the left of '::' must be a type
    src/agentic/GitSafetyAuthorityTools.h(119,15):
        error C3083: 'Agentic': the symbol to the left of '::' must be a type
    src/agentic/GitSafetyAuthorityTools.h(119,24):
        error C2039: 'AgentToolRegistry': is not a member of 'global namespace'
    src/agentic/GitSafetyAuthorityTools.h(120,5): error C2059: syntax error: 'const'

  GitSafetyAuthorityTools.h uses `RawrXD::Agentic::AgentToolRegistry` without the
  namespace being visible at that point.  rawr-server compiles
  deep2_openai_server.cpp, which reaches that header, and fails.

  CONSEQUENCE FOR ANY PRIOR CLAIM
  ------------------------------
  bin/Release/rawr-server.exe exists, timestamp 2026-10-01 17:32:58.
  A later build attempt (gate1_server_build3.log) FAILED to compile the same
  target.  The binary on disk therefore PREDATES the current source state and
  does not correspond to it.  Any runtime evidence produced through that
  binary is INVALID_MEASUREMENT with respect to the current tree.

  This is precisely the stale-binary failure already recorded in the ledger for
  a different gate ("a build failure from the above was observed to leave a
  stale binary that produced a plausible FAIL describing a build that no longer
  existed").  It has recurred.

CLASSIFICATION: BLOCKED + INVALID_MEASUREMENT for anything run via that binary

===============================================================================
FINDING B1-005  —  IDE LINK FAILED ON 3 UNRESOLVED FileOps SYMBOLS
===============================================================================
SEVERITY: P0 — BUILD GRAPH INCOMPLETE

MEASURED (rawrxd/build_ide_audit/ckpt_ide_build.log):
    Win32IDE_RuntimeCert.obj : error LNK2019: unresolved external symbol
        std::string FileOps_ReadFile(std::string const&)
    Win32IDE_RuntimeCert.obj : error LNK2019: unresolved external symbol
        bool FileOps_WriteFile(std::string const&, std::string const&)
    Win32IDE_RuntimeCert.obj : error LNK2019: unresolved external symbol
        bool FileOps_Exists(std::string const&)
    fatal error LNK1120: 3 unresolved externals

  Win32IDE_RuntimeCert.cpp (which DOES exist on disk) references the FileOps
  family; the defining TU is not linked into RawrXD-Win32IDE.

  bin/Release/RawrXD-Win32IDE.exe exists (21,724,160 bytes, 2026-10-01 18:21:33).
  A build attempt at 17:18-17:19 failed on these three symbols.  The IDE binary
  is NEWER than the failing build (18:21 vs 17:19), so a later successful link
  is plausible — but the sequence must be re-verified from clean before any IDE
  runtime result is admissible.

CORRECTION (from Batch 04, independently traced and verified)
-------------------------------------------------------------
The premise "the defining TU is not linked" is WRONG and is withdrawn.

  Win32IDE_FileOps.cpp:8 defines all seven FileOps symbols INSIDE
  `namespace RawrXD::IDE`.  Win32IDE_RuntimeCert.cpp declared the three it uses
  at GLOBAL scope, so it requested `::FileOps_ReadFile` — a different
  mangled name from the one defined.  This was a namespace-scope bug, not a
  missing source and not a duplicate authority.

  Fixed at Win32IDE_RuntimeCert.cpp:67-74.  Verified present in the 18:21:33
  binary (obj 18:10:18, exe 18:21:33, cert strings extractable).

  This finding is therefore DOWNGRADED: the IDE linked in that configuration.
  It is retained in the record because the log evidence is what misled the
  reading, and because the class of defect — a declaration in a different
  namespace from its definition, producing LNK2019 with no source missing — is
  worth naming.  A build graph can be complete and still fail to link.

CLASSIFICATION: RESOLVED (was BUILD_GRAPH_INCOMPLETE — that classification was
                wrong; the build graph was complete)

-------------------------------------------------------------------------------
FINDING B1-005b  —  THE IDE BINARY IS STALE AGAINST THE TREE
-------------------------------------------------------------------------------
SEVERITY: P0 — INVALID_MEASUREMENT for every runtime claim

  RawrXD-Win32IDE.exe linked        2026-10-01 18:21:33
  src/win32app/main_win32.cpp       2026-10-01 18:40:57   (+19 min AFTER link)
  src/win32app/launch_config.cpp    2026-10-01 18:38:35   (+17 min AFTER link)

  The shipped IDE binary does not correspond to the current source. Per the
  `single_writer.verification_invalidation` constraint, any result produced by
  running that binary describes a build that no longer exists, and must be
  discarded rather than read.

  Consequently EVERY IDE classification in this audit is
  IMPLEMENTED_NOT_RUNTIME_VERIFIED, for this reason and not for lack of effort.

CLASSIFICATION: INVALID_MEASUREMENT

===============================================================================
FINDING B1-006  —  InferenceEngine FAILS TO COMPILE (C2664 x3+)
===============================================================================
SEVERITY: P0 — BLOCKED

MEASURED (rawrxd/build_ide_audit/ckpt_rebuild_verify2.log):
    src/deep2/Deep2Engine_GpuForward.cpp(1125,38): error C2664:
      'VulkanParityGrid::emit(...)': cannot convert argument 5 from
      'Deep2::VulkanCompute::DeviceBuf' to 'const float *'
    src/deep2/Deep2Engine_GpuForward.cpp(1130,38): error C2664: (same)
    src/deep2/Deep2Engine_GpuForward.cpp(1138,34): error C2664: (same)
      declared at Deep2Engine_GpuForward.cpp(468,10)

  VulkanParityGrid::emit is declared taking `const float*` but is being called
  with a device buffer handle.  This is in the GPU forward path.

  NOTE: a later build (b66_build.log, 18:24) DID produce InferenceEngine.lib,
  so this may already be repaired.  Status: needs clean-tree confirmation.

CLASSIFICATION: BUILD_FAIL_AT_THIS_LOG; likely repaired — verify on clean build

===============================================================================
BINARY / TARGET STATE AS FOUND (rawrxd/build_ide_audit)
===============================================================================
  built and present in bin/Release:
      rawr-server.exe                    1,516,032   2026-10-01 17:32:58
      RawrXD-Win32IDE.exe              21,724,160   2026-10-01 18:21:33
      git_safety_authority_cert.exe       752,640   2026-10-01 18:33:48
      mla_forward_chain_cert.exe       1,058,816   2026-10-01 18:33:43
      mla_upload_contract_cert.exe       322,048   2026-10-01 17:59:46
      ckpt_rollback_crash_cert.exe       456,192   2026-10-01 17:27:50

  TARGET CENSUS:
      add_executable / add_library / add_custom_target  : ~450
      add_test                                          : 32
      RAWRXD_DROPPED_SOURCE_TOTAL                       : 225
      empty-bodied TUs wired into shipping source lists  : 10 (+1 trivial main)

  Only 32 ctest entries exist against ~450 targets.  The overwhelming majority
  of the ~400 cert/test executables are registered with NO add_test, so
  `ctest` does not execute them.  Target existence is not test execution.

===============================================================================
FINDING B1-007  —  BOTH SHIPPING CLI TARGETS LIST ABSENT AND STUB SOURCES
===============================================================================
SEVERITY: P0 — CONTRACT_VIOLATED (the shipping products are not what they claim)

This is separate from the 225 IDE drops: it affects the two shipping CLIs.

rawr-server  (rawrxd/CMakeLists.txt:10518), 10 sources:
    EXISTS  9,574 B  src/deep2/deep2_openai_server_main.cpp
    EXISTS 63,312 B  src/deep2/deep2_openai_server.cpp
    MISSING          src/agentic/IdeToolImplementations.cpp
    EXISTS 37,471 B  src/agentic/AgentToolRegistry.cpp
    EXISTS 57,478 B  src/agentic/CheckpointRollbackAuthority.cpp
    EXISTS 49,572 B  src/agentic/GitSafetyAuthority.cpp
    EXISTS 23,017 B  src/agentic/GitSafetyAuthorityTools.cpp
    EXISTS 11,327 B  src/core/ToolRegistry.cpp
    MISSING          src/rawr_agent.cpp
    EXISTS      50 B  src/deep2/deep2_k2_tps_rainbow_cert.cpp   <<< STUB

  -> 2 of 10 sources do not exist.  1 of the remaining 8 is a 50-byte stub.
  -> The dropped `src/rawr_agent.cpp` is named in the target that IS the agent.
     The shipping server contains no agent.

rawr  (rawrxd/CMakeLists.txt:10390), 26 distinct sources:
    All 25 non-stub sources EXIST with real sizes (1,261 B … 58,884 B).
    MISSING          src/agentic/IdeToolImplementations.cpp
    MISSING          src/rawr_agent.cpp
    EXISTS      48 B  src/deep2/deep2_k2_useful_tps_001.cpp      <<< STUB
  -> same two absent files, plus a 48-byte stub.
  -> `deep2_k2_useful_tps_001.cpp` is listed 3 times in this target's source
     list (duplicate registration of one stub).

WHAT THIS MEANS
---------------
  Both shipping CLIs are configured from source lists that include files that
  were never written, plus certification sources that are one-line comments.
  rawrxd_filter_missing_sources silently removes the two absent files, so the
  targets configure and link.  The stub files are KEPT, because they exist.

  Combined with B1-004 (rawr-server does not compile at HEAD+dirty), the
  shipping CLI surface is simultaneously over-claimed and unbuildable.

CLASSIFICATION: CONTRACT_VIOLATED + BLOCKED

===============================================================================
FINDING B1-008  —  RawrXD-Win32IDE TARGET LIST PARSES TO ZERO SOURCES
===============================================================================
SEVERITY: P0 — MEASUREMENT_ARTEFACT, disclosed rather than claimed

A naive per-block regex parse of
    add_executable(RawrXD-Win32IDE WIN32 ${WIN32IDE_SOURCES} ...)
(CMakeLists.txt:7290) yields ZERO literal sources, because the target consumes
the accumulated ${WIN32IDE_SOURCES} variable, not a literal list.  The variable
is assembled across ~90 list(APPEND) / list(FILTER) / list(REMOVE_ITEM)
statements spanning lines 5299-7285.

This audit reports the variable-driven target as INDIRECT, and does NOT claim a
source count for it from the naive parse.  Its 225 dropped files are instead
taken from the build system's own configure-time measurement, which is
reliable for this case because the function is the one that performed the drop.

Recorded because an audit that reported "IDE has 0 sources" would be wrong,
and the failure mode of silently reporting it is the reason it is written down.

CLASSIFICATION: MEASUREMENT_ARTEFACT (disclosed)

===============================================================================
FINDING B1-009  —  CONTROL TEST EXECUTED: THE SHIPPING IDE FAILS THE
                   PROJECT'S OWN STRICT-SOURCE CONFIGURE CONTROL
===============================================================================
SEVERITY: P0 — BLOCKED (the product cannot be configured under its own control)

The audit brief requires that a control be shown capable of failing. This one
was run twice, with a positive and a negative arm, using the real toolchain
(cmake 4.4.2, Release).

ARM 1 — control with the IDE DISABLED (expects to pass)
  cmake -S rawrxd -B build_strict_audit \
        -DRAWRXD_STRICT_SOURCES=ON -DCMAKE_BUILD_TYPE=Release
  RESULT: SUCCESS
      RAWRXD_DROPPED_SOURCE_TOTAL=0
      RAWRXD_SOURCE_CLOSURE=COMPLETE no referenced source file is missing

  This arm is a FALSE PASS and is reported as one. The cache shows why:
      RAWRXD_BUILD_WIN32IDE:BOOL=OFF
  With the IDE off, WIN32IDE_SOURCES is never assembled, so the 225-file gap is
  never examined. The control passes because the subject was not built.
  A control that passes on an empty subject demonstrates nothing.

ARM 2 — control with the IDE ENABLED (the actual shipping configuration)
  cmake -S rawrxd -B build_strict_ide_audit \
        -DRAWRXD_STRICT_SOURCES=ON -DRAWRXD_BUILD_WIN32IDE=ON \
        -DCMAKE_BUILD_TYPE=Release
  RESULT: FAILED — "Configuring incomplete, errors occurred!"

      CMake Error at CMakeLists.txt:276 (message):
        [rawrxd_filter_missing_sources] WIN32IDE_SOURCES: 225 referenced
        source(s) do not exist:
        ... [full list of 225 paths emitted] ...
        RAWRXD_STRICT_SOURCES=ON: refusing to configure with a source list
        that does not match the tree.
      Call Stack: CMakeLists.txt:7139 (rawrxd_filter_missing_sources)

  The same configure also emitted, immediately before the fatal error:
        [rawrxd_stub_gate] WIN32IDE_SOURCES: 17 translation unit(s) are
        EMPTY-BODIED (no code after stripping comments)

CONCLUSION
----------
  The strict control is REAL and it WORKS. It correctly detects the condition
  the build file documents at line 190-195. It is simply OFF in every shipping
  build, and turning it on makes the IDE unconfigurable.

  The 225 missing paths are now enumerated by the build system itself and
  match this audit's independent count exactly (225).

  This is the desired shape of evidence: a control with a passing arm, a
  failing arm, and a known reason the failing arm is not run by default.
  The defect is not a broken detector here. It is that the working detector is
  disabled, and disabling it is what allows the product to build.

CLASSIFICATION: BLOCKED (under the project's own strict control)
        CONTROL_STATE = FUNCTIONAL BUT DISABLED
        NEGATIVE_ARM = FAILED AS PREDICTED

-------------------------------------------------------------------------------
FINDING B1-010 — PREREQUISITE-EXPLICIT GATE (fix for the B1-009 false pass)
-------------------------------------------------------------------------------
The false pass in Arm 1 was not the count. `RAWRXD_DROPPED_SOURCE_TOTAL=0` is a
valid observation and was NOT altered. The defect was that the verifier treated
an unexercised measurement domain as successful evidence. Repaired by making
the prerequisite an explicit, computed field that the verdict depends on.

IMPLEMENTED (rawrxd/CMakeLists.txt)
-----------------------------------
  :7153  set(RAWRXD_IDE_SOURCE_CENSUS_EXECUTED 1)
         -- set at the ONLY place the IDE domain is actually examined, i.e. the
            line immediately after rawrxd_filter_missing_sources(WIN32IDE_SOURCES).
            Reached only when the IDE is configured. Not set at the summary.
  :18048 RAWRXD_SOURCE_CLOSURE_PREREQ_GATE_001
         -- every field computed from observed state, never printed as a literal
            _rawrxd_ide_configured   = if(TARGET RawrXD-Win32IDE) -> 1/0
            _rawrxd_ide_census       = RAWRXD_IDE_SOURCE_CENSUS_EXECUTED
            _rawrxd_dropped_total   = RAWRXD_DROPPED_SOURCE_COUNT

            MEASUREMENT_VALID = ide_configured AND census_executed
            VERDICT = !MEASUREMENT_VALID   -> FAIL_IDE_NOT_BUILT
                     MEASUREMENT_VALID AND total != 0 -> FAIL_DROPPED_SOURCE
                     MEASUREMENT_VALID AND total == 0 -> PASS

         -- RAWRXD_IDE_BUILD_ATTEMPTED / RAWRXD_IDE_BUILD_EXIT are emitted as the
            explicit sentinel "not-observable-at-configure-time" rather than a
            number or a 0. No build has run at configure time, so any numeric
            value would be a fabricated observation. Build evidence remains the
            POST_BUILD seal of the shipping target, which exists only on a
            successful link.

CONTROL EXECUTED — THREE ARMS, ALL AS PREDICTED
-----------------------------------------------
  ARM 1  IDE OFF, strict ON  (the false-pass arm that motivated this)
    RAWRXD_IDE_REQUIRED=1
    RAWRXD_IDE_TARGET_CONFIGURED=0
    RAWRXD_SOURCE_CENSUS_EXECUTED=0
    RAWRXD_IDE_BUILD_ATTEMPTED=not-observable-at-configure-time
    RAWRXD_IDE_BUILD_EXIT=not-observable-at-configure-time
    RAWRXD_DROPPED_SOURCE_TOTAL=0
    DROPPED_SOURCE_MEASUREMENT_VALID=0
    VERDICT=FAIL_IDE_NOT_BUILT          <-- WAS: "SOURCE_CLOSURE=COMPLETE"

    The count is still 0, exactly as observed. The verdict changed, which was
    the whole point.

  ARM 2  IDE ON, strict ON
    FATAL at CMakeLists.txt:276 — "225 referenced source(s) do not exist"
    "Configuring incomplete, errors occurred!"
    Configure aborts before the summary, so no receipt is emitted. Correct: a
    strict run must not produce a receipt at all, least of all a passing one.

  ARM 3  IDE ON, strict OFF  (the actual shipping configuration)
    RAWRXD_IDE_REQUIRED=1
    RAWRXD_IDE_TARGET_CONFIGURED=1
    RAWRXD_SOURCE_CENSUS_EXECUTED=1
    RAWRXD_DROPPED_SOURCE_TOTAL=225
    DROPPED_SOURCE_MEASUREMENT_VALID=1
    VERDICT=FAIL_DROPPED_SOURCE

    The domain was genuinely exercised and the real defect is now named, with
    the count the build system itself computed.

FALSE-PASS CLASS AFTER THIS CHANGE
----------------------------------
    IDE not configured       -> cannot PASS   (FAIL_IDE_NOT_BUILT)
    IDE build fails          -> cannot PASS   (configure aborts, or the
                                             POST_BUILD seal is not written)
    census not executed      -> cannot PASS   (FAIL_IDE_NOT_BUILT)
    built IDE + census run
      + zero dropped sources -> PASS
    built IDE + census run
      + any dropped source   -> FAIL_DROPPED_SOURCE

  A PASS is now reachable only through the conjunction the contract requires.

CLASSIFICATION: REPAIRED (control semantics), defect in the PRODUCT remains
  The gate is correct. The product still fails it: 225 sources are absent.

===============================================================================
FINDING B1-011  —  THE TREE IS BEING MODIFIED DURING THE AUDIT
===============================================================================
SEVERITY: P0 — INVALID_MEASUREMENT RISK (binds every result in this audit)

A second writer is actively changing the source tree while this audit runs.

EVIDENCE
--------
  137 files under rawrxd/ (excluding build dirs) modified after the audit
  began at 18:38. Still being written at capture time:

    18:40:57  165,354 B  src/win32app/main_win32.cpp
    18:44:04   11,287 B  src/agentic/CheckpointRollbackAuthority.h
    18:46:48   91,617 B  tools/git_safety_authority_cert.cpp
    18:48:28   58,555 B  src/agentic/CheckpointRollbackAuthority.cpp
    18:50:08  118,361 B  src/core/command_registry.hpp
    18:50:41   40,904 B  src/core/win32ide_handler_impls.cpp
    18:51:30 1,188,185 B  CMakeLists.txt          (17,929 -> 18,139 lines)
    18:53:13   72,411 B  src/refactor/RefactorChain.cpp        (new)
    18:53:19   22,684 B  src/refactor/RefactorChainIdeSurface.cpp (new)
    18:54:49  297,087 B  src/deep2/Deep2Engine.cpp
    18:54:58   44,013 B  tools/refactor_chain_cert.cpp          (new)

  New work products appearing mid-audit: RAWRXD_GIT_TRANSACTION_AUTHORITY_001
  (four separate gate runs at 18:39, 18:40, 18:41, 18:49, 18:49),
  RAWRXD_P1_REFACTOR_CHAIN_001, RAWRXD_Q6K_GEMV_PARITY_001,
  RAWRXD_B83_IDE_WRITE_TRANSACTIONAL_PROFILE_001.

  A new CMake target (rawrxd_refactor_chain + refactor_chain_cert) was appended
  and its source tools/refactor_chain_cert.cpp was written after the CMake
  reference — the build system generated a hard error
      "Cannot find source file: tools/refactor_chain_cert.cpp"
      "No SOURCES given to target: refactor_chain_cert"
      "CMake Generate step failed."
  i.e. the tree was momentarily un-generatable by a concurrent edit.

CONSEQUENCE — STATED PLAINLY
----------------------------
  No repository-wide audit executed against a tree that is changing can bind a
  PASS to the product.  The project's own
  `single_writer.verification_invalidation` constraint requires that any input
  change during verification invalidate the prior result.  Applied honestly
  here, that means every measurement in this audit is bound to a source
  identity and not to HEAD.

SOURCE IDENTITY THIS AUDIT IS BOUND TO
--------------------------------------
  HEAD = 9f67682ffea12a182ae4fd2d41fb3bc524f61d2b
  AGGREGATE_SHA256 (over the 8 load-bearing files) =
      F9A36454EC36FEF8E4039B33BBF412E2B08824A20E5AB2C9E1F5176F44789817
  captured 18:55:36

  CMakeLists.txt                     3D3636599EAB0D447EAE84AD4137B372CDA8EBAAE1255B2EA07B0F99EAF4E83E  18:51:30
  src/win32app/main_win32.cpp        6E94285C1EB140A45FF2DB96848259450DF0198114007595BEDAC45F2269D46F  18:40:57
  src/win32app/Win32IDE_Commands.cpp 3CB80132D5BF8781BBBFA0628B2784DDA003983CED131676212645FC0E97A22F  17:57:39
  src/win32app/Win32IDE_EditorEngine.cpp A09B85D3C22109BF4448D690E6743AD23306D8EB6EA0C9F4D83950FC25685DC0  17:07:31
  src/agentic/AgentToolRegistry.cpp  00086BD1A598807EF736792DD7801BB9F8749D1FC5E09D97FB76F0DD030F6B7C  18:38:12
  src/agentic/GitSafetyAuthority.cpp 0C0C8A963AC503780402B70789A71BCAF184221266138E90EDC78697ECBA2CAD  17:34:58
  src/deep2/Deep2Engine.cpp          C4D526A87ADE9E97D6CAC831F11E60BA5FAD2810FB97DA028D7739B154124B10  18:55:26
  src/authority/SingleWriterAuthority.cpp C128DAE374D5A8DCAD1A593952F132A45CF6419E46B95B1B665E81E2E3888F75  00:52:04

STABILITY OF THE CENTRAL CLAIMS — RE-VERIFIED AGAINST THE MOVING TREE
---------------------------------------------------------------------
  Because the tree moved, the two load-bearing counts were re-measured after
  the change rather than reused:

                                   measured at start   re-measured 18:55
    add_executable blocks                    348              349
    targets with 100% stub sources           119              119   (unchanged)
    distinct referenced paths               1365             1374
    referenced-but-missing paths             353              355

  BOTH CENTRAL FINDINGS SURVIVE THE TREE MOVING. The two extra missing paths
  are from the concurrent writer's own new targets. The 119 stub-only targets
  are unchanged at exactly 119.

CLASSIFICATION: INVALID_MEASUREMENT_RISK (managed by identity binding + re-verify)

  This finding is also the independent confirmation of the prior ledger's
  RAWRXD_SINGLE_WRITER_AUTHORITY_001 finding: the single-writer authority is
  real, built, and adopted by no product, while a second writer demonstrably
  mutates the tree. The authority is not enforcing anything (see B8-008).

===============================================================================
BATCH 01 CLOSURE
===============================================================================
STATUS = PARTIAL  (Batch 1 itself is closed; product is NOT in a passing state)

  AUTHORITY/BUILD_GRAPH      = CONTRACT_VIOLATED
  STRICT_SOURCE_CONTROL      = FUNCTIONAL, NOW PREREQUISITE-EXPLICIT
    arm1 (IDE off)           = FAIL_IDE_NOT_BUILT  (was a false PASS)
    arm2 (IDE on, strict)    = CONFIGURE ABORTS, 225 listed
    arm3 (IDE on, default)   = FAIL_DROPPED_SOURCE 225
    count falsified?         = NO — 0 preserved, only the verdict changed
  RAWRXD-DROPPED-SOURCES     = 225 (IDE), 128 further elsewhere
  IDE_REFERENCED_VS_REAL     = ~200 referenced / 43 real
  EMPTY_TU_IN_SHIPPING       = 10 + 1 trivial main
  INF_ENGINE_LIB_HAS_MAIN    = YES (LNK4006)
  RAW R-SERVER_COMPILES      = NO (GitSafetyAuthorityTools.h:119)
  IDE_LINK                   = LINKS (FileOps LNK2019 was a namespace bug, fixed)
  IDE_BINARY_VS_TREE         = STALE (exe 18:21 < main_win32.cpp 18:40)
  INF_ENGINE_COMPILES        = FAILED at 17:28, later success at 18:24 unverified
  CTEST_COVERAGE             = 32 / ~450 targets

  NOTHING IN BATCH 01 SUPPORTS A PASS.  Two shipping binaries on disk are
  proven not to correspond to the current source (B1-004 stale rawr-server).

  BOTH SHIPPING CLIs (rawr, rawr-server) list 2 ABSENT sources and 1 STUB
  source each.  The shipping server contains no agent (src/rawr_agent.cpp is
  absent) and no IDE tool implementations (IdeToolImplementations.cpp absent).