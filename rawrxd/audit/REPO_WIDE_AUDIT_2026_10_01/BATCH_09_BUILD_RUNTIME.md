# BATCH 09 — BUILD / LINK / RUNTIME VERIFICATION
# REPO_WIDE_AUDIT_2026_10_01
#
# STATUS: BLOCKED — and the blocker is established, not assumed.

===============================================================================
FINDING B9-001  —  A CLEAN RUNTIME VERIFICATION CANNOT BE BOUND TO A TREE
                  THAT IS STILL BEING MODIFIED
===============================================================================
SEVERITY: P0 — BLOCKED_BY_EXTERNAL_STATE

MEASURED
--------
Batch 9 requires a clean build from a stable source identity, then runtime
execution. The precondition is a tree that does not move while the build runs.
It is not met.

  At 18:38 the audit began against HEAD 9f67682f with a dirty tree.
  At 18:55:36 the source identity was captured:
      AGGREGATE_SHA256 = F9A36454EC36FEF8E4039B33BBF412E2B08824A20E5AB2C9E1F5176F44789817
  137 files under rawrxd/ changed between those two points.
  A 40-second sampling window taken during Batch 9 itself observed:
      src/gguf_loader.cpp  MODIFIED  (1 file changed inside 40 seconds)
  CMakeLists.txt advanced again to 18:56:42, i.e. after the identity capture.

  The most recent observed writes:
      18:55:26  src/deep2/Deep2Engine.cpp
      18:54:58  tools/refactor_chain_cert.cpp
      18:56:42  CMakeLists.txt

OBSERVED CONSEQUENCE — THE BUILD SYSTEM ITSELF FAILED ON THE MOVING TREE
-----------------------------------------------------------------------
  A clean configure of the shipping IDE target was attempted against this tree.
  It failed in the GENERATE step, not the compile step:

      CMake Error at CMakeLists.txt:18124 (add_executable):
        Cannot find source file:
          tools/refactor_chain_cert.cpp
      CMake Error at CMakeLists.txt:18124 (add_executable):
        No SOURCES given to target: refactor_chain_cert
      CMake Generate step failed.  Build files cannot be regenerated correctly.

  A target was registered whose source did not exist at generation time. That
  is a source list and a filesystem out of step with each other, produced
  mid-session by a concurrent writer.

WHY THIS BLOCKS THE BATCH RATHER THAN MERELY COMPLICATING IT
------------------------------------------------------------
  A runtime result is admissible only if it describes the source that produced
  it. Here:
    - RawrXD-Win32IDE.exe linked 18:21:33  vs main_win32.cpp 18:40:57  (stale)
    - rawr-server.exe    linked 17:32:58  vs AgentToolRegistry.cpp 18:38:12 (stale)
    - InferenceEngine.lib built 18:24      vs Deep2Engine.cpp 18:55:26  (stale)

  Every binary in the tree predates at least one input that defines the
  behaviour it would be asked to demonstrate. Running any of them would produce
  a plausible, specific, and false result. That is the exact failure this
  project's own `single_writer.verification_invalidation` constraint exists to
  prevent, and applying it here means: do not run them, and say so.

WHAT WAS AND WAS NOT ESTABLISHED
--------------------------------
  ESTABLISHED (configure-time, no build required, reproducible):
    - RAWRXD_STRICT_SOURCES=ON with the IDE enabled ABORTS configuration and
      enumerates all 225 absent sources.          [B1-009 arm 2]
    - The default configuration reports VERDICT=FAIL_DROPPED_SOURCE 225 with
      DROPPED_SOURCE_MEASUREMENT_VALID=1.         [B1-009 arm 3]
    - The prerequisite-explicit gate now emits its full field set and refuses
      to PASS an unexercised domain.               [B1-010]

  NOT ESTABLISHED (requires a stable tree):
    - Whether rawr-server compiles.  Batch 03 found the
      GitSafetyAuthorityTools.h:119 break is FIXED and all 9 agentic TUs pass
      `cl /Zs` (syntax-only). That is a compile-stage signal, not a link, and
      not a runtime.
    - Whether RawrXD-Win32IDE links from clean.  Batch 04 verified the
      FileOps LNK2019 was a namespace-scope bug already fixed, and confirmed
      the symbol is present in the 18:21:33 binary. Again: a stale binary.
    - Whether any product performs real inference on a real model.
    - Whether the IDE actually renders and dispatches commands.

CLASSIFICATION: BLOCKED
  BLOCKER = SOURCE_TREE_NOT_STABLE (a second writer is active)
  NOT a capability finding. Nothing here says the product cannot work; it says
  no measurement of the product can currently be bound to it.

===============================================================================
CLOSURE NOTE — WHAT BATCH 9 WOULD DO ONCE UNBLOCKED
===============================================================================
  1. Obtain a quiescent tree, or a commit, and record its identity.
  2. Configure with RAWRXD_STRICT_SOURCES=ON and RAWRXD_BUILD_WIN32IDE=ON.
     Expect FATAL at the 225 missing sources. That IS the honest current
     state; it must be resolved or the entries removed, not the flag lowered.
  3. Build the three products: rawr, rawr-server, RawrXD-Win32IDE.
  4. Confirm each binary is NEWER than every input in its target.
  5. Only then run: real-model inference, and real IDE command dispatch.
  6. Bind every runtime result to the step-1 identity.

  Step 2 failing is not a blocker introduced by this audit. It is the product
  reporting, accurately, that 225 of its own referenced sources do not exist.