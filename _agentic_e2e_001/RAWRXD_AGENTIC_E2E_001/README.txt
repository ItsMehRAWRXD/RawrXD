RAWRXD_AGENTIC_E2E_001
======================

Purpose
-------
Replace the remaining minimal/read-only agentic certification path with a real,
fail-closed coding path:

  REAL Deep2 model
    -> AgentToolRegistry dispatch
    -> source read
    -> real source edit
    -> real build process
    -> real child test executable
    -> captured tool result returned to model
    -> model final response

PASS cannot be emitted unless every mandatory field is real and green.
There is no synthetic token success branch and no stub fallback branch.

Files
-----
src/agentic/RawrXDAgenticE2E.hpp
src/agentic/RawrXDAgenticE2E.cpp
tests/rawrxd_agentic_e2e_gate.cpp
CMakeLists.agentic.snippet
INTEGRATION.cpp.snippet
APPLY.ps1

Production coding tools
-----------------------
registerRawrXDCodingTools() installs real operations on your IDE-owned
AgentToolRegistry:

  file.read
  file.write       atomic workspace-confined write
  file.replace     exact-cardinality workspace-confined edit
  process.run      direct child process, captured output, timeout; NO cmd.exe

process.run intentionally has no shell. For build + test, the model performs
separate calls and sees each real exit code/result before continuing.

Certification fixture
---------------------
runAgenticE2EGate() creates .rawr/agentic_gate with a deliberately failing
C++ program. The model is required to:

  1. read the actual source via agent.file.read
  2. edit BROKEN/return 7 -> OK/return 0 via a real write tool
  3. invoke agent.build, which performs a real CMake configure/build
  4. invoke agent.test, which launches the produced executable
  5. consume TEST_PASS + AGENTIC_E2E_OK in a later inference turn
  6. produce a final answer

Successful fixtures are removed. Failed fixtures remain for diagnosis.

Expected receipt
----------------
=== RAWRXD_WIN32IDE_AGENTIC_001 ===
IDE_LAUNCH=PASS
COMMAND_DISPATCH=PASS
REAL_MODEL_INFERENCE=PASS
TOOL_AUTHORITY=PASS
FILE_READ=PASS
FILE_EDIT=PASS
BUILD_RAN=PASS
BUILD_PASS=PASS
TEST_RAN=PASS
TEST_PASS=PASS
TOOL_RESULT_IN_CONTEXT=PASS
MODEL_FINAL=PASS
...
SYNTHETIC_TOKEN_OUTPUT=0
STUB_FALLBACKS=0
VERDICT=PASS

Important integration rule
--------------------------
Pass the exact Deep2Engine instance that just passed
RAWRXD_WIN32IDE_INFERENCE_001. Do not reload a tiny fixture model and do not
substitute a different model when the agent gate starts.

The existing repository agent dispatch describes itself as read-only and says
"No write tools". This drop adds the missing production mutation path rather
than certifying another audit-only loop.
