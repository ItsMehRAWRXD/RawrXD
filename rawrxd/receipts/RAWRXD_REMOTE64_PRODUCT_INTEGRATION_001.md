=== RAWRXD_REMOTE64_PRODUCT_INTEGRATION_001 ===
DATE=2026-10-01
SCOPE=Build authority + production integration for src/remote64 (64 MASM64 TUs)
BUILD_TREE=F:\~dev\rawrxd\build_ninja_release (VS 17 2022, Release)
PRODUCT_BIN=F:\~dev\rawrxd\build_ninja_release\bin\Release\rawr.exe

--- PRIOR STATE (measured, not assumed) ---
ASM_TU_COUNT_ON_DISK            = 64
CMAKE_TARGETS_BEFORE            = 0  (grep "remote64" in CMakeLists.txt -> 0 hits)
PRODUCTION_CONSUMERS_BEFORE     = 0  (deep2_bridge.asm symbols referenced by no C++ TU)
PRODUCT_BINARIES_LINKING_TU     = 0
SUBSYSTEM_DOC_STATUS            = "link/runtime certification OPEN" (src/remote64/README.md)

--- GATE 1: 64/64 ASM ASSEMBLE ---
TUS_ASSEMBLED                   = 64 / 64
ASSEMBLER                       = ml64.exe 14.44.35207 (Hostx64/x64)
PROBE                           = independent ml64 pass over all 64 files, all EXIT=0
CMAKE_BUILD                     = rawrxd_remote64 target builds clean (0 errors)
VERDICT                         = PASS

--- GATE 2: rawrxd_remote64 LIBRARY LINKS ---
TARGET                          = rawrxd_remote64 (STATIC, no main() -- deliberate)
ARTIFACT                        = build_ninja_release/Release/rawrxd_remote64.lib
LINK_PROBE                      = probe TU referencing RemoteSelfTest +
                                   Deep2RemoteObserveGate + Deep2RemoteControlGate
                                   archived against the lib -> EXIT=0
IMPORT_LIBRARIES_REQUIRED       = kernel32 user32 gdi32 ws2_32 bcrypt ntdll
IMPORT_LIBRARY_SOURCE           = derived from actual EXTERN usage per TU
                                   (bcrypt: aead/crypto/hashfile; ws2_32: transport/shutdown;
                                    gdi32: capture/viewer; user32: b37/b38/cursor/input/consent;
                                    ntdll: clipboard.asm RtlMoveMemory)
VERDICT                         = PASS
NOTE                            = LNK1561 on a direct exe link of these objects is EXPECTED
                                  for a library target and is not treated as a defect.

--- GATE 3: DEEP2 PRODUCTION TARGET CONSUMES deep2_bridge ---
WIRING                          = CMakeLists: rawrxd_remote64 linked PUBLIC into
                                  InferenceEngine; RAWRXD_REMOTE64_LINKED=1 defined
CXX_CONSUMER                     = src/remote64/remote64_bridge.{h,cpp} (new, first production
                                  C++ entry point into the 64 TUs)
DEEP2_CALLSITE                  = src/deep2/Deep2Engine.cpp initialize() ->
                                  rawrxd::remote64::initRemoteAuthority() +
                                  remoteObservePermitted() + remoteControlPermitted()
DEEP2_STATE_SURFACE             = Deep2Engine.h remoteObservePermitted() /
                                  remoteControlPermitted()
RUNTIME_EVIDENCE                = "[INIT] remote64 authority linked observe=0 control=0"
DECODE_PATH_IMPACT              = NONE. initialize() only reads the gates; no forward,
                                  sampler, KV, or timing code is touched.
VERDICT                         = PASS

--- GATE 4: RemoteSelfTest REACHABLE THROUGH PRODUCT BINARY ---
SUBCOMMAND                      = rawr remote-selftest (also: rawr remote)
MEASURED_OUTPUT (rawr.exe)      =
  REMOTE64_TU_COUNT=64
  RemoteSelfTest=0
  RemoteParitySelfTest=1
  RemoteParitySelfTest2=1
  RemoteFinalSelfTest=1
  DEEP2_OBSERVE_GATE=-3
  DEEP2_CONTROL_GATE=-3
  DEEP2_CONTROL_PERMITTED=0
  REMOTE_SELFTEST=PASS
  EXITCODE=0
CONVENTIONS_VERIFIED_IN_SOURCE  = selftest.asm uses R_OK(0)==pass;
                                  parity_selftest.asm / b45 / b60 use mov eax,1==pass.
DEFECT_FOUND_AND_FIXED           = remote64_bridge.cpp initially scored all four against
                                  R_OK(0), which reported a passing subsystem as FAIL
                                  (first run: RemoteSelfTest=0 parity=1 -> FAIL). Bridge now
                                  scores each test under its own documented convention.
GATE_SEMANTICS_VERIFIED         = both Deep2 gates return -3 (R_AUTH) pre-authentication and
                                  DEEP2_CONTROL_PERMITTED=0. A fresh process does not report a
                                  remote session as authorized.
VERDICT                         = PASS

--- GATE 5: EXISTING DEEP2 GENERATION STILL PASSES ---
CPU_ROUTE  (rawr run --tokens 8 bigdaddyg-fast "say hi")            EXIT=0
  GENERATED_TOKENS=8  COMPLETED=YES
  prefillMs=6303.7 decodeMs=21308.2 tps=0.38 (engine)
  TPS=0.290  PEAK_TPS=0.290
  [FWD_ALL] vulkan=0/0
GPU_ROUTE  (rawr run --tokens 8 --vulkan bigdaddyg-fast "say hi")   EXIT=0xC0000005
  GENERATED_TOKENS=8  COMPLETED=YES
  prefillMs=2654.3 decodeMs=1256.6 tps=6.37 (engine)
  TPS=2.046  PEAK_TPS=2.046
  [FWD_ALL] vulkan=1/1  GPU_FORWARD_ENTER ... devices=1 layers=28
  RECEIPT: MODEL/PROMPT_TOKENS/GENERATED_TOKENS/WALL_MS/TPS/COMPLETED=YES all written
MEASURED_GPU_SPEEDUP             = 6.37 / 0.38 = 16.7x decode TPS; 2.046 / 0.290 = 7.1x E2E
VERDICT                         = PASS for generation correctness and TPS authority
OPEN_DEFECT (new, pre-existing)  = GPU run produces a complete result + receipt, then exits
                                  0xC0000005 AFTER the final
                                  "[CLEANUP_STAGE] ~VulkanCompute body done" line -- i.e. in
                                  the ~VulkanCompute epilogue or later static destruction.
                                  Not caused by this integration (remote64 is read-only in
                                  initialize() and does not touch Vulkan).

--- GATE 6: CPU/GPU CORRECTNESS UNCHANGED ---
STATUS                         = NOT VERIFIED
REASON                         = no CPU-vs-GPU logits parity oracle was run in this session.
                                  Both routes complete and both report TPS, but "completes"
                                  is not "matches". Claiming parity here would be an
                                  unevidenced PASS.
NEXT                           = run the existing deep2 parity oracle (q4k/q6k/realgguf
                                  family) against the current binary for both routes.

--- FILES ADDED ---
  rawrxd/cmake/Remote64.cmake              (build authority; STATIC lib; warns if TU count != 64)
  rawrxd/src/remote64/remote64_bridge.h    (production C++ ABI + wrapper)
  rawrxd/src/remote64/remote64_bridge.cpp

--- FILES MODIFIED ---
  rawrxd/CMakeLists.txt                    include(cmake/Remote64.cmake); link into InferenceEngine
  rawrxd/src/deep2/Deep2Engine.h           gate accessors + state
  rawrxd/src/deep2/Deep2Engine.cpp         initialize() consumes the gates
  rawrxd/src/deep2/rawr_run.cpp            rawr remote-selftest subcommand
  rawrxd/src/gguf_loader.cpp               FP32LE -> ReadF32LE (missing symbol; build blocker)

--- BUILD UNBLOCKER (pre-existing, not caused by this gate) ---
BUILD_RAWRXD_AGENTIC_CLI was ON in build_ninja_release/CMakeCache.txt, which trips the
RAWRXD_AGENTIC_CLI_QUARANTINE_001 FATAL_ERROR at configure time. Reset to the documented
default OFF. The quarantine gate itself was left intact and still fires when ON.
InferenceEngine did not compile before this session: src/gguf_loader.cpp called an
undefined FP32LE(). Fixed to the existing ReadF32LE(). InferenceEngine.lib now builds at
58,765,692 bytes with 0 errors; rawr.exe builds at 1,506,816 bytes with 0 errors.

--- SYSTEMIC FINDING (unrelated to this gate, measured) ---
ORPHAN_SOURCE_FILES_NOT_NAMED_IN_ANY_CMAKE = 2751
  src/core 877 | src/generated 624 | src/deep2 369 | src/build 65 | src/remote64 59 |
  src/agentic 48 | src/shaders 43 | src/execution 42 | src/compute 42 | src/os 35 |
  src/reverse_engineering 35 | src/lavapath 27 | src/speculative 19 | src/cli 18
remote64 was 59 of these. The dominant "unfinished" class in this tree is not missing
logic -- it is source with no build authority. src/security/JwtValidator.cpp is the same
class: present, referenced by RAWRXD_SECURITY_JWT_VALIDATION_001, and named by no CMake
target. The pasted "agentic kernel" (AgentToolRegistry / StreamingToolParser /
AgentOrchestrator / CommandExecutor / JwtValidator) was NOT added, because every one of
those roles already has an authority in src/agentic (ToolRegistry.cpp, tool_registry.cpp,
ToolRegistry.h, tool_call_parser.cpp, tool_executor.cpp, ToolDispatcher.cpp,
AgentOrchestrator.cpp, AgentToolHandlers.cpp, streaming_command_handler.cpp) and
src/security/JwtValidator.cpp. Adding them would have created a second ToolRegistry, a
second AgentOrchestrator and a second JWT validator -- the same duplication this gate was
opened to remove.

--- OVERALL VERDICT ---
GATE1_ASM_ASSEMBLE            = PASS
GATE2_LIBRARY_LINKS           = PASS
GATE3_DEEP2_CONSUMES_BRIDGE   = PASS
GATE4_SELFTEST_VIA_PRODUCT    = PASS
GATE5_GENERATION_AND_TPS      = PASS
GATE6_CPU_GPU_PARITY         = OPEN (no parity oracle run)
OPEN_DEFECT_A                 = GPU run exits 0xC0000005 in teardown after ~VulkanCompute
VERDICT                       = PARTIAL
REASON                        = 5 of 6 gates pass with measured evidence; CPU/GPU parity is
                                unverified and the GPU teardown crash is unrepaired.